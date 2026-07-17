from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from agent.opensearch.documents import (
    CanonicalEventSearchDocument,
    DetectionSignalSearchDocument,
    calculate_projection_sha256,
)
from agent.persistence.orm_models import SearchProjectionState
from agent.persistence.outbox_repository import OutboxError


ProjectionDocument = CanonicalEventSearchDocument | DetectionSignalSearchDocument
ProjectionKey = tuple[str, str, str]


@dataclass(frozen=True)
class _PreparedProjection:
    document: ProjectionDocument
    fingerprint: str


def _key(document: ProjectionDocument) -> ProjectionKey:
    return (
        document.entity_type,
        document.entity_id,
        document.schema_version,
    )


class SearchProjectionStateRepository:
    """Atomically assign durable versions to safe event/signal projections."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def _upsert(self, values: list[dict[str, object]]) -> dict[ProjectionKey, int]:
        dialect_name = self.session.get_bind().dialect.name
        statement: Any
        if dialect_name == "postgresql":
            statement = postgresql_insert(SearchProjectionState).values(values)
        elif dialect_name == "sqlite":
            statement = sqlite_insert(SearchProjectionState).values(values)
        else:
            raise OutboxError("opensearch_projection_state_dialect_unsupported")

        excluded = statement.excluded
        unchanged = SearchProjectionState.projection_sha256 == excluded.projection_sha256
        statement = statement.on_conflict_do_update(
            index_elements=[
                SearchProjectionState.entity_type,
                SearchProjectionState.entity_id,
                SearchProjectionState.schema_version,
            ],
            set_={
                "projection_version": case(
                    (
                        unchanged,
                        SearchProjectionState.projection_version,
                    ),
                    else_=SearchProjectionState.projection_version + 1,
                ),
                "projection_sha256": excluded.projection_sha256,
                "updated_at": case(
                    (unchanged, SearchProjectionState.updated_at),
                    else_=excluded.updated_at,
                ),
                "version": case(
                    (unchanged, SearchProjectionState.version),
                    else_=SearchProjectionState.version + 1,
                ),
            },
        ).returning(
            SearchProjectionState.entity_type,
            SearchProjectionState.entity_id,
            SearchProjectionState.schema_version,
            SearchProjectionState.projection_version,
        )
        try:
            rows = self.session.execute(statement)
            return {
                (str(entity_type), str(entity_id), str(schema_version)): int(projection_version)
                for entity_type, entity_id, schema_version, projection_version in rows
            }
        except (IntegrityError, OperationalError):
            # The UnitOfWork owns the required rollback/retry boundary. Never expose
            # driver text or mutate the caller's transaction from this repository.
            raise OutboxError("opensearch_projection_state_retry") from None

    def resolve_documents(
        self,
        documents: list[ProjectionDocument],
    ) -> list[ProjectionDocument]:
        if not documents:
            return []

        prepared_by_key: dict[ProjectionKey, _PreparedProjection] = {}
        for document in documents:
            key = _key(document)
            fingerprint = calculate_projection_sha256(document)
            duplicate = prepared_by_key.get(key)
            if duplicate is not None:
                if duplicate.fingerprint != fingerprint:
                    raise OutboxError("opensearch_projection_batch_conflict")
                continue
            prepared_by_key[key] = _PreparedProjection(document, fingerprint)

        now = datetime.now(timezone.utc)
        versions = self._upsert(
            [
                {
                    "entity_type": key[0],
                    "entity_id": key[1],
                    "schema_version": key[2],
                    "projection_version": 1,
                    "projection_sha256": prepared.fingerprint,
                    "created_at": now,
                    "updated_at": now,
                    "version": 1,
                }
                for key, prepared in prepared_by_key.items()
            ]
        )
        if versions.keys() != prepared_by_key.keys():
            raise OutboxError("opensearch_projection_state_write_failed")

        return [
            document.model_copy(update={"document_version": versions[_key(document)]})
            for document in documents
        ]
