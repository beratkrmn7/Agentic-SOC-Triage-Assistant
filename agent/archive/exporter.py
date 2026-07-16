from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import cast

from agent.application.retention import RetentionEntity, RetentionPlan
from agent.archive.io import ArchiveExportError, ArchiveWriteResult, ArchiveWriter
from agent.archive.schemas import (
    ArchiveCutoffs,
    ArchiveEntityType,
    ArchiveManifestV1,
    ArchiveRecord,
    utc_datetime,
)
from agent.archive.serialization import (
    serialize_dependency_record,
    serialize_root_record,
)
from agent.archive.storage import ArchiveWorkspace
from agent.persistence.archive_repository import ArchiveExportRepository


CANDIDATE_PAYLOADS = (
    ("canonical_event", "canonical_events.ndjson.gz"),
    ("detection_signal", "detection_signals.ndjson.gz"),
    ("ingestion_job", "ingestion_jobs.ndjson.gz"),
    ("incident", "incidents.ndjson.gz"),
    ("audit_event", "audit_events.ndjson.gz"),
)


class ArchiveExporter:
    def __init__(
        self,
        repository: ArchiveExportRepository,
        writer: ArchiveWriter,
        *,
        batch_size: int,
        producer_version: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= batch_size <= 10_000:
            raise ValueError("archive_batch_size_invalid")
        self._repository = repository
        self._writer = writer
        self._batch_size = batch_size
        self._producer_version = producer_version
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def export(
        self,
        workspace: ArchiveWorkspace,
        plan: RetentionPlan,
        *,
        created_at: datetime,
    ) -> ArchiveWriteResult:
        payloads = []
        for entity_type, filename in CANDIDATE_PAYLOADS:
            archive_entity_type = cast(ArchiveEntityType, entity_type)
            payloads.append(
                self._writer.write_payload(
                    workspace,
                    filename,
                    self._candidate_records(entity_type, plan),
                    declared_entity_types=(archive_entity_type,),
                )
            )
        payloads.append(
            self._writer.write_payload(
                workspace,
                "dependent_records.ndjson.gz",
                self._dependency_records(plan),
            )
        )
        candidate_count = sum(payload.candidate_count for payload in payloads)
        dependency_count = sum(payload.dependency_count for payload in payloads)
        if candidate_count != plan.total_candidate_count:
            raise ArchiveExportError("archive_candidate_count_changed")
        completed_at = utc_datetime(self._clock())
        manifest = ArchiveManifestV1(
            archive_id=workspace.archive_id,
            policy_version=plan.policy_version,
            created_at=utc_datetime(created_at),
            completed_at=completed_at,
            archive_as_of=utc_datetime(plan.generated_at),
            cutoffs=ArchiveCutoffs(
                canonical_event=plan.cutoffs.canonical_event,
                detection_signal=plan.cutoffs.detection_signal,
                ingestion_job=plan.cutoffs.ingestion_job,
                incident=plan.cutoffs.incident,
                audit_event=plan.cutoffs.audit_event,
            ),
            producer_version=self._producer_version,
            payloads=tuple(payloads),
            candidate_record_count=candidate_count,
            dependency_record_count=dependency_count,
            total_record_count=candidate_count + dependency_count,
        )
        return self._writer.write_manifest(workspace, manifest)

    def _candidate_records(
        self,
        entity_type: str,
        plan: RetentionPlan,
    ) -> Iterator[ArchiveRecord]:
        for batch in self._repository.iter_candidate_batches(
            cast(RetentionEntity, entity_type),
            plan.cutoffs,
            plan.generated_at,
            self._batch_size,
        ):
            for row in batch:
                yield serialize_root_record(
                    entity_type,
                    row,
                    role="retention_candidate",
                    archive_as_of=plan.generated_at,
                )

    def _dependency_records(self, plan: RetentionPlan) -> Iterator[ArchiveRecord]:
        for batch in self._repository.iter_dependency_batches(
            plan.cutoffs,
            plan.generated_at,
            self._batch_size,
        ):
            for row in batch.rows:
                yield serialize_dependency_record(
                    batch.entity_type,
                    row,
                    archive_as_of=plan.generated_at,
                )
