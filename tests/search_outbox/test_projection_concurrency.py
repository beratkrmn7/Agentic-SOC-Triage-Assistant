from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from agent.opensearch.documents import CanonicalEventSearchDocument
from agent.persistence.database import Base
from agent.persistence.orm_models import (
    LogSource,
    SearchIndexOutbox,
    SearchProjectionState,
)
from agent.persistence.outbox_repository import (
    OutboxError,
    SearchIndexOutboxRepository,
)
from agent.persistence.projection_repository import SearchProjectionStateRepository


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
MAX_TRANSACTION_ATTEMPTS = 4


def _document(source_name: str) -> CanonicalEventSearchDocument:
    return CanonicalEventSearchDocument(
        schema_version="v1",
        entity_id="event-concurrent",
        document_version=1,
        indexed_at=NOW,
        source_updated_at=NOW,
        event_id="event-concurrent",
        timestamp=NOW,
        source_name=source_name,
    )


def _run_projection(
    factory,
    barrier: Barrier,
    *,
    document: CanonicalEventSearchDocument,
    marker_name: str,
) -> tuple[int, int]:
    retry_count = 0
    for attempt in range(MAX_TRANSACTION_ATTEMPTS):
        with factory() as session:
            try:
                if attempt == 0:
                    barrier.wait(timeout=10)
                versioned = SearchProjectionStateRepository(session).resolve_documents([document])[
                    0
                ]
                SearchIndexOutboxRepository(
                    session,
                    max_payload_bytes=65_536,
                    enqueue_chunk_size=100,
                    max_claim_batch_size=100,
                ).enqueue_upsert(versioned)
                marker = session.execute(
                    select(LogSource).where(LogSource.source_name == marker_name)
                ).scalar_one()
                marker.total_events = int(marker.total_events or 0) + 1
                session.commit()
                return versioned.document_version, retry_count
            except OutboxError as error:
                # Retry belongs to the source transaction boundary, not either
                # repository. A raw SQLAlchemy OperationalError would fail the test.
                session.rollback()
                retry_count += 1
                if (
                    error.code != "opensearch_projection_state_retry"
                    or attempt == MAX_TRANSACTION_ATTEMPTS - 1
                ):
                    raise
    raise AssertionError("bounded projection retry exhausted")


def _database(tmp_path: Path):
    database = tmp_path / "projection-concurrency.db"
    engine = create_engine(
        f"sqlite:///{database}",
        connect_args={"check_same_thread": False, "timeout": 1.0},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with factory.begin() as session:
        session.add_all(
            [
                LogSource(source_name="worker-a", total_events=0),
                LogSource(source_name="worker-b", total_events=0),
            ]
        )
    return engine, factory


def test_real_concurrent_same_projection_reuses_one_version_and_outbox(
    tmp_path: Path,
) -> None:
    engine, factory = _database(tmp_path)
    barrier = Barrier(2)
    document = _document("same-safe-projection")
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    _run_projection,
                    factory,
                    barrier,
                    document=document,
                    marker_name=marker,
                )
                for marker in ("worker-a", "worker-b")
            ]
            results = [future.result(timeout=20) for future in futures]

        assert [version for version, _retries in results] == [1, 1]
        assert all(retries < MAX_TRANSACTION_ATTEMPTS for _version, retries in results)
        with factory() as session:
            state = session.get(
                SearchProjectionState,
                ("canonical_event", "event-concurrent", "v1"),
            )
            assert state is not None
            assert state.projection_version == 1
            assert state.version == 1
            assert (
                session.execute(
                    select(func.count()).select_from(SearchProjectionState)
                ).scalar_one()
                == 1
            )
            assert (
                session.execute(select(func.count()).select_from(SearchIndexOutbox)).scalar_one()
                == 1
            )
            assert {
                row.source_name: row.total_events
                for row in session.execute(select(LogSource)).scalars()
            } == {"worker-a": 1, "worker-b": 1}
    finally:
        engine.dispose()


def test_real_concurrent_different_projections_receive_distinct_versions(
    tmp_path: Path,
) -> None:
    engine, factory = _database(tmp_path)
    barrier = Barrier(2)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    _run_projection,
                    factory,
                    barrier,
                    document=_document(source_name),
                    marker_name=marker,
                )
                for source_name, marker in (
                    ("projection-a", "worker-a"),
                    ("projection-b", "worker-b"),
                )
            ]
            results = [future.result(timeout=20) for future in futures]

        assert {version for version, _retries in results} == {1, 2}
        assert all(retries < MAX_TRANSACTION_ATTEMPTS for _version, retries in results)
        with factory() as session:
            state = session.get(
                SearchProjectionState,
                ("canonical_event", "event-concurrent", "v1"),
            )
            assert state is not None
            assert state.projection_version == 2
            assert state.version == 2
            rows = list(
                session.execute(
                    select(SearchIndexOutbox).order_by(SearchIndexOutbox.document_version)
                ).scalars()
            )
            assert [row.document_version for row in rows] == [1, 2]
            assert {row.payload["source_name"] for row in rows} == {
                "projection-a",
                "projection-b",
            }
            assert len({row.payload_sha256 for row in rows}) == 2
            assert {
                row.source_name: row.total_events
                for row in session.execute(select(LogSource)).scalars()
            } == {"worker-a": 1, "worker-b": 1}
    finally:
        engine.dispose()
