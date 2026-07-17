from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from agent.application.search_outbox import SearchOutboxService
from agent.config import Settings
from agent.opensearch.documents import (
    calculate_projection_sha256,
    canonical_event_document,
    detection_signal_document,
    projection_fingerprint_source,
)
from agent.persistence.database import Base
from agent.persistence.orm_models import (
    CanonicalEvent,
    DetectionSignal,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    SearchIndexOutbox,
    SearchProjectionState,
    ingestion_job_events,
    ingestion_job_signals,
)
from agent.persistence.outbox_repository import SearchIndexOutboxRepository


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)


def _settings() -> Settings:
    return Settings(_env_file=None, opensearch_enabled=True)


def _service(session: Session) -> SearchOutboxService:
    settings = _settings()
    return SearchOutboxService(
        session,
        SearchIndexOutboxRepository(
            session,
            max_payload_bytes=settings.opensearch_outbox_max_payload_bytes,
            enqueue_chunk_size=settings.opensearch_outbox_enqueue_chunk_size,
            max_claim_batch_size=settings.opensearch_outbox_max_claim_batch_size,
        ),
        settings,
    )


def _state(session: Session, entity_type: str, entity_id: str) -> SearchProjectionState:
    row = session.get(SearchProjectionState, (entity_type, entity_id, "v1"))
    assert row is not None
    return row


def _versions(session: Session, entity_type: str, entity_id: str) -> list[int]:
    return list(
        session.execute(
            select(SearchIndexOutbox.document_version)
            .where(
                SearchIndexOutbox.entity_type == entity_type,
                SearchIndexOutbox.entity_id == entity_id,
            )
            .order_by(SearchIndexOutbox.document_version)
        ).scalars()
    )


def test_projection_fingerprint_is_safe_deterministic_and_ignores_delivery_fields() -> None:
    event = CanonicalEvent(
        event_id="event-fingerprint",
        timestamp=NOW,
        source_name="firewall",
        raw_record_hash="raw-log-secret",
    )
    first = canonical_event_document(
        event,
        schema_version="v1",
        indexed_at=NOW,
        document_version=1,
        job_ids=("job-2", "job-1"),
    )
    second = canonical_event_document(
        event,
        schema_version="v1",
        indexed_at=NOW + timedelta(days=1),
        document_version=99,
        job_ids=("job-1", "job-2"),
    )

    source = projection_fingerprint_source(first)
    assert "document_version" not in source
    assert "indexed_at" not in source
    assert "raw_record_hash" not in source
    assert "raw-log-secret" not in str(source)
    assert calculate_projection_sha256(first) == calculate_projection_sha256(second)

    signal = DetectionSignal(
        signal_id="signal-fingerprint",
        rule_id="rule-1",
        severity="high",
        confidence=0.9,
        created_at=NOW,
        metrics={"raw_log": "super-secret-token"},
    )
    signal_source = projection_fingerprint_source(
        detection_signal_document(signal, schema_version="v1")
    )
    assert "metrics" not in signal_source
    assert "super-secret-token" not in str(signal_source)


def test_event_relationship_add_delete_replace_and_context_change_are_monotonic() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with factory() as session:
        event = CanonicalEvent(event_id="event-versioned", timestamp=NOW)
        jobs = [IngestionJob(id=f"job-{index}") for index in range(1, 4)]
        incident = Incident(incident_id="incident-1", version=1)
        session.add_all([event, incident, *jobs])
        service = _service(session)

        first = service.enqueue_analysis(events=[event], signals=[], incidents=[])
        retry = service.enqueue_analysis(events=[event], signals=[], incidents=[])
        assert first.inserted_count == 1
        assert retry.inserted_count == 0
        assert _state(session, "canonical_event", event.event_id).projection_version == 1

        session.execute(
            ingestion_job_events.insert().values(job_id="job-1", event_id=event.event_id)
        )
        service.enqueue_analysis(events=[event], signals=[], incidents=[])
        session.execute(
            delete(ingestion_job_events).where(
                ingestion_job_events.c.job_id == "job-1",
                ingestion_job_events.c.event_id == event.event_id,
            )
        )
        service.enqueue_analysis(events=[event], signals=[], incidents=[])

        session.execute(
            ingestion_job_events.insert(),
            [
                {"job_id": "job-1", "event_id": event.event_id},
                {"job_id": "job-2", "event_id": event.event_id},
            ],
        )
        service.enqueue_analysis(events=[event], signals=[], incidents=[])
        session.execute(
            delete(ingestion_job_events).where(
                ingestion_job_events.c.job_id == "job-1",
                ingestion_job_events.c.event_id == event.event_id,
            )
        )
        session.execute(
            ingestion_job_events.insert().values(job_id="job-3", event_id=event.event_id)
        )
        service.enqueue_analysis(events=[event], signals=[], incidents=[])

        association = IncidentEvent(
            incident_id=incident.incident_id,
            event_id=event.event_id,
            is_context=False,
        )
        session.add(association)
        service.enqueue_analysis(events=[event], signals=[], incidents=[])
        session.delete(association)
        service.enqueue_analysis(events=[event], signals=[], incidents=[])

        association = IncidentEvent(
            incident_id=incident.incident_id,
            event_id=event.event_id,
            is_context=True,
        )
        session.add(association)
        service.enqueue_analysis(events=[event], signals=[], incidents=[])
        association.is_context = False
        service.enqueue_analysis(events=[event], signals=[], incidents=[])

        assert _versions(session, "canonical_event", event.event_id) == list(range(1, 10))
        state = _state(session, "canonical_event", event.event_id)
        assert state.projection_version == 9
        assert state.version == 9
        latest = (
            session.execute(
                select(SearchIndexOutbox)
                .where(
                    SearchIndexOutbox.entity_type == "canonical_event",
                    SearchIndexOutbox.entity_id == event.event_id,
                )
                .order_by(SearchIndexOutbox.document_version.desc())
            )
            .scalars()
            .first()
        )
        assert latest is not None
        assert latest.payload["job_ids"] == ["job-2", "job-3"]
        assert latest.payload["incident_ids"] == [incident.incident_id]
        assert latest.payload["context_incident_ids"] == []
    engine.dispose()


def test_signal_relationship_and_safe_source_changes_are_monotonic() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    with factory() as session:
        signal = DetectionSignal(
            signal_id="signal-versioned",
            rule_id="rule-1",
            severity="medium",
            confidence=0.5,
            created_at=NOW,
        )
        jobs = [IngestionJob(id=f"signal-job-{index}") for index in range(1, 4)]
        incident = Incident(incident_id="signal-incident", version=1)
        session.add_all([signal, incident, *jobs])
        service = _service(session)

        service.enqueue_analysis(events=[], signals=[signal], incidents=[])
        retry = service.enqueue_analysis(events=[], signals=[signal], incidents=[])
        assert retry.inserted_count == 0

        session.execute(
            ingestion_job_signals.insert().values(job_id="signal-job-1", signal_id=signal.signal_id)
        )
        service.enqueue_analysis(events=[], signals=[signal], incidents=[])
        session.execute(
            delete(ingestion_job_signals).where(
                ingestion_job_signals.c.job_id == "signal-job-1",
                ingestion_job_signals.c.signal_id == signal.signal_id,
            )
        )
        service.enqueue_analysis(events=[], signals=[signal], incidents=[])

        association = IncidentSignal(
            incident_id=incident.incident_id,
            signal_id=signal.signal_id,
        )
        session.add(association)
        service.enqueue_analysis(events=[], signals=[signal], incidents=[])
        session.delete(association)
        service.enqueue_analysis(events=[], signals=[signal], incidents=[])

        session.execute(
            ingestion_job_signals.insert(),
            [
                {"job_id": "signal-job-1", "signal_id": signal.signal_id},
                {"job_id": "signal-job-2", "signal_id": signal.signal_id},
            ],
        )
        service.enqueue_analysis(events=[], signals=[signal], incidents=[])
        session.execute(
            delete(ingestion_job_signals).where(
                ingestion_job_signals.c.job_id == "signal-job-1",
                ingestion_job_signals.c.signal_id == signal.signal_id,
            )
        )
        session.execute(
            ingestion_job_signals.insert().values(job_id="signal-job-3", signal_id=signal.signal_id)
        )
        service.enqueue_analysis(events=[], signals=[signal], incidents=[])

        signal.severity = "critical"
        signal.confidence = 0.95
        signal.mitre_techniques = ["T1059"]
        signal.suppressed = True
        signal.suppression_reason = "known-safe"
        signal.target_entities = ["198.51.100.20"]
        service.enqueue_analysis(events=[], signals=[signal], incidents=[])

        assert _versions(session, "detection_signal", signal.signal_id) == list(range(1, 9))
        state = _state(session, "detection_signal", signal.signal_id)
        assert state.projection_version == 8
        assert state.version == 8
        latest = (
            session.execute(
                select(SearchIndexOutbox)
                .where(
                    SearchIndexOutbox.entity_type == "detection_signal",
                    SearchIndexOutbox.entity_id == signal.signal_id,
                )
                .order_by(SearchIndexOutbox.document_version.desc())
            )
            .scalars()
            .first()
        )
        assert latest is not None
        assert latest.payload["job_ids"] == ["signal-job-2", "signal-job-3"]
        assert latest.payload["severity"] == "critical"
        assert latest.payload["mitre_techniques"] == ["T1059"]
        assert (
            session.execute(select(func.count()).select_from(SearchProjectionState)).scalar_one()
            == 1
        )
    engine.dispose()
