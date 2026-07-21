"""Phase 6E.4A blocker 5: historical evidence must survive cross-job merges.

The ORM incident has no evidence column, so mappers hydrate DetectionSignal
and IncidentBundle with empty evidence. The stateful merge must reconstruct
bounded, deterministic evidence from persisted canonical events so earlier
jobs' evidence does not vanish as later jobs merge in.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.detection.incident_correlation import MAX_INCIDENT_EVIDENCE
from agent.persistence.orm_models import Base
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import (
    FIXED,
    make_event,
    make_incident,
    make_signal,
    submit_job,
)


@pytest.fixture
def session_factory():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield SessionLocal
    engine.dispose()
    try:
        os.remove(path)
    except PermissionError:
        pass


def test_three_sequential_jobs_preserve_historical_evidence(session_factory) -> None:
    import datetime

    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    job_event_ids = {0: ["j0e1", "j0e2"], 1: ["j1e1", "j1e2"], 2: ["j2e1", "j2e2"]}
    last_result = None

    # Each job is a separate UnitOfWork, hydrating from persistence between
    # merges (the realistic cross-job path), so job 2's merge only sees job 0
    # and job 1 through reconstructed persisted evidence.
    for index in range(3):
        ts = FIXED + datetime.timedelta(minutes=index)
        events = [make_event(eid, ts=ts) for eid in job_event_ids[index]]
        signal = make_signal(f"SIG-{index}", job_event_ids[index], ts=ts)
        incident = make_incident(f"INC-{index}", signal, events, ts=ts)
        with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
            last_result, _ = submit_job(
                uow, service, settings,
                job_id=f"job-{index}", events=events, signal=signal, incident=incident, now=ts,
            )

    assert last_result.status == "merged"
    evidence_ids = set(last_result.evidence_event_ids)

    # Deterministic, duplicate-free, bounded, and belonging only to real
    # incident event IDs.
    assert len(last_result.evidence_event_ids) == len(evidence_ids)
    assert len(evidence_ids) <= MAX_INCIDENT_EVIDENCE
    all_incident_event_ids = {eid for ids in job_event_ids.values() for eid in ids}
    assert evidence_ids <= all_incident_event_ids

    # Representation from the earliest job (job 0) AND the incoming job (job 2)
    # both survive - historical evidence did not vanish.
    assert evidence_ids & set(job_event_ids[0]), "job 0 evidence vanished"
    assert evidence_ids & set(job_event_ids[2]), "incoming job evidence missing"

    # The canonical incident's persisted events span all three jobs, so a
    # fresh reconstruction is durable across process restarts.
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(last_result.canonical_incident_id)
        persisted_event_ids = {e.event_id for e in incident_row.events if not e.is_context}
    assert persisted_event_ids == all_incident_event_ids


def test_reconstruction_is_deterministic_across_repeated_calls(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("e1"), make_event("e2")]
        signal = make_signal("SIG-A", ["e1", "e2"])
        incident = make_incident("INC-A", signal, events)
        submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=FIXED,
        )

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get("INC-A")
        first = service._reconstruct_canonical_evidence(uow, incident_row, limit=50)
        second = service._reconstruct_canonical_evidence(uow, incident_row, limit=50)

    assert [e.event_id for e in first] == [e.event_id for e in second]
    assert [e.event_id for e in first] == ["e1", "e2"]
    # Reconstructed evidence carries only safe structured fields, never raw
    # records or parser metadata.
    for item in first:
        assert set(item.original_fields).issubset(
            {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action"}
        )
        assert item.reason == "persisted_incident_evidence"
