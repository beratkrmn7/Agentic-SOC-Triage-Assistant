"""Phase 6E.4A blocker 1: first-state creation must be foreign-key safe.

These tests run with SQLite `PRAGMA foreign_keys=ON` so the
state.incident_id -> incidents.incident_id FK is actually enforced. The
canonical incident and its correlation-state row must be created inside one
savepoint, and a concurrent unique-key loser must roll back both its
temporary incident and state row (leaving no orphan incident) before merging
into the winner.
"""

from __future__ import annotations

import datetime
import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.persistence.orm_models import Base, Incident, IncidentCorrelationState
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import (
    FIXED,
    make_event,
    make_incident,
    make_signal,
    submit_job,
)


def _fk_engine(path: str):
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _enable_fk(dbapi_connection, _record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


@pytest.fixture
def fk_session_factory():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = _fk_engine(path)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield SessionLocal
    engine.dispose()
    try:
        os.remove(path)
    except PermissionError:
        pass


def test_first_creation_is_foreign_key_safe(fk_session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        events = [make_event("a1")]
        signal = make_signal("SIG-A", ["a1"])
        incident = make_incident("INC-A", signal, events)
        result, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=FIXED,
        )

    assert result.status == "created"

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(result.correlation_key)
        assert state is not None
        assert str(state.incident_id) == result.canonical_incident_id
        assert uow.incidents.get(result.canonical_incident_id) is not None


def test_expires_at_is_later_than_future_dated_last_seen(fk_session_factory) -> None:
    # A short TTL plus a future-dated event window would push expires_at at or
    # below last_seen (violating the CHECK) unless expires_at anchors to
    # max(now, last_seen) + ttl.
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=1,
        stateful_correlation_window_seconds=1,
    )
    service = StatefulIncidentCorrelationService()
    future_event = FIXED + datetime.timedelta(days=30)

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        events = [make_event("f1", ts=future_event)]
        signal = make_signal("SIG-F", ["f1"], ts=future_event)
        incident = make_incident("INC-F", signal, events, ts=future_event)
        result, _ = submit_job(
            uow, service, settings,
            job_id="job-f", events=events, signal=signal, incident=incident, now=FIXED,
        )

    assert result.status == "created"
    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(result.correlation_key)
        assert state is not None
        # Both loaded back naive from SQLite; compare directly.
        assert state.expires_at > state.last_seen


def test_concurrent_first_writers_are_fk_safe_and_leave_no_orphan(fk_session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def worker(index: int):
        events = [make_event(f"evt-{index}")]
        signal = make_signal(f"SIG-{index}", [f"evt-{index}"])
        incident = make_incident(f"INC-{index}", signal, events)
        try:
            barrier.wait(timeout=10)
            with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
                return submit_job(
                    uow, service, settings,
                    job_id=f"job-{index}", events=events, signal=signal,
                    incident=incident, now=FIXED,
                )[0]
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(worker, [0, 1]))

    assert not errors, f"worker threads raised: {errors}"
    assert all(r is not None for r in results)
    assert sorted(r.status for r in results) == ["created", "merged"]
    canonical_ids = {r.canonical_incident_id for r in results}
    assert len(canonical_ids) == 1

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        assert uow.session.query(IncidentCorrelationState).count() == 1
        # Exactly one incident row: the loser's temporary incident rolled back.
        assert uow.session.query(Incident).count() == 1
        canonical_id = next(iter(canonical_ids))
        incident_row = uow.incidents.get(canonical_id)
        event_ids = [e.event_id for e in incident_row.events]
        signal_ids = [s.signal_id for s in incident_row.signals]
        assert set(event_ids) == {"evt-0", "evt-1"}
        assert set(signal_ids) == {"SIG-0", "SIG-1"}
        # Both jobs ended up associated with the single canonical incident.
        assert {str(j.id) for j in incident_row.jobs} == {"job-0", "job-1"}
