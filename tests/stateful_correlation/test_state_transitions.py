"""Phase 6E.4A blocker 2: state-transition semantics - a stale backward
arrival must never replace or mutate an active campaign."""

from __future__ import annotations

import datetime
import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.persistence.orm_models import Base
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import make_event, make_incident, make_signal, submit_job


DAY = datetime.datetime(2026, 7, 10, tzinfo=datetime.timezone.utc)


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


def _at(hour: int) -> datetime.datetime:
    return DAY + datetime.timedelta(hours=hour)


def test_stale_backward_arrival_leaves_active_state_unchanged(session_factory) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_window_seconds=3600,
        stateful_correlation_state_ttl_seconds=86400,
    )
    service = StatefulIncidentCorrelationService()

    # Active campaign at 10:00.
    active_time = _at(10)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1", ts=active_time)]
        signal = make_signal("SIG-A", ["a1"], ts=active_time)
        incident = make_incident("INC-A", signal, events, ts=active_time)
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=active_time,
        )
    key = result_a.correlation_key
    canonical_id = result_a.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(key)
        before = (
            str(state.incident_id),
            int(state.generation),
            int(state.version),
            state.first_seen,
            state.last_seen,
        )

    # Late incident describing activity at 01:00, ingested at 10:05. 01:00 is
    # far older than 10:00 - window (09:00), so it must be classified stale.
    late_event = _at(1)
    ingestion_time = _at(10) + datetime.timedelta(minutes=5)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("b1", ts=late_event)]
        signal = make_signal("SIG-B", ["b1"], ts=late_event)
        incident = make_incident("INC-B", signal, events, ts=late_event)
        result_b, _ = submit_job(
            uow, service, settings,
            job_id="job-b", events=events, signal=signal, incident=incident,
            now=ingestion_time,
        )

    assert result_b.status == "stale"
    assert result_b.material_changes == ()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(key)
        after = (
            str(state.incident_id),
            int(state.generation),
            int(state.version),
            state.first_seen,
            state.last_seen,
        )
        # The stale arrival never became (or displaced) the canonical
        # campaign incident.
        assert str(state.incident_id) == canonical_id

    # incident_id, generation, version, first_seen and last_seen all unchanged.
    assert after == before


def test_later_burst_beyond_window_starts_new_generation(session_factory) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_window_seconds=3600,
        stateful_correlation_state_ttl_seconds=86400,
    )
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1", ts=_at(10))]
        signal = make_signal("SIG-A", ["a1"], ts=_at(10))
        incident = make_incident("INC-A", signal, events, ts=_at(10))
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=_at(10),
        )
    canonical_id = result_a.canonical_incident_id

    # A distinctly later burst (16:00) - beyond 10:00 + 1h window - starts a
    # new generation rather than merging into the earlier active campaign.
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("c1", ts=_at(16))]
        signal = make_signal("SIG-C", ["c1"], ts=_at(16))
        incident = make_incident("INC-C", signal, events, ts=_at(16))
        result_c, _ = submit_job(
            uow, service, settings,
            job_id="job-c", events=events, signal=signal, incident=incident, now=_at(16),
        )

    assert result_c.status == "new_generation"
    assert result_c.generation == 2
    assert result_c.canonical_incident_id != canonical_id
