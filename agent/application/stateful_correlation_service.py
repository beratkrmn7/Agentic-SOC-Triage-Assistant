"""Phase 6E.4A: persistent cross-job correlation - persistence mechanics.

This module is the only place that touches the database for stateful
correlation. It is intentionally NOT called from AnalysisService yet - see
`StatefulIncidentCorrelationService.resolve_and_merge`'s `enabled` guard,
which makes the whole facade a proven no-op whenever
`settings.stateful_correlation_enabled` is False. Production routing
integration (deciding when to call this, LLM report reuse, retriage
suppression) is Phase 6E.4B's responsibility, not this foundation's.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Sequence, cast

from sqlalchemy.exc import IntegrityError

from agent.config import Settings
from agent.correlation.merge import merge_incident_bundles
from agent.correlation.stateful import (
    StatefulStateSnapshot,
    compute_correlation_key,
    derive_stateful_profile,
    is_state_eligible,
)
from agent.detection.config import DetectionSettings
from agent.detection.models import DetectionSignal, IncidentBundle
from agent.persistence.lifecycle import IncidentLifecycle
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import (
    DetectionSignal as OrmDetectionSignal,
    Incident,
    IncidentCorrelationState,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
)
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent


ResolveStatus = Literal[
    "created", "merged", "no_op", "new_generation", "unsupported", "disabled"
]

MaterialChangeCode = str


class StatefulCorrelationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class StatefulResolveResult:
    status: ResolveStatus
    canonical_incident: Optional[Incident]
    incoming_incident_id: str
    canonical_incident_id: Optional[str]
    correlation_key: Optional[str]
    generation: Optional[int]
    material_changes: tuple[MaterialChangeCode, ...]


def _as_utc(value: Any) -> datetime:
    """SQLite drops tzinfo on round-trip even for DateTime(timezone=True)
    columns; every other supported dialect preserves it. Normalize to
    UTC-aware here so downstream comparisons never straddle naive/aware.

    `value` is typed Any because this codebase's classic (non-Mapped)
    SQLAlchemy Column declarations statically type instance attribute
    access as Column[datetime] rather than datetime - the runtime value on
    a loaded ORM instance is always a real datetime.
    """
    value = cast(datetime, value)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _state_snapshot(state: IncidentCorrelationState) -> StatefulStateSnapshot:
    return StatefulStateSnapshot(
        correlation_version=str(state.correlation_version),
        generation=int(state.generation),
        incident_id=str(state.incident_id),
        first_seen=_as_utc(state.first_seen),
        last_seen=_as_utc(state.last_seen),
        expires_at=_as_utc(state.expires_at),
    )


def _is_noop(canonical_row: Incident, incoming_bundle: IncidentBundle, job: IngestionJob) -> bool:
    if job not in canonical_row.jobs:
        return False
    existing_event_ids = {e.event_id for e in canonical_row.events if not e.is_context}
    if not set(incoming_bundle.event_ids) <= existing_event_ids:
        return False
    existing_signal_ids = {s.signal_id for s in canonical_row.signals}
    if not set(incoming_bundle.signal_ids) <= existing_signal_ids:
        return False
    return True


class StatefulIncidentMergeService:
    """Focused persistence mechanics for one canonical Incident row."""

    def create_canonical(
        self, uow: UnitOfWork, *, bundle: IncidentBundle, job: IngestionJob
    ) -> Incident:
        existing = uow.incidents.get_for_update(bundle.incident_id)
        if existing is not None:
            if job not in existing.jobs:
                existing.jobs.append(job)
            return existing

        orm_incident = DataMapper.domain_incident_to_orm(bundle)
        uow.incidents.add(orm_incident)
        orm_incident.jobs.append(job)
        IncidentLifecycle.transition(orm_incident, "new", actor="stateful_correlation")
        return orm_incident

    def merge_into_canonical(
        self,
        uow: UnitOfWork,
        *,
        canonical_row: Incident,
        incoming_bundle: IncidentBundle,
        job: IngestionJob,
        available_signals: Optional[Sequence[DetectionSignal]],
        detection_settings: DetectionSettings,
        max_context_events: int,
    ):
        canonical_bundle = DataMapper.orm_to_domain_incident(canonical_row)
        # SQLite drops tzinfo on DateTime(timezone=True) round-trips; other
        # dialects preserve it. Normalize so merge_incident_bundles never
        # compares a naive ORM-loaded timestamp against an aware one.
        canonical_bundle = canonical_bundle.model_copy(
            update={
                "first_seen": _as_utc(canonical_bundle.first_seen),
                "last_seen": _as_utc(canonical_bundle.last_seen),
            }
        )
        outcome = merge_incident_bundles(
            canonical=canonical_bundle,
            incoming=incoming_bundle,
            available_signals=available_signals,
            settings=detection_settings,
            max_context_events=max_context_events,
        )
        merged = outcome.incident

        existing_rows_by_id = {row.event_id: row for row in canonical_row.events}
        for event_id in merged.event_ids:
            row = existing_rows_by_id.get(event_id)
            if row is None:
                canonical_row.events.append(IncidentEvent(event_id=event_id, is_context=False))
            elif row.is_context:
                row.is_context = False
        for event_id in merged.context_event_ids:
            if event_id not in existing_rows_by_id:
                canonical_row.events.append(IncidentEvent(event_id=event_id, is_context=True))

        existing_signal_ids = {s.signal_id for s in canonical_row.signals}
        for signal_id in merged.signal_ids:
            if signal_id not in existing_signal_ids:
                canonical_row.signals.append(IncidentSignal(signal_id=signal_id))

        if job not in canonical_row.jobs:
            canonical_row.jobs.append(job)

        # Classic (non-Mapped) Column declarations statically type instance
        # attributes as Column[T]; the same convention as
        # agent/persistence/lifecycle.py's IncidentLifecycle.transition.
        canonical_row.title = merged.title  # type: ignore[assignment]
        canonical_row.incident_type = merged.incident_type  # type: ignore[assignment]
        canonical_row.incident_family = merged.incident_family  # type: ignore[assignment]
        canonical_row.severity = merged.severity  # type: ignore[assignment]
        canonical_row.confidence = merged.confidence  # type: ignore[assignment]
        canonical_row.first_seen = merged.first_seen  # type: ignore[assignment]
        canonical_row.last_seen = merged.last_seen  # type: ignore[assignment]
        canonical_row.primary_entity = merged.primary_entity  # type: ignore[assignment]
        canonical_row.target_entities = merged.target_entities  # type: ignore[assignment]
        canonical_row.mitre_techniques = merged.mitre_techniques  # type: ignore[assignment]
        canonical_row.metrics = merged.metrics  # type: ignore[assignment]

        if outcome.material_changes:
            canonical_row.version = max(1, int(canonical_row.version or 1)) + 1  # type: ignore[assignment]

        return canonical_row, outcome


class StatefulIncidentCorrelationService:
    """Public facade: `resolve_and_merge` is the single entry point.

    Not wired into AnalysisService in this foundation PR. When
    `settings.stateful_correlation_enabled` is False, this method performs
    no database writes and returns status="disabled" - callers can invoke
    it unconditionally without behavior changing while the flag stays off.
    """

    def __init__(self, merge_service: Optional[StatefulIncidentMergeService] = None) -> None:
        self._merge_service = merge_service or StatefulIncidentMergeService()

    def resolve_and_merge(
        self,
        uow: UnitOfWork,
        *,
        incoming_bundle: IncidentBundle,
        incoming_events: Sequence[CanonicalLogEvent],
        incoming_signal_rows: Sequence[OrmDetectionSignal],
        job: IngestionJob,
        settings: Optional[Settings] = None,
        detection_settings: Optional[DetectionSettings] = None,
        now: Optional[datetime] = None,
    ) -> StatefulResolveResult:
        settings = settings or uow.settings
        detection_settings = detection_settings or DetectionSettings()
        now = now or datetime.now(timezone.utc)

        if not settings.stateful_correlation_enabled:
            return StatefulResolveResult(
                status="disabled",
                canonical_incident=None,
                incoming_incident_id=incoming_bundle.incident_id,
                canonical_incident_id=None,
                correlation_key=None,
                generation=None,
                material_changes=(),
            )

        profile = derive_stateful_profile(
            incoming_bundle,
            incoming_events,
            correlation_version=settings.stateful_correlation_version,
            max_profile_items=settings.stateful_correlation_max_profile_items,
        )
        if profile is None:
            return StatefulResolveResult(
                status="unsupported",
                canonical_incident=None,
                incoming_incident_id=incoming_bundle.incident_id,
                canonical_incident_id=None,
                correlation_key=None,
                generation=None,
                material_changes=(),
            )

        correlation_key = compute_correlation_key(profile)
        ttl = timedelta(seconds=settings.stateful_correlation_state_ttl_seconds)
        window_seconds = settings.stateful_correlation_window_seconds

        assert uow.session is not None, "resolve_and_merge requires an open UnitOfWork"
        session = uow.session

        state = uow.correlation_state.get_for_update(correlation_key)

        if state is None:
            try:
                with session.begin_nested():
                    new_state = IncidentCorrelationState(
                        correlation_key=correlation_key,
                        correlation_version=profile.correlation_version,
                        strategy=profile.strategy,
                        incident_id=incoming_bundle.incident_id,
                        profile=profile.model_dump(mode="json"),
                        generation=1,
                        first_seen=incoming_bundle.first_seen,
                        last_seen=incoming_bundle.last_seen,
                        expires_at=now + ttl,
                        version=1,
                    )
                    uow.correlation_state.add(new_state)
                    session.flush()
            except IntegrityError:
                # Another worker won the race to create this correlation_key.
                # Re-read the winning row and fall through to the
                # already-exists handling below using that row.
                state = uow.correlation_state.get_for_update(correlation_key)
                if state is None:
                    raise StatefulCorrelationError(
                        "stateful_correlation_state_race_unresolved"
                    ) from None
            else:
                canonical_row = self._merge_service.create_canonical(
                    uow, bundle=incoming_bundle, job=job
                )
                session.flush()
                return StatefulResolveResult(
                    status="created",
                    canonical_incident=canonical_row,
                    incoming_incident_id=incoming_bundle.incident_id,
                    canonical_incident_id=str(canonical_row.incident_id),
                    correlation_key=correlation_key,
                    generation=1,
                    material_changes=("new_state",),
                )

        incident_exists = uow.incidents.get_for_update(state.incident_id) is not None
        eligible = incident_exists and is_state_eligible(
            _state_snapshot(state),
            correlation_version=profile.correlation_version,
            incident_exists=incident_exists,
            incoming_first_seen=incoming_bundle.first_seen,
            incoming_last_seen=incoming_bundle.last_seen,
            window_seconds=window_seconds,
            now=now,
        )

        if eligible:
            canonical_row = uow.incidents.get_for_update(state.incident_id)
            assert canonical_row is not None

            if _is_noop(canonical_row, incoming_bundle, job):
                return StatefulResolveResult(
                    status="no_op",
                    canonical_incident=canonical_row,
                    incoming_incident_id=incoming_bundle.incident_id,
                    canonical_incident_id=str(canonical_row.incident_id),
                    correlation_key=correlation_key,
                    generation=int(state.generation),
                    material_changes=(),
                )

            available_signals = self._load_available_signals(
                uow, canonical_row, incoming_signal_rows
            )
            merged_row, outcome = self._merge_service.merge_into_canonical(
                uow,
                canonical_row=canonical_row,
                incoming_bundle=incoming_bundle,
                job=job,
                available_signals=available_signals,
                detection_settings=detection_settings,
                max_context_events=detection_settings.MAX_CONTEXT_EVENTS_PER_INCIDENT,
            )
            session.flush()

            new_first_seen = min(_as_utc(state.first_seen), incoming_bundle.first_seen)
            new_last_seen = max(_as_utc(state.last_seen), incoming_bundle.last_seen)
            ok = uow.correlation_state.extend_active_generation(
                correlation_key,
                expected_version=int(state.version),
                profile=profile.model_dump(mode="json"),
                first_seen=new_first_seen,
                last_seen=new_last_seen,
                expires_at=now + ttl,
                now=now,
            )
            if not ok:
                raise StatefulCorrelationError("stateful_correlation_state_conflict")

            return StatefulResolveResult(
                status="merged",
                canonical_incident=merged_row,
                incoming_incident_id=incoming_bundle.incident_id,
                canonical_incident_id=str(merged_row.incident_id),
                correlation_key=correlation_key,
                generation=int(state.generation),
                material_changes=outcome.material_changes,
            )

        new_generation = int(state.generation) + 1
        canonical_row = self._merge_service.create_canonical(
            uow, bundle=incoming_bundle, job=job
        )
        session.flush()
        ok = uow.correlation_state.replace_expired_generation(
            correlation_key,
            expected_version=int(state.version),
            new_incident_id=str(canonical_row.incident_id),
            new_generation=new_generation,
            profile=profile.model_dump(mode="json"),
            first_seen=incoming_bundle.first_seen,
            last_seen=incoming_bundle.last_seen,
            expires_at=now + ttl,
            now=now,
        )
        if not ok:
            raise StatefulCorrelationError("stateful_correlation_state_conflict")

        return StatefulResolveResult(
            status="new_generation",
            canonical_incident=canonical_row,
            incoming_incident_id=incoming_bundle.incident_id,
            canonical_incident_id=str(canonical_row.incident_id),
            correlation_key=correlation_key,
            generation=new_generation,
            material_changes=("new_generation",),
        )

    @staticmethod
    def _load_available_signals(
        uow: UnitOfWork,
        canonical_row: Incident,
        incoming_signal_rows: Sequence[OrmDetectionSignal],
    ) -> list[DetectionSignal]:
        def _normalized(signal: DetectionSignal) -> DetectionSignal:
            # See _as_utc: SQLite drops tzinfo on round-trip.
            return signal.model_copy(
                update={
                    "first_seen": _as_utc(signal.first_seen),
                    "last_seen": _as_utc(signal.last_seen),
                }
            )

        domain_signals: list[DetectionSignal] = []
        seen: set[str] = set()
        for row in incoming_signal_rows:
            if row.signal_id not in seen:
                domain_signals.append(_normalized(DataMapper.orm_to_domain_signal(row)))
                seen.add(str(row.signal_id))
        for signal_assoc in canonical_row.signals:
            signal_id = str(signal_assoc.signal_id)
            if signal_id in seen:
                continue
            orm_row = uow.detection_signals.get(signal_id)
            if orm_row is not None:
                domain_signals.append(_normalized(DataMapper.orm_to_domain_signal(orm_row)))
                seen.add(signal_id)
        return domain_signals
