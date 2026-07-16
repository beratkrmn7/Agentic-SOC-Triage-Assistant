from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import String, and_, case, cast, exists, false, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.selectable import Select

from agent.application.retention import (
    RetentionCandidateSummary,
    RetentionCutoffs,
    RetentionEntity,
)
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    RetentionHold,
    ingestion_job_events,
    ingestion_job_incidents,
    ingestion_job_signals,
)


TERMINAL_INCIDENT_STATUSES = ("resolved", "closed")
ELIGIBLE_JOB_STATUSES = ("completed",)


@dataclass(frozen=True)
class RetentionCandidateSpec:
    entity_type: RetentionEntity
    model: type[Any]
    entity_id_column: ColumnElement[Any]
    timestamp_column: ColumnElement[datetime]
    timestamp_attribute: str
    entity_id_attribute: str
    cutoff: datetime
    candidate: ColumnElement[bool]
    protected_active: ColumnElement[bool]
    protected_hold: ColumnElement[bool]


class RetentionRepository:
    """Central retention predicates for aggregate planning and bounded export."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def summarize(
        self,
        *,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
    ) -> tuple[RetentionCandidateSummary, ...]:
        return tuple(
            self._aggregate(self.candidate_spec(entity_type, cutoffs, as_of))
            for entity_type in (
                "canonical_event",
                "detection_signal",
                "ingestion_job",
                "incident",
                "audit_event",
            )
        )

    def candidate_spec(
        self,
        entity_type: RetentionEntity,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
    ) -> RetentionCandidateSpec:
        if entity_type == "canonical_event":
            return self._canonical_event_spec(cutoffs.canonical_event, as_of)
        if entity_type == "detection_signal":
            return self._detection_signal_spec(cutoffs.detection_signal, as_of)
        if entity_type == "ingestion_job":
            return self._ingestion_job_spec(cutoffs.ingestion_job, as_of)
        if entity_type == "incident":
            return self._incident_spec(cutoffs.incident, as_of)
        return self._audit_event_spec(cutoffs.audit_event, as_of)

    def candidate_select(
        self,
        entity_type: RetentionEntity,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
        *,
        value_column: ColumnElement[Any] | None = None,
    ) -> Select[Any]:
        spec = self.candidate_spec(entity_type, cutoffs, as_of)
        selected = value_column if value_column is not None else spec.entity_id_column
        return select(selected).select_from(spec.model).where(spec.candidate)

    def iter_candidate_batches(
        self,
        entity_type: RetentionEntity,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
        batch_size: int,
    ) -> Iterator[tuple[Any, ...]]:
        if batch_size < 1:
            raise ValueError("retention_batch_size_invalid")
        spec = self.candidate_spec(entity_type, cutoffs, as_of)
        last_timestamp: datetime | None = None
        last_entity_id: str | None = None
        while True:
            statement = select(spec.model).where(spec.candidate)
            if last_timestamp is not None and last_entity_id is not None:
                statement = statement.where(
                    or_(
                        spec.timestamp_column > last_timestamp,
                        and_(
                            spec.timestamp_column == last_timestamp,
                            spec.entity_id_column > last_entity_id,
                        ),
                    )
                )
            statement = statement.order_by(
                spec.timestamp_column.asc(),
                spec.entity_id_column.asc(),
            ).limit(batch_size)
            rows = tuple(self._session.scalars(statement))
            if not rows:
                return
            yield rows
            last = rows[-1]
            last_timestamp = getattr(last, spec.timestamp_attribute)
            raw_entity_id = getattr(last, spec.entity_id_attribute)
            if raw_entity_id is None and entity_type == "audit_event":
                raw_entity_id = last.id
            last_entity_id = str(raw_entity_id)

    def _active_hold(
        self,
        entity_type: RetentionEntity,
        entity_id: ColumnElement[Any],
        as_of: datetime,
    ) -> ColumnElement[bool]:
        return exists(
            select(1).where(
                RetentionHold.entity_type == entity_type,
                RetentionHold.entity_id == entity_id,
                RetentionHold.released_at.is_(None),
                or_(
                    RetentionHold.expires_at.is_(None),
                    RetentionHold.expires_at > as_of,
                ),
            )
        )

    @staticmethod
    def _protected_incident_status() -> ColumnElement[bool]:
        return or_(
            Incident.status.is_(None),
            Incident.status.not_in(TERMINAL_INCIDENT_STATUSES),
        )

    @staticmethod
    def _protected_job_status() -> ColumnElement[bool]:
        return or_(
            IngestionJob.status.is_(None),
            IngestionJob.status.not_in(ELIGIBLE_JOB_STATUSES),
        )

    def _canonical_event_spec(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSpec:
        active_incident = exists(
            select(1)
            .select_from(IncidentEvent)
            .join(Incident, Incident.incident_id == IncidentEvent.incident_id)
            .where(
                IncidentEvent.event_id == CanonicalEvent.event_id,
                self._protected_incident_status(),
            )
        )
        active_job = exists(
            select(1)
            .select_from(ingestion_job_events)
            .join(IngestionJob, IngestionJob.id == ingestion_job_events.c.job_id)
            .where(
                ingestion_job_events.c.event_id == CanonicalEvent.event_id,
                self._protected_job_status(),
            )
        )
        hold = self._active_hold("canonical_event", CanonicalEvent.event_id, as_of)
        aged = and_(
            CanonicalEvent.timestamp.is_not(None),
            CanonicalEvent.timestamp < cutoff,
        )
        protected = or_(active_incident, active_job)
        return RetentionCandidateSpec(
            "canonical_event",
            CanonicalEvent,
            CanonicalEvent.event_id,
            CanonicalEvent.timestamp,
            "timestamp",
            "event_id",
            cutoff,
            and_(aged, ~protected, ~hold),
            and_(aged, protected),
            and_(aged, hold),
        )

    def _detection_signal_spec(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSpec:
        active_incident = exists(
            select(1)
            .select_from(IncidentSignal)
            .join(Incident, Incident.incident_id == IncidentSignal.incident_id)
            .where(
                IncidentSignal.signal_id == DetectionSignal.signal_id,
                self._protected_incident_status(),
            )
        )
        active_job = exists(
            select(1)
            .select_from(ingestion_job_signals)
            .join(IngestionJob, IngestionJob.id == ingestion_job_signals.c.job_id)
            .where(
                ingestion_job_signals.c.signal_id == DetectionSignal.signal_id,
                self._protected_job_status(),
            )
        )
        hold = self._active_hold("detection_signal", DetectionSignal.signal_id, as_of)
        aged = and_(
            DetectionSignal.created_at.is_not(None),
            DetectionSignal.created_at < cutoff,
        )
        protected = or_(active_incident, active_job)
        return RetentionCandidateSpec(
            "detection_signal",
            DetectionSignal,
            DetectionSignal.signal_id,
            DetectionSignal.created_at,
            "created_at",
            "signal_id",
            cutoff,
            and_(aged, ~protected, ~hold),
            and_(aged, protected),
            and_(aged, hold),
        )

    def _ingestion_job_spec(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSpec:
        active_incident = exists(
            select(1)
            .select_from(ingestion_job_incidents)
            .join(Incident, Incident.incident_id == ingestion_job_incidents.c.incident_id)
            .where(
                ingestion_job_incidents.c.job_id == IngestionJob.id,
                self._protected_incident_status(),
            )
        )
        hold = self._active_hold("ingestion_job", IngestionJob.id, as_of)
        aged = and_(
            IngestionJob.completed_at.is_not(None),
            IngestionJob.completed_at < cutoff,
        )
        eligible = IngestionJob.status.in_(ELIGIBLE_JOB_STATUSES)
        protected = or_(self._protected_job_status(), active_incident)
        return RetentionCandidateSpec(
            "ingestion_job",
            IngestionJob,
            IngestionJob.id,
            IngestionJob.completed_at,
            "completed_at",
            "id",
            cutoff,
            and_(aged, eligible, ~active_incident, ~hold),
            and_(aged, protected),
            and_(aged, eligible, hold),
        )

    def _incident_spec(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSpec:
        hold = self._active_hold("incident", Incident.incident_id, as_of)
        aged = and_(Incident.updated_at.is_not(None), Incident.updated_at < cutoff)
        eligible = Incident.status.in_(TERMINAL_INCIDENT_STATUSES)
        return RetentionCandidateSpec(
            "incident",
            Incident,
            Incident.incident_id,
            Incident.updated_at,
            "updated_at",
            "incident_id",
            cutoff,
            and_(aged, eligible, ~hold),
            and_(aged, self._protected_incident_status()),
            and_(aged, eligible, hold),
        )

    def _audit_event_spec(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSpec:
        archive_id = case(
            (AuditEvent.audit_event_id.is_not(None), AuditEvent.audit_event_id),
            else_=cast(AuditEvent.id, String),
        )
        hold = self._active_hold("audit_event", archive_id, as_of)
        aged = and_(AuditEvent.timestamp.is_not(None), AuditEvent.timestamp < cutoff)
        return RetentionCandidateSpec(
            "audit_event",
            AuditEvent,
            archive_id,
            AuditEvent.timestamp,
            "timestamp",
            "audit_event_id",
            cutoff,
            and_(aged, ~hold),
            false(),
            and_(aged, hold),
        )

    def _aggregate(self, spec: RetentionCandidateSpec) -> RetentionCandidateSummary:
        statement = select(
            func.coalesce(func.sum(case((spec.candidate, 1), else_=0)), 0),
            func.min(case((spec.candidate, spec.timestamp_column), else_=None)),
            func.max(case((spec.candidate, spec.timestamp_column), else_=None)),
            func.coalesce(func.sum(case((spec.protected_active, 1), else_=0)), 0),
            func.coalesce(func.sum(case((spec.protected_hold, 1), else_=0)), 0),
        ).select_from(spec.model)
        row = self._session.execute(statement).one()
        return RetentionCandidateSummary(
            entity_type=spec.entity_type,
            cutoff=spec.cutoff,
            candidate_count=int(row[0]),
            oldest_candidate_at=row[1],
            newest_candidate_at=row[2],
            protected_by_active_relationship_count=int(row[3]),
            protected_by_legal_hold_count=int(row[4]),
        )
