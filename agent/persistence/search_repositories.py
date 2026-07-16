from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy import Select, and_, case, exists, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from agent.application.search_service import (
    EventSearchCriteria,
    EventSearchResult,
    IncidentSearchCriteria,
    IncidentSearchResult,
    JobSearchCriteria,
    JobSearchResult,
    RepositorySearchPage,
    SEVERITY_RANKS,
    SearchCursor,
    SearchValidationError,
    SignalSearchCriteria,
    SignalSearchResult,
    SortDirection,
)
from agent.persistence.orm_models import (
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    Report,
)


T = TypeVar("T")


def _severity_rank(column: ColumnElement[Any]) -> ColumnElement[int]:
    return case(SEVERITY_RANKS, value=column, else_=-1)


class SqlAlchemySearchRepository:
    """Bounded, allowlist-only structured metadata search."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _json_array_contains(
        self, column: ColumnElement[Any], value: str
    ) -> ColumnElement[bool]:
        dialect = self._session.get_bind().dialect.name
        if dialect == "sqlite":
            elements = func.json_each(column).table_valued("key", "value").alias()
        elif dialect == "postgresql":
            elements = func.json_array_elements_text(column).table_valued("value").alias()
        else:
            raise SearchValidationError("mitre_technique_filter_not_supported")
        return exists(select(1).select_from(elements).where(elements.c.value == value))

    @staticmethod
    def _with_cursor(
        statement: Select[Any],
        sort_column: ColumnElement[Any],
        id_column: ColumnElement[str],
        cursor: SearchCursor | None,
        direction: SortDirection,
    ) -> Select[Any]:
        if cursor is None:
            return statement
        id_after = id_column > cursor.item_id if direction == "asc" else id_column < cursor.item_id
        if cursor.value is None:
            return statement.where(and_(sort_column.is_(None), id_after))
        value_after = sort_column > cursor.value if direction == "asc" else sort_column < cursor.value
        return statement.where(
            or_(
                value_after,
                and_(sort_column == cursor.value, id_after),
                sort_column.is_(None),
            )
        )

    def _execute_page(
        self,
        statement: Select[Any],
        *,
        sort_column: ColumnElement[Any],
        id_column: ColumnElement[str],
        sort_key: str,
        id_key: str,
        direction: SortDirection,
        cursor: SearchCursor | None,
        page_size: int,
        mapper: Callable[[Any], T],
    ) -> RepositorySearchPage[T]:
        statement = self._with_cursor(
            statement, sort_column, id_column, cursor, direction
        )
        primary_order = (
            sort_column.asc().nullslast()
            if direction == "asc"
            else sort_column.desc().nullslast()
        )
        tie_order = id_column.asc() if direction == "asc" else id_column.desc()
        bounded = statement.order_by(primary_order, tie_order).limit(page_size + 1)
        rows = self._session.execute(bounded).mappings().fetchmany(page_size + 1)
        has_more = len(rows) > page_size
        page_rows = rows[:page_size]
        items = [mapper(row) for row in page_rows]
        next_position = None
        if has_more and page_rows:
            last = page_rows[-1]
            next_position = (last[sort_key], str(last[id_key]))
        return RepositorySearchPage(items, has_more, next_position)

    def search_incidents(
        self, criteria: IncidentSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[IncidentSearchResult]:
        event_count = (
            select(func.count(IncidentEvent.id))
            .where(IncidentEvent.incident_id == Incident.incident_id)
            .correlate(Incident)
            .scalar_subquery()
        )
        signal_count = (
            select(func.count(IncidentSignal.id))
            .where(IncidentSignal.incident_id == Incident.incident_id)
            .correlate(Incident)
            .scalar_subquery()
        )
        has_report = exists(
            select(1).where(Report.incident_id == Incident.incident_id)
        )
        statement = select(
            Incident.incident_id.label("incident_id"),
            Incident.title.label("title"),
            Incident.incident_type.label("incident_type"),
            Incident.incident_family.label("incident_family"),
            Incident.severity.label("severity"),
            Incident.confidence.label("confidence"),
            Incident.status.label("status"),
            Incident.first_seen.label("first_seen"),
            Incident.last_seen.label("last_seen"),
            Incident.created_at.label("created_at"),
            Incident.primary_entity.label("primary_entity"),
            event_count.label("event_count"),
            signal_count.label("signal_count"),
            has_report.label("has_report"),
        )
        if criteria.statuses:
            statement = statement.where(Incident.status.in_(criteria.statuses))
        if criteria.severities:
            statement = statement.where(Incident.severity.in_(criteria.severities))
        for column, value in (
            (Incident.incident_type, criteria.incident_type),
            (Incident.incident_family, criteria.incident_family),
            (Incident.primary_entity, criteria.primary_entity),
        ):
            if value is not None:
                statement = statement.where(column == value)
        if criteria.min_confidence is not None:
            statement = statement.where(Incident.confidence >= criteria.min_confidence)
        if criteria.max_confidence is not None:
            statement = statement.where(Incident.confidence <= criteria.max_confidence)
        for date_column, start, end in (
            (Incident.first_seen, criteria.first_seen_from, criteria.first_seen_to),
            (Incident.last_seen, criteria.last_seen_from, criteria.last_seen_to),
            (Incident.created_at, criteria.created_at_from, criteria.created_at_to),
        ):
            if start is not None:
                statement = statement.where(date_column >= start)
            if end is not None:
                statement = statement.where(date_column <= end)
        if criteria.mitre_technique is not None:
            statement = statement.where(
                self._json_array_contains(
                    Incident.mitre_techniques, criteria.mitre_technique
                )
            )
        if criteria.job_id is not None:
            statement = statement.where(
                Incident.jobs.any(IngestionJob.id == criteria.job_id)
            )
        if criteria.has_report is not None:
            statement = statement.where(
                has_report if criteria.has_report else ~has_report
            )
        if criteria.has_validated_evidence is not None:
            has_validated_evidence = exists(
                select(1).where(
                    EvidenceItem.incident_id == Incident.incident_id,
                    EvidenceItem.validation_status == "validated",
                )
            )
            statement = statement.where(
                has_validated_evidence
                if criteria.has_validated_evidence
                else ~has_validated_evidence
            )
        if criteria.title_prefix is not None:
            statement = statement.where(
                Incident.title.startswith(criteria.title_prefix, autoescape=True)
            )
        sort_columns: dict[str, ColumnElement[Any]] = {
            "created_at": Incident.created_at,
            "first_seen": Incident.first_seen,
            "last_seen": Incident.last_seen,
            "severity": _severity_rank(Incident.severity),
            "confidence": Incident.confidence,
        }
        sort_column = sort_columns[criteria.sort]
        sort_key: str = criteria.sort
        if criteria.sort == "severity":
            sort_key = "_severity_rank"
            statement = statement.add_columns(sort_column.label(sort_key))
        return self._execute_page(
            statement,
            sort_column=sort_column,
            id_column=Incident.incident_id,
            sort_key=sort_key,
            id_key="incident_id",
            direction=criteria.direction,
            cursor=cursor,
            page_size=criteria.page_size,
            mapper=lambda row: IncidentSearchResult(
                incident_id=str(row["incident_id"]),
                title=str(row["title"] or ""),
                incident_type=str(row["incident_type"] or ""),
                incident_family=str(row["incident_family"] or ""),
                severity=str(row["severity"] or ""),
                confidence=float(row["confidence"] or 0),
                status=str(row["status"] or ""),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                created_at=row["created_at"],
                primary_entity=str(row["primary_entity"] or ""),
                signal_count=int(row["signal_count"]),
                event_count=int(row["event_count"]),
                has_report=bool(row["has_report"]),
            ),
        )

    def search_events(
        self, criteria: EventSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[EventSearchResult]:
        statement = select(
            CanonicalEvent.event_id.label("event_id"),
            CanonicalEvent.timestamp.label("timestamp"),
            CanonicalEvent.source_name.label("source_name"),
            CanonicalEvent.parser_name.label("parser_name"),
            CanonicalEvent.src_ip.label("src_ip"),
            CanonicalEvent.dst_ip.label("dst_ip"),
            CanonicalEvent.src_port.label("src_port"),
            CanonicalEvent.dst_port.label("dst_port"),
            CanonicalEvent.protocol.label("protocol"),
            CanonicalEvent.action.label("action"),
            CanonicalEvent.safe_message_excerpt.label("safe_message_excerpt"),
        )
        for column, value in (
            (CanonicalEvent.event_id, criteria.event_id),
            (CanonicalEvent.source_name, criteria.source_name),
            (CanonicalEvent.parser_name, criteria.parser_name),
            (CanonicalEvent.src_ip, criteria.src_ip),
            (CanonicalEvent.dst_ip, criteria.dst_ip),
            (CanonicalEvent.src_port, criteria.src_port),
            (CanonicalEvent.dst_port, criteria.dst_port),
            (CanonicalEvent.protocol, criteria.protocol),
            (CanonicalEvent.action, criteria.action),
            (CanonicalEvent.user, criteria.user),
        ):
            if value is not None:
                statement = statement.where(column == value)
        if criteria.timestamp_from is not None:
            statement = statement.where(
                CanonicalEvent.timestamp >= criteria.timestamp_from
            )
        if criteria.timestamp_to is not None:
            statement = statement.where(CanonicalEvent.timestamp <= criteria.timestamp_to)
        if criteria.job_id is not None:
            statement = statement.where(
                CanonicalEvent.jobs.any(IngestionJob.id == criteria.job_id)
            )
        if criteria.incident_id is not None:
            incident_relation = exists(
                select(1).where(
                    IncidentEvent.incident_id == criteria.incident_id,
                    IncidentEvent.event_id == CanonicalEvent.event_id,
                )
            )
            if criteria.is_context is not None:
                incident_relation = exists(
                    select(1).where(
                        IncidentEvent.incident_id == criteria.incident_id,
                        IncidentEvent.event_id == CanonicalEvent.event_id,
                        IncidentEvent.is_context == criteria.is_context,
                    )
                )
            statement = statement.where(incident_relation)
        return self._execute_page(
            statement,
            sort_column=CanonicalEvent.timestamp,
            id_column=CanonicalEvent.event_id,
            sort_key="timestamp",
            id_key="event_id",
            direction=criteria.direction,
            cursor=cursor,
            page_size=criteria.page_size,
            mapper=lambda row: EventSearchResult(
                event_id=str(row["event_id"]),
                timestamp=row["timestamp"],
                source_name=str(row["source_name"] or ""),
                parser_name=str(row["parser_name"] or ""),
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                src_port=row["src_port"],
                dst_port=row["dst_port"],
                protocol=row["protocol"],
                action=row["action"],
                safe_message_excerpt=str(row["safe_message_excerpt"] or ""),
            ),
        )

    def search_signals(
        self, criteria: SignalSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[SignalSearchResult]:
        statement = select(
            DetectionSignal.signal_id.label("signal_id"),
            DetectionSignal.rule_id.label("rule_id"),
            DetectionSignal.rule_name.label("rule_name"),
            DetectionSignal.signal_type.label("signal_type"),
            DetectionSignal.severity.label("severity"),
            DetectionSignal.confidence.label("confidence"),
            DetectionSignal.first_seen.label("first_seen"),
            DetectionSignal.last_seen.label("last_seen"),
            DetectionSignal.created_at.label("created_at"),
            DetectionSignal.suppressed.label("suppressed"),
        )
        for column, value in (
            (DetectionSignal.signal_id, criteria.signal_id),
            (DetectionSignal.rule_id, criteria.rule_id),
            (DetectionSignal.rule_name, criteria.rule_name),
            (DetectionSignal.signal_type, criteria.signal_type),
            (DetectionSignal.signal_family, criteria.signal_family),
        ):
            if value is not None:
                statement = statement.where(column == value)
        if criteria.severities:
            statement = statement.where(
                DetectionSignal.severity.in_(criteria.severities)
            )
        if criteria.min_confidence is not None:
            statement = statement.where(
                DetectionSignal.confidence >= criteria.min_confidence
            )
        if criteria.max_confidence is not None:
            statement = statement.where(
                DetectionSignal.confidence <= criteria.max_confidence
            )
        if criteria.suppressed is not None:
            statement = statement.where(
                DetectionSignal.suppressed == criteria.suppressed
            )
        for date_column, start, end in (
            (
                DetectionSignal.first_seen,
                criteria.first_seen_from,
                criteria.first_seen_to,
            ),
            (
                DetectionSignal.last_seen,
                criteria.last_seen_from,
                criteria.last_seen_to,
            ),
        ):
            if start is not None:
                statement = statement.where(date_column >= start)
            if end is not None:
                statement = statement.where(date_column <= end)
        if criteria.job_id is not None:
            statement = statement.where(
                DetectionSignal.jobs.any(IngestionJob.id == criteria.job_id)
            )
        if criteria.incident_id is not None:
            statement = statement.where(
                exists(
                    select(1).where(
                        IncidentSignal.incident_id == criteria.incident_id,
                        IncidentSignal.signal_id == DetectionSignal.signal_id,
                    )
                )
            )
        if criteria.mitre_technique is not None:
            statement = statement.where(
                self._json_array_contains(
                    DetectionSignal.mitre_techniques, criteria.mitre_technique
                )
            )
        sort_columns: dict[str, ColumnElement[Any]] = {
            "created_at": DetectionSignal.created_at,
            "first_seen": DetectionSignal.first_seen,
            "last_seen": DetectionSignal.last_seen,
            "severity": _severity_rank(DetectionSignal.severity),
            "confidence": DetectionSignal.confidence,
        }
        sort_column = sort_columns[criteria.sort]
        sort_key: str = criteria.sort
        if criteria.sort == "severity":
            sort_key = "_severity_rank"
            statement = statement.add_columns(sort_column.label(sort_key))
        return self._execute_page(
            statement,
            sort_column=sort_column,
            id_column=DetectionSignal.signal_id,
            sort_key=sort_key,
            id_key="signal_id",
            direction=criteria.direction,
            cursor=cursor,
            page_size=criteria.page_size,
            mapper=lambda row: SignalSearchResult(
                signal_id=str(row["signal_id"]),
                rule_id=str(row["rule_id"] or ""),
                rule_name=str(row["rule_name"] or ""),
                signal_type=str(row["signal_type"] or ""),
                severity=str(row["severity"] or ""),
                confidence=float(row["confidence"] or 0),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                suppressed=bool(row["suppressed"]),
            ),
        )

    def search_jobs(
        self, criteria: JobSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[JobSearchResult]:
        statement = select(
            IngestionJob.id.label("job_id"),
            IngestionJob.status.label("status"),
            IngestionJob.source_name.label("source_name"),
            IngestionJob.analysis_mode.label("analysis_mode"),
            IngestionJob.created_at.label("created_at"),
            IngestionJob.started_at.label("started_at"),
            IngestionJob.completed_at.label("completed_at"),
            IngestionJob.attempt_count.label("attempt_count"),
            IngestionJob.reused_count.label("reused_count"),
            IngestionJob.error_code.label("error_code"),
        )
        for column, value in (
            (IngestionJob.id, criteria.job_id),
            (IngestionJob.analysis_mode, criteria.analysis_mode),
            (IngestionJob.source_name, criteria.source_name),
            (IngestionJob.file_sha256, criteria.file_sha256),
            (IngestionJob.pipeline_version, criteria.pipeline_version),
            (IngestionJob.error_code, criteria.error_code),
        ):
            if value is not None:
                statement = statement.where(column == value)
        if criteria.statuses:
            statement = statement.where(IngestionJob.status.in_(criteria.statuses))
        if criteria.reused is not None:
            statement = statement.where(
                IngestionJob.reused_count > 0
                if criteria.reused
                else IngestionJob.reused_count == 0
            )
        if criteria.min_reused_count is not None:
            statement = statement.where(
                IngestionJob.reused_count >= criteria.min_reused_count
            )
        for date_column, start, end in (
            (IngestionJob.created_at, criteria.created_at_from, criteria.created_at_to),
            (IngestionJob.queued_at, criteria.queued_at_from, criteria.queued_at_to),
            (
                IngestionJob.completed_at,
                criteria.completed_at_from,
                criteria.completed_at_to,
            ),
        ):
            if start is not None:
                statement = statement.where(date_column >= start)
            if end is not None:
                statement = statement.where(date_column <= end)
        if criteria.cancelled is not None:
            is_cancelled = or_(
                IngestionJob.status == "cancelled",
                IngestionJob.cancelled_at.is_not(None),
            )
            statement = statement.where(
                is_cancelled if criteria.cancelled else ~is_cancelled
            )
        if criteria.min_attempt_count is not None:
            statement = statement.where(
                IngestionJob.attempt_count >= criteria.min_attempt_count
            )
        sort_columns: dict[str, ColumnElement[Any]] = {
            "created_at": IngestionJob.created_at,
            "completed_at": IngestionJob.completed_at,
            "status": IngestionJob.status,
        }
        return self._execute_page(
            statement,
            sort_column=sort_columns[criteria.sort],
            id_column=IngestionJob.id,
            sort_key=criteria.sort,
            id_key="job_id",
            direction=criteria.direction,
            cursor=cursor,
            page_size=criteria.page_size,
            mapper=lambda row: JobSearchResult(
                job_id=str(row["job_id"]),
                status=str(row["status"] or ""),
                source_name=str(row["source_name"] or ""),
                analysis_mode=row["analysis_mode"],
                created_at=row["created_at"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                attempt_count=int(row["attempt_count"] or 0),
                reused_count=int(row["reused_count"] or 0),
                error_code=row["error_code"],
            ),
        )
