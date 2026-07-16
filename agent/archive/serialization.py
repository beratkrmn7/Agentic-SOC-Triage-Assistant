from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from agent.archive.schemas import (
    ArchiveRecord,
    ArchiveDataModel,
    ArchiveEntityType,
    ArchiveRole,
    AuditEventArchiveData,
    CanonicalEventArchiveData,
    DetectionSignalArchiveData,
    EvidenceItemArchiveData,
    IncidentArchiveData,
    IncidentEventAssociationArchiveData,
    IncidentSignalAssociationArchiveData,
    IngestionJobArchiveData,
    JobEventAssociationArchiveData,
    JobIncidentAssociationArchiveData,
    JobSignalAssociationArchiveData,
    ReportArchiveData,
    TriageRunArchiveData,
    safe_string_list,
    safe_text,
    utc_datetime,
)


def _timestamp(value: Any, fallback: datetime) -> datetime:
    return utc_datetime(value) if isinstance(value, datetime) else fallback


def _integer(value: Any, default: int = 0) -> int:
    return int(value) if value is not None else default


def _float(value: Any) -> float | None:
    return float(value) if value is not None else None


def serialize_root_record(
    entity_type: str,
    row: Any,
    *,
    role: str,
    archive_as_of: datetime,
) -> ArchiveRecord:
    archive_as_of = utc_datetime(archive_as_of)
    data: ArchiveDataModel
    if entity_type == "canonical_event":
        recorded_at = _timestamp(row.timestamp, archive_as_of)
        entity_id = str(row.event_id)
        data = CanonicalEventArchiveData(
            source_name=safe_text(row.source_name),
            parser_name=safe_text(row.parser_name, max_length=128),
            parser_version=safe_text(row.parser_version, max_length=64),
            timestamp=recorded_at,
            observed_at=(
                _timestamp(row.observed_at, archive_as_of)
                if row.observed_at is not None
                else None
            ),
            source_line=row.source_line,
            src_ip=safe_text(row.src_ip, max_length=64),
            dst_ip=safe_text(row.dst_ip, max_length=64),
            src_port=row.src_port,
            dst_port=row.dst_port,
            protocol=safe_text(row.protocol, max_length=32),
            action=safe_text(row.action, max_length=64),
            user=safe_text(row.user),
        )
    elif entity_type == "detection_signal":
        recorded_at = _timestamp(row.created_at, archive_as_of)
        entity_id = str(row.signal_id)
        data = DetectionSignalArchiveData(
            rule_id=safe_text(row.rule_id, max_length=128),
            rule_name=safe_text(row.rule_name),
            rule_version=safe_text(row.rule_version, max_length=64),
            signal_family=safe_text(row.signal_family, max_length=128),
            signal_type=safe_text(row.signal_type, max_length=128),
            severity=safe_text(row.severity, max_length=32),
            confidence=_float(row.confidence),
            first_seen=(
                _timestamp(row.first_seen, archive_as_of)
                if row.first_seen is not None
                else None
            ),
            last_seen=(
                _timestamp(row.last_seen, archive_as_of)
                if row.last_seen is not None
                else None
            ),
            created_at=recorded_at,
            suppressed=bool(row.suppressed),
            mitre_techniques=safe_string_list(row.mitre_techniques),
            target_entities=safe_string_list(row.target_entities),
        )
    elif entity_type == "ingestion_job":
        recorded_at = _timestamp(row.completed_at, archive_as_of)
        entity_id = str(row.id)
        data = IngestionJobArchiveData(
            source_name=safe_text(row.source_name),
            file_sha256=(
                str(row.file_sha256).lower()
                if row.file_sha256 and len(str(row.file_sha256)) == 64
                else None
            ),
            pipeline_version=safe_text(row.pipeline_version, max_length=64),
            analysis_mode=safe_text(row.analysis_mode, max_length=64),
            status=safe_text(row.status, max_length=32),
            error_code=safe_text(row.error_code, max_length=128),
            input_format=safe_text(row.input_format, max_length=64),
            created_at=(
                _timestamp(row.created_at, archive_as_of)
                if row.created_at is not None
                else None
            ),
            updated_at=(
                _timestamp(row.updated_at, archive_as_of)
                if row.updated_at is not None
                else None
            ),
            queued_at=(
                _timestamp(row.queued_at, archive_as_of)
                if row.queued_at is not None
                else None
            ),
            started_at=(
                _timestamp(row.started_at, archive_as_of)
                if row.started_at is not None
                else None
            ),
            completed_at=recorded_at,
            attempt_count=_integer(row.attempt_count),
            reused_count=_integer(row.reused_count),
            total_records=_integer(row.total_records),
            parsed_records=_integer(row.parsed_records),
            failed_records=_integer(row.failed_records),
            unsupported_records=_integer(row.unsupported_records),
            semantically_invalid_records=_integer(row.semantically_invalid_records),
            skipped_records=_integer(row.skipped_records),
            bytes_read=_integer(row.bytes_read),
            duration_ms=_integer(row.duration_ms),
            cancel_requested_at=(
                _timestamp(row.cancel_requested_at, archive_as_of)
                if row.cancel_requested_at is not None
                else None
            ),
            cancelled_at=(
                _timestamp(row.cancelled_at, archive_as_of)
                if row.cancelled_at is not None
                else None
            ),
            cancel_reason_code=safe_text(row.cancel_reason_code, max_length=128),
        )
    elif entity_type == "incident":
        recorded_at = _timestamp(row.updated_at, archive_as_of)
        entity_id = str(row.incident_id)
        data = IncidentArchiveData(
            title=safe_text(row.title, max_length=512),
            incident_type=safe_text(row.incident_type, max_length=128),
            incident_family=safe_text(row.incident_family, max_length=128),
            status=safe_text(row.status, max_length=32),
            severity=safe_text(row.severity, max_length=32),
            confidence=_float(row.confidence),
            version=max(1, _integer(row.version, 1)),
            merge_key=safe_text(row.merge_key),
            first_seen=(
                _timestamp(row.first_seen, archive_as_of)
                if row.first_seen is not None
                else None
            ),
            last_seen=(
                _timestamp(row.last_seen, archive_as_of)
                if row.last_seen is not None
                else None
            ),
            created_at=(
                _timestamp(row.created_at, archive_as_of)
                if row.created_at is not None
                else None
            ),
            updated_at=recorded_at,
            primary_entity=safe_text(row.primary_entity),
            target_entities=safe_string_list(row.target_entities),
            mitre_techniques=safe_string_list(row.mitre_techniques),
        )
    elif entity_type == "audit_event":
        recorded_at = _timestamp(row.timestamp, archive_as_of)
        entity_id = str(row.audit_event_id or row.id)
        data = AuditEventArchiveData(
            incident_id=safe_text(row.incident_id),
            timestamp=recorded_at,
            event_type=safe_text(row.event_type, max_length=128),
            entity_type=safe_text(row.entity_type, max_length=128),
            entity_id=safe_text(row.entity_id),
            action=safe_text(row.action, max_length=128),
            old_status=safe_text(row.old_status, max_length=64),
            new_status=safe_text(row.new_status, max_length=64),
            actor_type=safe_text(row.actor_type, max_length=64),
            actor_id=safe_text(row.actor_id),
            request_id=safe_text(row.request_id, max_length=128),
        )
    else:
        raise ValueError("archive_root_entity_type_unsupported")

    return ArchiveRecord(
        entity_type=cast(ArchiveEntityType, entity_type),
        entity_id=entity_id,
        archive_role=cast(ArchiveRole, role),
        recorded_at=recorded_at,
        data=data.model_dump(mode="json", exclude_none=True),
    )


def serialize_dependency_record(
    entity_type: str,
    row: Any,
    *,
    archive_as_of: datetime,
) -> ArchiveRecord:
    archive_as_of = utc_datetime(archive_as_of)
    if entity_type in {
        "canonical_event",
        "detection_signal",
        "ingestion_job",
        "incident",
        "audit_event",
    }:
        return serialize_root_record(
            entity_type,
            row,
            role="dependency",
            archive_as_of=archive_as_of,
        )

    data: ArchiveDataModel
    if entity_type == "triage_run":
        entity_id = str(row.triage_run_id or f"triage-row-{row.id}")
        recorded_at = _timestamp(row.started_at, archive_as_of)
        data = TriageRunArchiveData(
            source_database_id=int(row.id),
            job_id=safe_text(row.job_id),
            incident_id=safe_text(row.incident_id),
            started_at=(
                _timestamp(row.started_at, archive_as_of)
                if row.started_at is not None
                else None
            ),
            completed_at=(
                _timestamp(row.completed_at, archive_as_of)
                if row.completed_at is not None
                else None
            ),
            status=safe_text(row.status, max_length=32),
            provider=safe_text(row.provider, max_length=64),
            model=safe_text(row.model, max_length=128),
            prompt_version=safe_text(row.prompt_version, max_length=64),
            schema_version=safe_text(row.schema_version, max_length=64),
            verdict=safe_text(row.verdict, max_length=64),
            severity=safe_text(row.severity, max_length=32),
            confidence_score=_float(row.confidence_score),
            incident_type=safe_text(row.incident_type, max_length=128),
            cache_hit=bool(row.cache_hit),
            iteration_count=_integer(row.iteration_count),
            search_count=_integer(row.search_count),
            tool_count=_integer(row.tool_count),
            retry_count=_integer(row.retry_count),
            latency_ms=_integer(row.latency_ms),
            estimated_cost=float(row.estimated_cost or 0),
        )
    elif entity_type == "evidence_item":
        entity_id = str(row.evidence_id or f"evidence-row-{row.id}")
        recorded_at = archive_as_of
        data = EvidenceItemArchiveData(
            job_id=safe_text(row.job_id),
            incident_id=safe_text(row.incident_id),
            triage_run_id=row.triage_run_id,
            event_id=safe_text(row.event_id),
            reason=safe_text(row.reason),
            source=safe_text(row.source, max_length=128),
            validation_status=safe_text(row.validation_status, max_length=64),
            rejection_reason=safe_text(row.rejection_reason),
        )
    elif entity_type == "report":
        entity_id = str(row.report_id or f"report-row-{row.id}")
        recorded_at = _timestamp(row.generated_at, archive_as_of)
        data = ReportArchiveData(
            job_id=safe_text(row.job_id),
            incident_id=safe_text(row.incident_id),
            triage_run_id=row.triage_run_id,
            generated_at=(
                _timestamp(row.generated_at, archive_as_of)
                if row.generated_at is not None
                else None
            ),
            format=safe_text(row.format, max_length=32),
            content_sha256=(
                str(row.content_sha256).lower()
                if row.content_sha256 and len(str(row.content_sha256)) == 64
                else None
            ),
        )
    elif entity_type == "incident_event_association":
        incident_id = str(row.incident_id)
        event_id = str(row.event_id)
        entity_id = f"{incident_id}:{event_id}"
        recorded_at = archive_as_of
        data = IncidentEventAssociationArchiveData(
            incident_id=incident_id,
            event_id=event_id,
            is_context=bool(row.is_context),
        )
    elif entity_type == "incident_signal_association":
        incident_id = str(row.incident_id)
        signal_id = str(row.signal_id)
        entity_id = f"{incident_id}:{signal_id}"
        recorded_at = archive_as_of
        data = IncidentSignalAssociationArchiveData(
            incident_id=incident_id,
            signal_id=signal_id,
        )
    elif entity_type == "job_event_association":
        job_id = str(row.job_id)
        event_id = str(row.event_id)
        entity_id = f"{job_id}:{event_id}"
        recorded_at = archive_as_of
        data = JobEventAssociationArchiveData(job_id=job_id, event_id=event_id)
    elif entity_type == "job_signal_association":
        job_id = str(row.job_id)
        signal_id = str(row.signal_id)
        entity_id = f"{job_id}:{signal_id}"
        recorded_at = archive_as_of
        data = JobSignalAssociationArchiveData(job_id=job_id, signal_id=signal_id)
    elif entity_type == "job_incident_association":
        job_id = str(row.job_id)
        incident_id = str(row.incident_id)
        entity_id = f"{job_id}:{incident_id}"
        recorded_at = archive_as_of
        data = JobIncidentAssociationArchiveData(
            job_id=job_id,
            incident_id=incident_id,
        )
    else:
        raise ValueError("archive_dependency_entity_type_unsupported")

    return ArchiveRecord(
        entity_type=cast(ArchiveEntityType, entity_type),
        entity_id=entity_id,
        archive_role="dependency",
        recorded_at=recorded_at,
        data=data.model_dump(mode="json", exclude_none=True),
    )
