from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import uuid

from agent.application.retention import RetentionPlanner, RetentionPolicy
from agent.archive.exporter import ArchiveExporter
from agent.archive.io import (
    ArchiveExportError,
    ArchiveIntegrityError,
    ArchiveVerificationResult,
    ArchiveVerifier,
    ArchiveWriter,
)
from agent.archive.schemas import validate_archive_id, utc_datetime
from agent.archive.storage import (
    ArchiveStorageError,
    ArchiveStore,
    ArchiveWorkspace,
    new_archive_id,
)
from agent.config import Settings
from agent.persistence.orm_models import AuditEvent, RetentionArchiveRun
from agent.persistence.unit_of_work import UnitOfWork


class ArchiveOperationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ArchiveOperationResult:
    archive_id: str
    policy_version: str
    status: str
    candidate_record_count: int
    dependency_record_count: int
    total_record_count: int
    payload_count: int
    manifest_sha256: str
    verified: bool


class ArchiveService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        store: ArchiveStore,
        settings: Settings,
        *,
        clock: Callable[[], datetime] | None = None,
        archive_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._store = store
        self._settings = settings
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._archive_id_factory = archive_id_factory or new_archive_id
        self._writer = ArchiveWriter(store)
        self._verifier = ArchiveVerifier(store)

    def create(self) -> ArchiveOperationResult:
        archive_id = validate_archive_id(self._archive_id_factory())
        archive_as_of = utc_datetime(self._clock())
        policy = RetentionPolicy.from_settings(self._settings)
        workspace: ArchiveWorkspace | None = None
        run_created = False
        finalized = False
        try:
            self._create_run(archive_id, archive_as_of, policy.version)
            run_created = True
            workspace = self._store.begin(archive_id)
            with self._uow_factory() as uow:
                planner = RetentionPlanner(
                    uow.retention,
                    policy,
                    clock=lambda: archive_as_of,
                )
                plan = planner.plan()
                exporter = ArchiveExporter(
                    uow.archive_exports,
                    self._writer,
                    batch_size=self._settings.retention_archive_batch_size,
                    producer_version=self._settings.pipeline_version,
                    clock=self._clock,
                )
                write_result = exporter.export(
                    workspace,
                    plan,
                    created_at=archive_as_of,
                )
            verification = self._verifier.verify(
                archive_id,
                workspace=workspace,
            )
            if verification.manifest_sha256 != write_result.manifest_sha256:
                raise ArchiveIntegrityError("archive_manifest_checksum_mismatch")
            self._mark_completed(verification)
            self._store.finalize(workspace)
            finalized = True
            self._mark_verified(verification)
            return self._result(verification, "verified")
        except Exception as exc:
            if finalized:
                raise ArchiveOperationError(
                    "archive_metadata_finalize_pending"
                ) from None
            if workspace is not None:
                try:
                    self._store.abort(workspace)
                except ArchiveStorageError:
                    pass
            code = self._error_code(exc)
            if run_created:
                try:
                    self._mark_failed(archive_id, code)
                except Exception:
                    pass
            raise ArchiveOperationError(code) from None

    def verify(self, archive_id: str) -> ArchiveOperationResult:
        validate_archive_id(archive_id)
        try:
            with self._uow_factory() as uow:
                run = uow.archive_runs.get(archive_id)
                if run is None or str(run.storage_key) != archive_id:
                    raise ArchiveOperationError("archive_not_found")
                known_checksum = (
                    str(run.manifest_sha256) if run.manifest_sha256 else None
                )
            verification = self._verifier.verify(archive_id)
            if (
                known_checksum is not None
                and verification.manifest_sha256 != known_checksum
            ):
                raise ArchiveIntegrityError("archive_manifest_checksum_mismatch")
            self._mark_verified(verification)
            return self._result(verification, "verified")
        except ArchiveOperationError:
            raise
        except Exception as exc:
            raise ArchiveOperationError(self._error_code(exc)) from None

    def _create_run(
        self,
        archive_id: str,
        archive_as_of: datetime,
        policy_version: str,
    ) -> None:
        with self._uow_factory() as uow:
            uow.archive_runs.add(
                RetentionArchiveRun(
                    archive_id=archive_id,
                    policy_version=policy_version,
                    schema_version=self._settings.retention_archive_schema_version,
                    status="creating",
                    archive_as_of=archive_as_of,
                    created_at=archive_as_of,
                    storage_key=archive_id,
                    candidate_record_count=0,
                    dependency_record_count=0,
                    total_record_count=0,
                )
            )
            self._add_audit(
                uow,
                archive_id=archive_id,
                event_type="retention_archive_started",
                timestamp=archive_as_of,
                policy_version=policy_version,
                status="creating",
            )

    def _mark_completed(self, verification: ArchiveVerificationResult) -> None:
        manifest = verification.manifest
        with self._uow_factory() as uow:
            run = uow.archive_runs.get(verification.archive_id)
            if run is None or str(run.status) != "creating":
                raise ArchiveOperationError("archive_run_transition_invalid")
            run.status = "completed"
            run.completed_at = manifest.completed_at
            run.manifest_sha256 = verification.manifest_sha256
            run.candidate_record_count = manifest.candidate_record_count
            run.dependency_record_count = manifest.dependency_record_count
            run.total_record_count = manifest.total_record_count
            run.sanitized_error_code = None

    def _mark_verified(self, verification: ArchiveVerificationResult) -> None:
        manifest = verification.manifest
        verified_at = utc_datetime(self._clock())
        with self._uow_factory() as uow:
            run = uow.archive_runs.get(verification.archive_id)
            if run is None or str(run.status) not in {"completed", "verified"}:
                raise ArchiveOperationError("archive_run_transition_invalid")
            already_verified = str(run.status) == "verified"
            run.status = "verified"
            run.verified_at = verified_at
            run.manifest_sha256 = verification.manifest_sha256
            if not already_verified:
                self._add_audit(
                    uow,
                    archive_id=verification.archive_id,
                    event_type="retention_archive_completed",
                    timestamp=manifest.completed_at,
                    policy_version=manifest.policy_version,
                    status="completed",
                    candidate_count=manifest.candidate_record_count,
                    dependency_count=manifest.dependency_record_count,
                    total_count=manifest.total_record_count,
                )
                self._add_audit(
                    uow,
                    archive_id=verification.archive_id,
                    event_type="retention_archive_verified",
                    timestamp=verified_at,
                    policy_version=manifest.policy_version,
                    status="verified",
                    candidate_count=manifest.candidate_record_count,
                    dependency_count=manifest.dependency_record_count,
                    total_count=manifest.total_record_count,
                )

    def _mark_failed(self, archive_id: str, error_code: str) -> None:
        failed_at = utc_datetime(self._clock())
        with self._uow_factory() as uow:
            run = uow.archive_runs.get(archive_id)
            if run is None:
                return
            run.status = "failed"
            run.sanitized_error_code = error_code
            self._add_audit(
                uow,
                archive_id=archive_id,
                event_type="retention_archive_failed",
                timestamp=failed_at,
                policy_version=str(run.policy_version),
                status="failed",
                candidate_count=int(run.candidate_record_count or 0),
                dependency_count=int(run.dependency_record_count or 0),
                total_count=int(run.total_record_count or 0),
                error_code=error_code,
            )

    @staticmethod
    def _add_audit(
        uow: UnitOfWork,
        *,
        archive_id: str,
        event_type: str,
        timestamp: datetime,
        policy_version: str,
        status: str,
        candidate_count: int = 0,
        dependency_count: int = 0,
        total_count: int = 0,
        error_code: str | None = None,
    ) -> None:
        assert uow.session is not None
        details: dict[str, Any] = {
            "archive_id": archive_id,
            "policy_version": policy_version,
            "schema_version": "retention-archive/v1",
            "status": status,
            "candidate_count": candidate_count,
            "dependency_count": dependency_count,
            "total_count": total_count,
            "timestamp": utc_datetime(timestamp).isoformat(),
        }
        if error_code is not None:
            details["error_code"] = error_code
        uow.session.add(
            AuditEvent(
                audit_event_id=f"ae_{uuid.uuid4().hex}",
                timestamp=timestamp,
                event_type=event_type,
                entity_type="retention_archive",
                entity_id=archive_id,
                action=event_type,
                actor_type="system",
                actor_id="retention_archive_service",
                actor="system",
                details=details,
            )
        )

    @staticmethod
    def _error_code(exc: Exception) -> str:
        if isinstance(exc, ArchiveOperationError):
            return exc.code
        if isinstance(exc, ArchiveIntegrityError):
            return "archive_integrity_failed"
        if isinstance(exc, ArchiveStorageError):
            return "archive_storage_failed"
        if isinstance(exc, ArchiveExportError):
            return "archive_export_failed"
        if isinstance(exc, (ValueError, TypeError)):
            return "archive_validation_failed"
        return "archive_operation_failed"

    @staticmethod
    def _result(
        verification: ArchiveVerificationResult,
        status: str,
    ) -> ArchiveOperationResult:
        manifest = verification.manifest
        return ArchiveOperationResult(
            archive_id=verification.archive_id,
            policy_version=manifest.policy_version,
            status=status,
            candidate_record_count=manifest.candidate_record_count,
            dependency_record_count=manifest.dependency_record_count,
            total_record_count=manifest.total_record_count,
            payload_count=len(manifest.payloads),
            manifest_sha256=verification.manifest_sha256,
            verified=status == "verified",
        )
