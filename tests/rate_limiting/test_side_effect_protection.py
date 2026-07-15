import datetime
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

import server
from agent.api.deps import get_dispatcher, get_staging_store
from agent.application.authentication import (
    AuthenticatedPrincipal,
    local_development_principal,
)
from agent.persistence.orm_models import AuditEvent, Incident, IngestionJob
from agent.security.abuse_protection import (
    RateLimitCategory,
    RateLimitExceededError,
)
from agent.security.authorization import Role
from tests.rate_limiting.conftest import bearer, make_rate_settings


class RecordingStagingStore:
    def __init__(self):
        self.stage_count = 0
        self.remove_count = 0
        self.staged: set[str] = set()

    def stage_file(self, stream, job_id, original_filename):
        self.stage_count += 1
        stream.read()
        self.staged.add(job_id)
        return f"memory://{job_id}", "a" * 64

    def get_file_path(self, job_id):
        return f"memory://{job_id}"

    def remove_file(self, job_id):
        self.remove_count += 1
        self.staged.discard(job_id)

    def move_file(self, src_job_id, dest_job_id):
        self.staged.discard(src_job_id)
        self.staged.add(dest_job_id)


class RecordingDispatcher:
    def __init__(self):
        self.jobs: list[str] = []

    def enqueue(self, job_id):
        self.jobs.append(job_id)


def _consume_local(application, category: RateLimitCategory) -> None:
    application.state.rate_limit_manager.enforce_principal(
        category,
        principal=local_development_principal(),
        request_id="preconsume",
        route="TEST preconsume",
    )


def test_excessive_submission_creates_no_job_file_or_queue_side_effect(
    app_factory,
    session_factory,
):
    settings = make_rate_settings(rate_limit_job_submissions=1)
    application = app_factory(settings)
    staging = RecordingStagingStore()
    dispatcher = RecordingDispatcher()
    application.dependency_overrides[get_staging_store] = lambda: staging
    application.dependency_overrides[get_dispatcher] = lambda: dispatcher
    upload = {"file": ("events.jsonl", BytesIO(b"{}\n"), "application/json")}

    with TestClient(application) as client:
        accepted = client.post("/api/v1/analysis-jobs/file", files=upload)
        denied = client.post(
            "/api/v1/analysis-jobs/file",
            files={"file": ("second.jsonl", b"{}\n", "application/json")},
        )

    session = session_factory()
    try:
        jobs = session.query(IngestionJob).all()
    finally:
        session.close()
    assert accepted.status_code == 202
    assert denied.status_code == 429
    assert len(jobs) == 1
    assert staging.stage_count == 1
    assert len(staging.staged) == 1
    assert len(dispatcher.jobs) == 1


def test_legacy_submission_routes_cannot_bypass_limit(app_factory, monkeypatch):
    settings = make_rate_settings(rate_limit_job_submissions=1)
    application = app_factory(settings)
    _consume_local(application, RateLimitCategory.JOB_SUBMISSION)

    async def forbidden_save(*args, **kwargs):
        raise AssertionError("legacy upload reached business logic")

    def forbidden_analysis(*args, **kwargs):
        raise AssertionError("legacy analysis reached business logic")

    monkeypatch.setattr(server, "secure_save_upload", forbidden_save)
    monkeypatch.setattr(server.agent_app, "invoke", forbidden_analysis)
    upload = {"file": ("events.jsonl", b"{}\n", "application/json")}
    with TestClient(application) as client:
        responses = [
            client.post("/ingest/file", files=upload),
            client.post("/detect/file", files=upload),
            client.post("/analyze/file", files=upload),
            client.post(
                "/analyze",
                json={"incident_id": "inc-test", "raw_logs": []},
            ),
        ]
    assert all(response.status_code == 429 for response in responses)


def test_viewer_denied_by_rbac_cannot_create_job(
    app_factory,
    create_credential,
    session_factory,
):
    credential = create_credential(role=Role.VIEWER)
    application = app_factory(make_rate_settings(auth_mode="api_key"))
    staging = RecordingStagingStore()
    dispatcher = RecordingDispatcher()
    application.dependency_overrides[get_staging_store] = lambda: staging
    application.dependency_overrides[get_dispatcher] = lambda: dispatcher
    with TestClient(application) as client:
        response = client.post(
            "/api/v1/analysis-jobs/file",
            headers=bearer(credential.api_key),
            files={"file": ("events.jsonl", b"{}\n", "application/json")},
        )
    session = session_factory()
    try:
        job_count = session.query(IngestionJob).count()
    finally:
        session.close()
    assert response.status_code == 403
    assert job_count == staging.stage_count == len(dispatcher.jobs) == 0


def test_service_analyst_and_admin_use_separate_submission_buckets(app_factory):
    application = app_factory(make_rate_settings(rate_limit_job_submissions=1))
    manager = application.state.rate_limit_manager
    for role in (Role.SERVICE, Role.ANALYST, Role.ADMIN):
        principal = AuthenticatedPrincipal(
            subject_type="api_client",
            subject_id=f"credential-{role.value}",
            display_name=role.value,
            authentication_method="api_key",
            roles=(role.value,),
            credential_id=f"credential-{role.value}",
        )
        decision = manager.enforce_principal(
            RateLimitCategory.JOB_SUBMISSION,
            principal=principal,
            request_id=role.value,
            route="POST /api/v1/analysis-jobs/file",
        )
        assert decision is not None and decision.allowed


def _insert_job(session_factory) -> None:
    session = session_factory()
    try:
        session.add(IngestionJob(
            id="job-limited",
            idempotency_key="job-limited-key",
            source_name="test",
            original_filename="events.jsonl",
            file_sha256="b" * 64,
            pipeline_version="1.0.0",
            analysis_mode="analyze",
            status="queued",
            attempt_count=0,
        ))
        session.commit()
    finally:
        session.close()


def test_limited_cancellation_changes_no_state_attempt_or_audit(
    app_factory,
    session_factory,
):
    _insert_job(session_factory)
    application = app_factory(make_rate_settings(rate_limit_mutations=1))
    staging = RecordingStagingStore()
    application.dependency_overrides[get_staging_store] = lambda: staging
    _consume_local(application, RateLimitCategory.MUTATION)
    with TestClient(application) as client:
        response = client.post("/api/v1/analysis-jobs/job-limited/cancel")
    session = session_factory()
    try:
        job = session.get(IngestionJob, "job-limited")
        audit_count = session.query(AuditEvent).count()
        assert job is not None
        assert job.status == "queued"
        assert job.attempt_count == 0
    finally:
        session.close()
    assert response.status_code == 429
    assert audit_count == 0
    assert staging.remove_count == 0


def _insert_incident(session_factory) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    session = session_factory()
    try:
        session.add(Incident(
            incident_id="incident-limited",
            title="Limited incident",
            incident_type="other",
            incident_family="other",
            status="new",
            severity="low",
            confidence=0.5,
            version=1,
            first_seen=now,
            last_seen=now,
            primary_entity="unknown",
            target_entities=[],
            mitre_techniques=[],
            metrics={},
        ))
        session.commit()
    finally:
        session.close()


def test_limited_incident_update_changes_no_version_or_audit(
    app_factory,
    session_factory,
):
    _insert_incident(session_factory)
    application = app_factory(make_rate_settings(rate_limit_mutations=1))
    _consume_local(application, RateLimitCategory.MUTATION)
    with TestClient(application) as client:
        response = client.patch(
            "/api/v1/incidents/incident-limited/status",
            json={"status": "triaged", "expected_version": 1},
        )
    session = session_factory()
    try:
        incident = session.get(Incident, "incident-limited")
        audit_count = session.query(AuditEvent).count()
        assert incident is not None
        assert incident.status == "new"
        assert incident.version == 1
    finally:
        session.close()
    assert response.status_code == 429
    assert audit_count == 0


def test_read_and_mutation_buckets_are_independent(app_factory):
    application = app_factory(make_rate_settings(
        rate_limit_reads=1,
        rate_limit_mutations=1,
    ))
    manager = application.state.rate_limit_manager
    principal = local_development_principal()
    manager.enforce_principal(
        RateLimitCategory.READ,
        principal=principal,
        request_id="read-1",
        route="GET /test",
    )
    with pytest.raises(RateLimitExceededError):
        manager.enforce_principal(
            RateLimitCategory.READ,
            principal=principal,
            request_id="read-2",
            route="GET /test",
        )
    mutation = manager.enforce_principal(
        RateLimitCategory.MUTATION,
        principal=principal,
        request_id="mutation-1",
        route="PATCH /test",
    )
    assert mutation is not None and mutation.allowed
