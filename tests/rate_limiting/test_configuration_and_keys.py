import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agent.config import Settings
from agent.security.rate_limit_keys import RateLimitKeyBuilder
from server import create_app
from tests.rate_limiting.conftest import TEST_RATE_LIMIT_SECRET


def production_values(**overrides) -> dict:
    values = {
        "app_env": "production",
        "auth_mode": "api_key",
        "https_required": True,
        "trusted_hosts": ["api.example.test"],
        "llm_enabled": False,
        "rate_limiting_enabled": True,
        "rate_limit_backend": "redis",
        "rate_limit_key_secret": TEST_RATE_LIMIT_SECRET,
    }
    values.update(overrides)
    return values


def error_text(caught: pytest.ExceptionInfo[ValidationError]) -> str:
    return str(caught.value)


def test_production_with_rate_limiting_disabled_fails_startup():
    with pytest.raises(ValidationError) as caught:
        Settings(**production_values(rate_limiting_enabled=False))
    assert "production_rate_limiting_required" in error_text(caught)


def test_production_with_memory_backend_fails_startup():
    with pytest.raises(ValidationError) as caught:
        Settings(**production_values(rate_limit_backend="memory"))
    assert "production_redis_rate_limit_required" in error_text(caught)


def test_production_without_rate_limit_key_secret_fails_startup():
    with pytest.raises(ValidationError) as caught:
        Settings(**production_values(rate_limit_key_secret=None))
    assert "production_rate_limit_key_secret_required" in error_text(caught)


def test_development_with_memory_backend_starts():
    settings = Settings(
        app_env="development",
        auth_mode="disabled",
        llm_enabled=False,
        rate_limit_backend="memory",
    )
    application = create_app(settings)
    with TestClient(application) as client:
        response = client.get("/health/live")
    assert response.status_code == 200


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rate_limit_general_requests", 0),
        ("rate_limit_general_window_seconds", 0),
        ("rate_limit_auth_failures", 0),
        ("rate_limit_auth_failure_window_seconds", 0),
        ("rate_limit_job_submissions", 0),
        ("rate_limit_job_submission_window_seconds", 0),
        ("rate_limit_mutations", 0),
        ("rate_limit_mutation_window_seconds", 0),
        ("rate_limit_reads", 0),
        ("rate_limit_read_window_seconds", 0),
    ],
)
def test_limits_and_windows_reject_invalid_values(field, value):
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def key_builder() -> RateLimitKeyBuilder:
    return RateLimitKeyBuilder(
        secret=TEST_RATE_LIMIT_SECRET.encode(),
        prefix="soc-rate-limit-test",
    )


def test_redis_key_does_not_contain_raw_api_key():
    raw_key = "soc_deadbeefdead_" + "A" * 43
    key = key_builder().for_principal(
        subject_type="api_client",
        subject_id=raw_key,
        authentication_method="api_key",
        category="read",
    )
    assert raw_key not in key


def test_redis_key_does_not_contain_jwt():
    jwt_value = "header.secret-claims.signature"
    key = key_builder().for_principal(
        subject_type="human_user",
        subject_id=jwt_value,
        authentication_method="oidc_jwt",
        category="read",
    )
    assert jwt_value not in key


def test_redis_key_does_not_contain_raw_ip_address():
    raw_address = "203.0.113.27"
    key = key_builder().for_anonymous(
        client_address=f"ipv4:{raw_address}",
        category="authentication_failure",
    )
    assert raw_address not in key


def test_identical_safe_identity_and_category_generate_deterministic_key():
    first = key_builder().for_principal(
        subject_type="human_user",
        subject_id="verified-subject",
        authentication_method="oidc_jwt",
        category="job_submission",
    )
    second = key_builder().for_principal(
        subject_type="human_user",
        subject_id="verified-subject",
        authentication_method="oidc_jwt",
        category="job_submission",
    )
    assert first == second


def test_different_categories_generate_different_keys():
    builder = key_builder()
    read_key = builder.for_anonymous(
        client_address="ipv6:2001:db8::1",
        category="read",
    )
    mutation_key = builder.for_anonymous(
        client_address="ipv6:2001:db8::1",
        category="mutation",
    )
    assert read_key != mutation_key
