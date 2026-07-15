import datetime

from fastapi.testclient import TestClient

from agent.application.authentication import (
    AUTHENTICATION_ERROR,
    AuthenticatedPrincipal,
    AuthenticationRequiredError,
    ApiKeyAuthenticationService,
)
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.authorization import Role
from tests.rate_limiting.conftest import bearer, make_rate_settings


class FakeOidcService:
    def authenticate(self, token: str) -> AuthenticatedPrincipal:
        if token != "good.jwt.token":
            raise AuthenticationRequiredError()
        return AuthenticatedPrincipal(
            subject_type="human_user",
            subject_id="verified-oidc-subject",
            display_name="Verified analyst",
            authentication_method="oidc_jwt",
            roles=(Role.ANALYST.value,),
            credential_id=None,
        )

    def check_provider(self) -> None:
        return None


def oidc_settings(**overrides):
    values = {
        "auth_mode": "oidc",
        "oidc_issuer": "https://identity.example.test",
        "oidc_audience": "soc-api",
        "rate_limit_auth_failures": 2,
    }
    values.update(overrides)
    return make_rate_settings(**values)


def test_request_over_limit_returns_public_429_and_bounded_headers(app_factory):
    settings = make_rate_settings(rate_limit_general_requests=2)
    application = app_factory(settings)
    with TestClient(application) as client:
        first = client.get("/docs")
        second = client.get("/docs")
        denied = client.get("/docs", headers={"X-Request-ID": "rate-test-1"})

    assert first.status_code == second.status_code == 200
    assert denied.status_code == 429
    assert denied.json() == {
        "code": "rate_limited",
        "message": "Too many requests. Please retry later.",
    }
    assert denied.headers["X-Request-ID"] == "rate-test-1"
    assert denied.headers["X-Content-Type-Options"] == "nosniff"
    assert 1 <= int(denied.headers["Retry-After"]) <= 60
    assert denied.headers["X-RateLimit-Limit"] == "2"
    assert denied.headers["X-RateLimit-Remaining"] == "0"
    assert int(denied.headers["X-RateLimit-Reset"]) > 0


def test_successful_application_response_has_one_restrictive_header_set(
    app_factory,
    create_credential,
):
    credential = create_credential(role=Role.ANALYST)
    settings = make_rate_settings(auth_mode="api_key", rate_limit_reads=3)
    application = app_factory(settings)
    with TestClient(application) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers=bearer(credential.api_key),
        )
    assert response.status_code == 200
    assert response.headers.get_list("X-RateLimit-Limit") == ["3"]
    assert response.headers["X-RateLimit-Remaining"] == "2"


def test_repeated_invalid_api_key_attempts_become_429(app_factory):
    settings = make_rate_settings(
        auth_mode="api_key",
        rate_limit_auth_failures=2,
    )
    application = app_factory(settings)
    headers = bearer("soc_deadbeefdead_" + "A" * 43)
    with TestClient(application) as client:
        responses = [
            client.get("/api/v1/incidents/", headers=headers)
            for _ in range(3)
        ]
    assert [response.status_code for response in responses] == [401, 401, 429]
    assert all(response.json() == AUTHENTICATION_ERROR for response in responses[:2])
    assert responses[2].json()["code"] == "rate_limited"


def test_repeated_invalid_jwt_attempts_become_429(app_factory):
    application = app_factory(
        oidc_settings(),
        oidc_service=FakeOidcService(),
    )
    with TestClient(application) as client:
        responses = [
            client.get(
                "/api/v1/incidents/",
                headers=bearer("bad.jwt.token"),
            )
            for _ in range(3)
        ]
    assert [response.status_code for response in responses] == [401, 401, 429]


def test_missing_credentials_are_throttled_safely_and_remain_generic(
    app_factory,
):
    settings = make_rate_settings(
        auth_mode="api_key",
        rate_limit_auth_failures=2,
    )
    application = app_factory(settings)
    with TestClient(application) as client:
        first = client.get("/api/v1/incidents/")
        second = client.get("/api/v1/incidents/")
        denied = client.get("/api/v1/incidents/")
    assert first.status_code == second.status_code == 401
    assert first.json() == second.json() == AUTHENTICATION_ERROR
    assert denied.status_code == 429


def test_successful_authentication_remains_valid_after_failure_threshold(
    app_factory,
    create_credential,
):
    credential = create_credential(role=Role.ANALYST)
    settings = make_rate_settings(
        auth_mode="api_key",
        rate_limit_auth_failures=1,
    )
    application = app_factory(settings)
    invalid = bearer("soc_deadbeefdead_" + "B" * 43)
    with TestClient(application) as client:
        assert client.get("/api/v1/incidents/", headers=invalid).status_code == 401
        assert client.get("/api/v1/incidents/", headers=invalid).status_code == 429
        valid = client.get(
            "/api/v1/incidents/",
            headers=bearer(credential.api_key),
        )
    assert valid.status_code == 200


def test_revoked_credential_is_401_before_threshold_and_429_after(
    app_factory,
    create_credential,
    session_factory,
):
    credential = create_credential(role=Role.ANALYST)
    ApiKeyAuthenticationService(UnitOfWork(session_factory)).revoke_credential(
        credential.credential.credential_id
    )
    application = app_factory(make_rate_settings(
        auth_mode="api_key",
        rate_limit_auth_failures=2,
    ))
    with TestClient(application) as client:
        responses = [
            client.get(
                "/api/v1/incidents/",
                headers=bearer(credential.api_key),
            )
            for _ in range(3)
        ]
    assert [response.status_code for response in responses] == [401, 401, 429]
    assert responses[0].json() == responses[1].json() == AUTHENTICATION_ERROR


def test_expired_credential_is_401_before_threshold_and_429_after(
    app_factory,
    create_credential,
):
    credential = create_credential(
        role=Role.ANALYST,
        expires_at=datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(minutes=1),
    )
    application = app_factory(make_rate_settings(
        auth_mode="api_key",
        rate_limit_auth_failures=2,
    ))
    with TestClient(application) as client:
        responses = [
            client.get(
                "/api/v1/incidents/",
                headers=bearer(credential.api_key),
            )
            for _ in range(3)
        ]
    assert [response.status_code for response in responses] == [401, 401, 429]
    assert responses[0].json() == responses[1].json() == AUTHENTICATION_ERROR


def test_hybrid_api_key_and_jwt_have_independent_principal_buckets(
    app_factory,
    create_credential,
):
    credential = create_credential(role=Role.ANALYST)
    settings = make_rate_settings(
        auth_mode="hybrid",
        oidc_issuer="https://identity.example.test",
        oidc_audience="soc-api",
        rate_limit_reads=1,
    )
    application = app_factory(settings, oidc_service=FakeOidcService())
    with TestClient(application) as client:
        api_first = client.get(
            "/api/v1/incidents/",
            headers=bearer(credential.api_key),
        )
        api_denied = client.get(
            "/api/v1/incidents/",
            headers=bearer(credential.api_key),
        )
        jwt_first = client.get(
            "/api/v1/incidents/",
            headers=bearer("good.jwt.token"),
        )
        jwt_denied = client.get(
            "/api/v1/incidents/",
            headers=bearer("good.jwt.token"),
        )
    assert [
        api_first.status_code,
        api_denied.status_code,
        jwt_first.status_code,
        jwt_denied.status_code,
    ] == [200, 429, 200, 429]


def test_health_endpoints_remain_public_without_rate_headers(app_factory):
    settings = make_rate_settings(
        auth_mode="api_key",
        rate_limit_general_requests=1,
    )
    application = app_factory(settings)
    with TestClient(application) as client:
        responses = [client.get("/health/live") for _ in range(4)]
    assert all(response.status_code == 200 for response in responses)
    assert all("X-RateLimit-Limit" not in response.headers for response in responses)
