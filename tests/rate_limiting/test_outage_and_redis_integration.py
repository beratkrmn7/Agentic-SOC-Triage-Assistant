import logging
import os
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from agent.api.security import (
    ANONYMOUS_CLIENT_ADDRESS,
    trusted_client_address,
)
from agent.security.abuse_protection import RateLimitCategory
from agent.security.rate_limiting import (
    RateLimiterUnavailableError,
    RedisRateLimiter,
)
from tests.rate_limiting.conftest import make_rate_settings


class UnavailableLimiter:
    def consume(self, key, *, limit, window_seconds, cost=1):
        raise RateLimiterUnavailableError()

    def check_health(self):
        return False


class SecretFailingRedis:
    ERROR_TEXT = "redis://secret-user:secret-pass@redis.private:6379/12"

    def eval(self, *args):
        raise RuntimeError(self.ERROR_TEXT)

    def ping(self):
        raise RuntimeError(self.ERROR_TEXT)


def test_redis_backend_outage_returns_safe_503_with_security_and_request_id(
    app_factory,
):
    settings = make_rate_settings(rate_limit_backend="redis")
    application = app_factory(settings, limiter=UnavailableLimiter())
    with TestClient(application) as client:
        response = client.get(
            "/docs",
            headers={"X-Request-ID": "backend-down-1"},
        )
    assert response.status_code == 503
    assert response.json() == {
        "code": "rate_limit_unavailable",
        "message": "The request cannot be processed at this time.",
    }
    assert response.headers["X-Request-ID"] == "backend-down-1"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_redis_error_text_and_url_are_not_exposed_in_response_or_logs(
    app_factory,
    caplog,
):
    settings = make_rate_settings(
        rate_limit_backend="redis",
        rate_limit_redis_url=SecretFailingRedis.ERROR_TEXT,
    )
    limiter = RedisRateLimiter(
        settings.rate_limit_redis_url,
        client=SecretFailingRedis(),
    )
    application = app_factory(settings, limiter=limiter)
    secret_authorization = "Bearer soc_deadbeefdead_" + "A" * 43
    with caplog.at_level(logging.ERROR):
        with TestClient(application) as client:
            response = client.get(
                "/api/v1/incidents/",
                headers={
                    "Authorization": secret_authorization,
                    "X-Forwarded-For": "203.0.113.99",
                },
            )
    exposed = response.text + str(dict(response.headers)) + caplog.text
    for secret in (
        SecretFailingRedis.ERROR_TEXT,
        "secret-pass",
        secret_authorization,
        "203.0.113.99",
        "C:\\private\\events.jsonl",
        "/srv/private/events.jsonl",
    ):
        assert secret not in exposed


def test_readiness_reports_rate_limiter_down_without_backend_details(
    app_factory,
):
    settings = make_rate_settings(rate_limit_backend="redis")
    application = app_factory(settings, limiter=UnavailableLimiter())
    with TestClient(application) as client:
        response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["components"]["rate_limiter"] == "down"
    serialized = response.text.lower()
    assert "redis://" not in serialized
    assert "localhost" not in serialized
    assert "6379" not in serialized


def test_liveness_remains_200_during_redis_outage(app_factory):
    settings = make_rate_settings(rate_limit_backend="redis")
    application = app_factory(settings, limiter=UnavailableLimiter())
    with TestClient(application) as client:
        response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live"}


def test_untrusted_forwarded_addresses_are_ignored():
    settings = make_rate_settings(
        forwarded_headers_enabled=True,
        trusted_proxy_ips=["192.0.2.10"],
    )
    scope = {
        "type": "http",
        "client": ("198.51.100.20", 50000),
        "headers": [(b"x-forwarded-for", b"203.0.113.99")],
    }
    assert trusted_client_address(scope, settings) == "ipv4:198.51.100.20"


def test_trusted_proxy_address_is_normalized_without_reflection():
    settings = make_rate_settings(
        forwarded_headers_enabled=True,
        trusted_proxy_ips=["192.0.2.10"],
    )
    scope = {
        "type": "http",
        "client": ("192.0.2.10", 50000),
        "headers": [(b"x-forwarded-for", b"2001:0db8:0:0::1")],
    }
    assert trusted_client_address(scope, settings) == "ipv6:2001:db8::1"


def test_invalid_direct_address_uses_non_identifying_anonymous_bucket():
    settings = make_rate_settings()
    scope = {
        "type": "http",
        "client": ("invalid-client-name", 50000),
        "headers": [],
    }
    assert trusted_client_address(scope, settings) == ANONYMOUS_CLIENT_ADDRESS


def test_invalid_forwarded_address_uses_non_identifying_anonymous_bucket():
    settings = make_rate_settings(
        forwarded_headers_enabled=True,
        trusted_proxy_ips=["192.0.2.10"],
    )
    scope = {
        "type": "http",
        "client": ("192.0.2.10", 50000),
        "headers": [(b"x-forwarded-for", b"not-an-address")],
    }
    assert trusted_client_address(scope, settings) == ANONYMOUS_CLIENT_ADDRESS


@pytest.mark.integration
def test_real_redis_is_shared_across_apps_and_ttl_cleans_up(app_factory):
    import redis

    redis_url = os.getenv(
        "RATE_LIMIT_REDIS_INTEGRATION_URL",
        "redis://localhost:6379/15",
    )
    inspection_client = redis.Redis.from_url(
        redis_url,
        socket_connect_timeout=1,
        socket_timeout=1,
    )
    try:
        inspection_client.ping()
    except Exception:
        pytest.skip("real Redis is not available")

    prefix = f"soc-rate-limit-integration-{uuid.uuid4().hex}"
    settings = make_rate_settings(
        rate_limit_backend="redis",
        rate_limit_redis_url=redis_url,
        rate_limit_prefix=prefix,
        rate_limit_general_requests=3,
        rate_limit_general_window_seconds=1,
    )
    first_app = app_factory(settings)
    second_app = app_factory(settings)
    opaque_key = first_app.state.rate_limit_manager.key_builder.for_anonymous(
        client_address=ANONYMOUS_CLIENT_ADDRESS,
        category=RateLimitCategory.DOCUMENTATION.value,
    )
    try:
        with TestClient(first_app) as first, TestClient(second_app) as second:
            responses = [
                first.get("/docs"),
                second.get("/docs"),
                first.get("/docs"),
                second.get("/docs"),
            ]
        assert [response.status_code for response in responses] == [
            200,
            200,
            200,
            429,
        ]
        assert 0 <= inspection_client.ttl(opaque_key) <= 1
        time.sleep(1.1)
        assert inspection_client.exists(opaque_key) == 0
    finally:
        inspection_client.delete(opaque_key)
        inspection_client.close()
