from collections.abc import Callable

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.api.deps import (
    get_optional_oidc_authentication_service,
    get_uow,
)
from agent.application.authentication import ApiKeyAuthenticationService
from agent.config import Settings, get_settings
from agent.persistence.database import Base
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.authorization import Role
from agent.security.rate_limiting import RateLimiter
from server import create_app


TEST_RATE_LIMIT_SECRET = "rate-limit-test-secret-value-0001"


def make_rate_settings(**overrides) -> Settings:
    values = {
        "app_env": "test",
        "auth_mode": "disabled",
        "llm_enabled": False,
        "trusted_hosts": ["localhost", "127.0.0.1", "testserver"],
        "rate_limit_key_secret": TEST_RATE_LIMIT_SECRET,
        "rate_limit_general_requests": 1000,
        "rate_limit_auth_failures": 10,
        "rate_limit_job_submissions": 100,
        "rate_limit_mutations": 100,
        "rate_limit_reads": 1000,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'rate-limiting.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


@pytest.fixture
def app_factory(session_factory) -> Callable:
    def factory(
        settings: Settings | None = None,
        *,
        limiter: RateLimiter | None = None,
        oidc_service=None,
    ):
        selected = settings or make_rate_settings()
        application = create_app(selected, rate_limiter=limiter)
        application.dependency_overrides[get_settings] = lambda: selected
        application.dependency_overrides[get_uow] = (
            lambda: UnitOfWork(session_factory)
        )
        if oidc_service is not None:
            application.dependency_overrides[
                get_optional_oidc_authentication_service
            ] = lambda: oidc_service
        return application

    return factory


@pytest.fixture
def create_credential(session_factory):
    def create(*, role: Role = Role.SERVICE, expires_at=None):
        return ApiKeyAuthenticationService(
            UnitOfWork(session_factory)
        ).generate_credential(
            name=f"Rate limit {role.value}",
            role=role,
            expires_at=expires_at,
        )

    return create


def bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}
