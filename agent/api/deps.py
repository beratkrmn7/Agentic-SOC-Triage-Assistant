from fastapi import Depends, Header

from agent.application.authentication import (
    AuthenticatedPrincipal,
    AuthenticationRequiredError,
    ApiKeyAuthenticationService,
    local_development_principal,
)
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.config import Settings, get_settings

# Global engine/session factory for FastAPI
settings = get_settings()
engine = create_engine_factory(settings)
session_factory = create_session_factory(engine)

def get_uow() -> UnitOfWork:
    return UnitOfWork(session_factory)

def get_staging_store():
    from agent.application.staging import LocalFileStagingStore
    return LocalFileStagingStore(staging_dir=settings.staging_dir)

def get_dispatcher():
    from agent.queue.dispatchers import DatabasePollingDispatcher, CeleryAnalysisJobDispatcher
    if settings.task_queue_backend == "celery":
        return CeleryAnalysisJobDispatcher()
    return DatabasePollingDispatcher()


def get_authenticated_principal(
    authorization: str | None = Header(default=None, alias="Authorization"),
    auth_settings: Settings = Depends(get_settings),
    uow: UnitOfWork = Depends(get_uow, use_cache=False),
) -> AuthenticatedPrincipal:
    if auth_settings.auth_mode == "disabled":
        return local_development_principal()

    if authorization is None:
        raise AuthenticationRequiredError()
    scheme, separator, api_key = authorization.partition(" ")
    if (
        scheme.lower() != "bearer"
        or separator != " "
        or not api_key
        or any(character.isspace() for character in api_key)
    ):
        raise AuthenticationRequiredError()
    return ApiKeyAuthenticationService(uow).authenticate(api_key)
