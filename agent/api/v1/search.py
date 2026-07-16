from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict
from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Annotated, Any, Generic, Literal, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from agent.api.deps import get_uow, require_permission
from agent.application.authentication import AuthenticatedPrincipal
from agent.application.search_service import (
    EventSearchCriteria,
    IncidentSearchCriteria,
    InvalidSearchCursorError,
    JobSearchCriteria,
    SearchPage,
    SearchService,
    SearchValidationError,
    SignalSearchCriteria,
)
from agent.config import Settings, get_settings
from agent.persistence.search_repositories import SqlAlchemySearchRepository
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.abuse_protection import RateLimitCategory
from agent.security.authorization import AuthorizationDeniedError, Permission, Role


router = APIRouter(prefix="/search", tags=["search"])
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class IncidentSearchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    incident_type: str
    incident_family: str
    severity: str
    confidence: float
    status: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    primary_entity: str
    signal_count: int
    event_count: int
    has_report: bool


class EventSearchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: datetime
    source_name: str
    parser_name: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    action: str | None
    safe_message_excerpt: str


class SignalSearchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    signal_id: str
    rule_id: str
    rule_name: str
    signal_type: str
    severity: str
    confidence: float
    first_seen: datetime | None
    last_seen: datetime | None
    suppressed: bool


class JobSearchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: str
    status: str
    source_name: str
    analysis_mode: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    attempt_count: int
    reused_count: int
    error_code: str | None


ResponseT = TypeVar("ResponseT", bound=BaseModel)


class SearchPageResponse(BaseModel, Generic[ResponseT]):
    items: list[ResponseT]
    next_cursor: str | None
    has_more: bool


def get_search_service(
    uow: UnitOfWork = Depends(get_uow, use_cache=False),
    settings: Settings = Depends(get_settings),
) -> Iterator[SearchService]:
    with uow:
        if uow.session is None:
            raise RuntimeError("search_session_unavailable")
        yield SearchService(SqlAlchemySearchRepository(uow.session), settings)


def _page_response(page: SearchPage[Any]) -> dict[str, object]:
    return {
        "items": [asdict(item) for item in page.items],
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
    }


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "timezone_required",
                "message": "Search timestamps must include a timezone.",
            },
        )
    return value.astimezone(timezone.utc)


def _normalized_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_ip", "message": "The IP address is invalid."},
        ) from None


def _run_search(call):
    try:
        return _page_response(call())
    except InvalidSearchCursorError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": exc.code, "message": "The search cursor is invalid."},
        ) from None
    except SearchValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": exc.code, "message": "The search request is invalid."},
        ) from None


@router.get(
    "/incidents",
    response_model=SearchPageResponse[IncidentSearchResponse],
)
def search_incidents(
    status: Annotated[list[str] | None, Query()] = None,
    severity: Annotated[list[str] | None, Query()] = None,
    incident_type: str | None = None,
    incident_family: str | None = None,
    min_confidence: Annotated[float | None, Query(ge=0, le=1)] = None,
    max_confidence: Annotated[float | None, Query(ge=0, le=1)] = None,
    primary_entity: str | None = None,
    first_seen_from: datetime | None = None,
    first_seen_to: datetime | None = None,
    last_seen_from: datetime | None = None,
    last_seen_to: datetime | None = None,
    created_at_from: datetime | None = None,
    created_at_to: datetime | None = None,
    mitre_technique: str | None = None,
    job_id: str | None = None,
    has_report: bool | None = None,
    has_validated_evidence: bool | None = None,
    title_prefix: Annotated[str | None, Query(max_length=120)] = None,
    sort: Literal[
        "created_at", "first_seen", "last_seen", "severity", "confidence"
    ] = "created_at",
    direction: Literal["asc", "desc"] = "desc",
    page_size: Annotated[int | None, Query(ge=1)] = None,
    cursor: str | None = None,
    service: SearchService = Depends(get_search_service),
    settings: Settings = Depends(get_settings),
    _principal: AuthenticatedPrincipal = Depends(
        require_permission(
            Permission.INCIDENT_READ,
            rate_limit_category=RateLimitCategory.READ,
        )
    ),
):
    criteria = IncidentSearchCriteria(
        statuses=tuple(status or ()),
        severities=tuple(severity or ()),
        incident_type=incident_type,
        incident_family=incident_family,
        min_confidence=min_confidence,
        max_confidence=max_confidence,
        primary_entity=primary_entity,
        first_seen_from=_utc(first_seen_from),
        first_seen_to=_utc(first_seen_to),
        last_seen_from=_utc(last_seen_from),
        last_seen_to=_utc(last_seen_to),
        created_at_from=_utc(created_at_from),
        created_at_to=_utc(created_at_to),
        mitre_technique=mitre_technique,
        job_id=job_id,
        has_report=has_report,
        has_validated_evidence=has_validated_evidence,
        title_prefix=title_prefix,
        sort=sort,
        direction=direction,
        page_size=page_size or settings.search_default_page_size,
        cursor=cursor,
    )
    return _run_search(lambda: service.search_incidents(criteria))


@router.get(
    "/events",
    response_model=SearchPageResponse[EventSearchResponse],
)
def search_events(
    event_id: str | None = None,
    source_name: str | None = None,
    parser_name: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    dst_port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    protocol: str | None = None,
    action: str | None = None,
    user: str | None = None,
    timestamp_from: datetime | None = None,
    timestamp_to: datetime | None = None,
    job_id: str | None = None,
    incident_id: str | None = None,
    is_context: bool | None = None,
    sort: Literal["timestamp"] = "timestamp",
    direction: Literal["asc", "desc"] = "desc",
    page_size: Annotated[int | None, Query(ge=1)] = None,
    cursor: str | None = None,
    service: SearchService = Depends(get_search_service),
    settings: Settings = Depends(get_settings),
    _principal: AuthenticatedPrincipal = Depends(
        require_permission(
            Permission.INCIDENT_READ,
            rate_limit_category=RateLimitCategory.READ,
        )
    ),
):
    criteria = EventSearchCriteria(
        event_id=event_id,
        source_name=source_name,
        parser_name=parser_name,
        src_ip=_normalized_ip(src_ip),
        dst_ip=_normalized_ip(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        action=action,
        user=user,
        timestamp_from=_utc(timestamp_from),
        timestamp_to=_utc(timestamp_to),
        job_id=job_id,
        incident_id=incident_id,
        is_context=is_context,
        sort=sort,
        direction=direction,
        page_size=page_size or settings.search_default_page_size,
        cursor=cursor,
    )
    return _run_search(lambda: service.search_events(criteria))


@router.get(
    "/signals",
    response_model=SearchPageResponse[SignalSearchResponse],
)
def search_signals(
    signal_id: str | None = None,
    rule_id: str | None = None,
    rule_name: str | None = None,
    signal_type: str | None = None,
    signal_family: str | None = None,
    severity: Annotated[list[str] | None, Query()] = None,
    min_confidence: Annotated[float | None, Query(ge=0, le=1)] = None,
    max_confidence: Annotated[float | None, Query(ge=0, le=1)] = None,
    suppressed: bool | None = None,
    first_seen_from: datetime | None = None,
    first_seen_to: datetime | None = None,
    last_seen_from: datetime | None = None,
    last_seen_to: datetime | None = None,
    job_id: str | None = None,
    incident_id: str | None = None,
    mitre_technique: str | None = None,
    sort: Literal[
        "created_at", "first_seen", "last_seen", "severity", "confidence"
    ] = "created_at",
    direction: Literal["asc", "desc"] = "desc",
    page_size: Annotated[int | None, Query(ge=1)] = None,
    cursor: str | None = None,
    service: SearchService = Depends(get_search_service),
    settings: Settings = Depends(get_settings),
    _principal: AuthenticatedPrincipal = Depends(
        require_permission(
            Permission.INCIDENT_READ,
            rate_limit_category=RateLimitCategory.READ,
        )
    ),
):
    criteria = SignalSearchCriteria(
        signal_id=signal_id,
        rule_id=rule_id,
        rule_name=rule_name,
        signal_type=signal_type,
        signal_family=signal_family,
        severities=tuple(severity or ()),
        min_confidence=min_confidence,
        max_confidence=max_confidence,
        suppressed=suppressed,
        first_seen_from=_utc(first_seen_from),
        first_seen_to=_utc(first_seen_to),
        last_seen_from=_utc(last_seen_from),
        last_seen_to=_utc(last_seen_to),
        job_id=job_id,
        incident_id=incident_id,
        mitre_technique=mitre_technique,
        sort=sort,
        direction=direction,
        page_size=page_size or settings.search_default_page_size,
        cursor=cursor,
    )
    return _run_search(lambda: service.search_signals(criteria))


@router.get(
    "/jobs",
    response_model=SearchPageResponse[JobSearchResponse],
)
def search_jobs(
    job_id: str | None = None,
    status: Annotated[list[str] | None, Query()] = None,
    analysis_mode: str | None = None,
    source_name: str | None = None,
    file_sha256: str | None = None,
    pipeline_version: str | None = None,
    reused: bool | None = None,
    min_reused_count: Annotated[int | None, Query(ge=0)] = None,
    created_at_from: datetime | None = None,
    created_at_to: datetime | None = None,
    queued_at_from: datetime | None = None,
    queued_at_to: datetime | None = None,
    completed_at_from: datetime | None = None,
    completed_at_to: datetime | None = None,
    error_code: str | None = None,
    cancelled: bool | None = None,
    min_attempt_count: Annotated[int | None, Query(ge=0)] = None,
    sort: Literal["created_at", "completed_at", "status"] = "created_at",
    direction: Literal["asc", "desc"] = "desc",
    page_size: Annotated[int | None, Query(ge=1)] = None,
    cursor: str | None = None,
    service: SearchService = Depends(get_search_service),
    settings: Settings = Depends(get_settings),
    principal: AuthenticatedPrincipal = Depends(
        require_permission(
            Permission.JOB_READ,
            rate_limit_category=RateLimitCategory.READ,
        )
    ),
):
    if file_sha256 is not None:
        if not ({Role.SERVICE.value, Role.ADMIN.value} & set(principal.roles)):
            raise AuthorizationDeniedError()
        if not SHA256_PATTERN.fullmatch(file_sha256):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "file_sha256_invalid",
                    "message": "The file digest is invalid.",
                },
            )
        file_sha256 = file_sha256.lower()
    criteria = JobSearchCriteria(
        job_id=job_id,
        statuses=tuple(status or ()),
        analysis_mode=analysis_mode,
        source_name=source_name,
        file_sha256=file_sha256,
        pipeline_version=pipeline_version,
        reused=reused,
        min_reused_count=min_reused_count,
        created_at_from=_utc(created_at_from),
        created_at_to=_utc(created_at_to),
        queued_at_from=_utc(queued_at_from),
        queued_at_to=_utc(queued_at_to),
        completed_at_from=_utc(completed_at_from),
        completed_at_to=_utc(completed_at_to),
        error_code=error_code,
        cancelled=cancelled,
        min_attempt_count=min_attempt_count,
        sort=sort,
        direction=direction,
        page_size=page_size or settings.search_default_page_size,
        cursor=cursor,
    )
    return _run_search(lambda: service.search_jobs(criteria))
