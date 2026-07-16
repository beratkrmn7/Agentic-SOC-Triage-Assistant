from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
from typing import Generic, Literal, Protocol, TypeVar

from agent.config import Settings


SortDirection = Literal["asc", "desc"]
CursorValue = str | float | int | datetime | None
MAX_FILTER_VALUES = 20
MAX_CURSOR_LENGTH = 2048

INCIDENT_STATUSES = frozenset(
    {
        "new",
        "triaged",
        "needs_review",
        "assigned",
        "investigating",
        "confirmed",
        "false_positive",
        "resolved",
        "closed",
        "reopened",
    }
)
SEVERITIES = frozenset(
    {"none", "informational", "low", "medium", "high", "critical"}
)
JOB_STATUSES = frozenset(
    {
        "pending",
        "queued",
        "processing",
        "completed",
        "failed",
        "cancel_requested",
        "cancelled",
    }
)


class SearchValidationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class InvalidSearchCursorError(SearchValidationError):
    def __init__(self) -> None:
        super().__init__("invalid_search_cursor")


@dataclass(frozen=True)
class SearchCursor:
    resource: str
    sort: str
    direction: SortDirection
    value: CursorValue
    item_id: str


@dataclass(frozen=True)
class IncidentSearchCriteria:
    statuses: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    incident_type: str | None = None
    incident_family: str | None = None
    min_confidence: float | None = None
    max_confidence: float | None = None
    primary_entity: str | None = None
    first_seen_from: datetime | None = None
    first_seen_to: datetime | None = None
    last_seen_from: datetime | None = None
    last_seen_to: datetime | None = None
    created_at_from: datetime | None = None
    created_at_to: datetime | None = None
    mitre_technique: str | None = None
    job_id: str | None = None
    has_report: bool | None = None
    has_validated_evidence: bool | None = None
    title_prefix: str | None = None
    sort: Literal[
        "created_at", "first_seen", "last_seen", "severity", "confidence"
    ] = "created_at"
    direction: SortDirection = "desc"
    page_size: int = 50
    cursor: str | None = None


@dataclass(frozen=True)
class EventSearchCriteria:
    event_id: str | None = None
    source_name: str | None = None
    parser_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    action: str | None = None
    user: str | None = None
    timestamp_from: datetime | None = None
    timestamp_to: datetime | None = None
    job_id: str | None = None
    incident_id: str | None = None
    is_context: bool | None = None
    sort: Literal["timestamp"] = "timestamp"
    direction: SortDirection = "desc"
    page_size: int = 50
    cursor: str | None = None


@dataclass(frozen=True)
class SignalSearchCriteria:
    signal_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    signal_type: str | None = None
    signal_family: str | None = None
    severities: tuple[str, ...] = ()
    min_confidence: float | None = None
    max_confidence: float | None = None
    suppressed: bool | None = None
    first_seen_from: datetime | None = None
    first_seen_to: datetime | None = None
    last_seen_from: datetime | None = None
    last_seen_to: datetime | None = None
    job_id: str | None = None
    incident_id: str | None = None
    mitre_technique: str | None = None
    sort: Literal[
        "created_at", "first_seen", "last_seen", "severity", "confidence"
    ] = "created_at"
    direction: SortDirection = "desc"
    page_size: int = 50
    cursor: str | None = None


@dataclass(frozen=True)
class JobSearchCriteria:
    job_id: str | None = None
    statuses: tuple[str, ...] = ()
    analysis_mode: str | None = None
    source_name: str | None = None
    file_sha256: str | None = None
    pipeline_version: str | None = None
    reused: bool | None = None
    min_reused_count: int | None = None
    created_at_from: datetime | None = None
    created_at_to: datetime | None = None
    queued_at_from: datetime | None = None
    queued_at_to: datetime | None = None
    completed_at_from: datetime | None = None
    completed_at_to: datetime | None = None
    error_code: str | None = None
    cancelled: bool | None = None
    min_attempt_count: int | None = None
    sort: Literal["created_at", "completed_at", "status"] = "created_at"
    direction: SortDirection = "desc"
    page_size: int = 50
    cursor: str | None = None


@dataclass(frozen=True)
class IncidentSearchResult:
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


@dataclass(frozen=True)
class EventSearchResult:
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


@dataclass(frozen=True)
class SignalSearchResult:
    signal_id: str
    rule_id: str
    rule_name: str
    signal_type: str
    severity: str
    confidence: float
    first_seen: datetime | None
    last_seen: datetime | None
    suppressed: bool


@dataclass(frozen=True)
class JobSearchResult:
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


T = TypeVar("T")


@dataclass(frozen=True)
class RepositorySearchPage(Generic[T]):
    items: list[T]
    has_more: bool
    next_position: tuple[CursorValue, str] | None = None


@dataclass(frozen=True)
class SearchPage(Generic[T]):
    items: list[T]
    next_cursor: str | None
    has_more: bool


class SearchRepository(Protocol):
    def search_incidents(
        self, criteria: IncidentSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[IncidentSearchResult]: ...

    def search_events(
        self, criteria: EventSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[EventSearchResult]: ...

    def search_signals(
        self, criteria: SignalSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[SignalSearchResult]: ...

    def search_jobs(
        self, criteria: JobSearchCriteria, cursor: SearchCursor | None
    ) -> RepositorySearchPage[JobSearchResult]: ...


_DEVELOPMENT_CURSOR_SECRET = secrets.token_bytes(32)


class SearchCursorCodec:
    def __init__(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("search_cursor_secret_too_short")
        self._secret = secret

    @staticmethod
    def _b64encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )

    def encode(self, cursor: SearchCursor) -> str:
        payload = json.dumps(
            {
                "r": cursor.resource,
                "s": cursor.sort,
                "d": cursor.direction,
                "v": cursor.value,
                "i": cursor.item_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        encoded = f"{self._b64encode(payload)}.{self._b64encode(signature)}"
        if len(encoded) > MAX_CURSOR_LENGTH:
            raise InvalidSearchCursorError()
        return encoded

    def decode(
        self,
        token: str,
        *,
        resource: str,
        sort: str,
        direction: SortDirection,
    ) -> SearchCursor:
        if not token or len(token) > MAX_CURSOR_LENGTH:
            raise InvalidSearchCursorError()
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = self._b64decode(encoded_payload)
            signature = self._b64decode(encoded_signature)
            expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise InvalidSearchCursorError()
            document = json.loads(payload)
            if set(document) != {"r", "s", "d", "v", "i"}:
                raise InvalidSearchCursorError()
            cursor = SearchCursor(
                resource=str(document["r"]),
                sort=str(document["s"]),
                direction=document["d"],
                value=document["v"],
                item_id=str(document["i"]),
            )
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            raise InvalidSearchCursorError() from None
        if (
            cursor.resource != resource
            or cursor.sort != sort
            or cursor.direction != direction
            or not cursor.item_id
        ):
            raise InvalidSearchCursorError()
        return cursor


def _validate_nonempty(value: str | None, field_name: str) -> None:
    if value is not None and not value.strip():
        raise SearchValidationError(f"{field_name}_empty")


def _validate_values(
    values: tuple[str, ...], field_name: str, allowed: frozenset[str]
) -> None:
    if len(values) > MAX_FILTER_VALUES:
        raise SearchValidationError(f"{field_name}_too_many_values")
    if any(not value.strip() for value in values):
        raise SearchValidationError(f"{field_name}_empty")
    if any(value not in allowed for value in values):
        raise SearchValidationError(f"{field_name}_invalid")


def _validate_range(
    start: datetime | None, end: datetime | None, field_name: str
) -> None:
    for value in (start, end):
        if value is not None and value.utcoffset() is None:
            raise SearchValidationError(f"{field_name}_timezone_required")
    if start is not None and end is not None and start > end:
        raise SearchValidationError(f"{field_name}_range_invalid")


def _validate_confidence(minimum: float | None, maximum: float | None) -> None:
    if minimum is not None and not 0 <= minimum <= 1:
        raise SearchValidationError("min_confidence_invalid")
    if maximum is not None and not 0 <= maximum <= 1:
        raise SearchValidationError("max_confidence_invalid")
    if minimum is not None and maximum is not None and minimum > maximum:
        raise SearchValidationError("confidence_range_invalid")


def validate_criteria(
    criteria: IncidentSearchCriteria
    | EventSearchCriteria
    | SignalSearchCriteria
    | JobSearchCriteria,
    *,
    max_page_size: int,
) -> None:
    if not 1 <= criteria.page_size <= max_page_size:
        raise SearchValidationError("page_size_invalid")
    if isinstance(criteria, IncidentSearchCriteria):
        _validate_values(criteria.statuses, "status", INCIDENT_STATUSES)
        _validate_values(criteria.severities, "severity", SEVERITIES)
        _validate_confidence(criteria.min_confidence, criteria.max_confidence)
        _validate_range(criteria.first_seen_from, criteria.first_seen_to, "first_seen")
        _validate_range(criteria.last_seen_from, criteria.last_seen_to, "last_seen")
        _validate_range(criteria.created_at_from, criteria.created_at_to, "created_at")
        for name in (
            "incident_type",
            "incident_family",
            "primary_entity",
            "mitre_technique",
            "job_id",
            "title_prefix",
        ):
            _validate_nonempty(getattr(criteria, name), name)
    elif isinstance(criteria, EventSearchCriteria):
        _validate_range(criteria.timestamp_from, criteria.timestamp_to, "timestamp")
        for name in (
            "event_id",
            "source_name",
            "parser_name",
            "src_ip",
            "dst_ip",
            "protocol",
            "action",
            "user",
            "job_id",
            "incident_id",
        ):
            _validate_nonempty(getattr(criteria, name), name)
        if criteria.is_context is not None and criteria.incident_id is None:
            raise SearchValidationError("incident_id_required_for_context")
    elif isinstance(criteria, SignalSearchCriteria):
        _validate_values(criteria.severities, "severity", SEVERITIES)
        _validate_confidence(criteria.min_confidence, criteria.max_confidence)
        _validate_range(criteria.first_seen_from, criteria.first_seen_to, "first_seen")
        _validate_range(criteria.last_seen_from, criteria.last_seen_to, "last_seen")
        for name in (
            "signal_id",
            "rule_id",
            "rule_name",
            "signal_type",
            "signal_family",
            "job_id",
            "incident_id",
            "mitre_technique",
        ):
            _validate_nonempty(getattr(criteria, name), name)
    else:
        _validate_values(criteria.statuses, "status", JOB_STATUSES)
        _validate_range(criteria.created_at_from, criteria.created_at_to, "created_at")
        _validate_range(criteria.queued_at_from, criteria.queued_at_to, "queued_at")
        _validate_range(criteria.completed_at_from, criteria.completed_at_to, "completed_at")
        if criteria.min_reused_count is not None and criteria.min_reused_count < 0:
            raise SearchValidationError("min_reused_count_invalid")
        if criteria.min_attempt_count is not None and criteria.min_attempt_count < 0:
            raise SearchValidationError("min_attempt_count_invalid")
        for name in (
            "job_id",
            "analysis_mode",
            "source_name",
            "file_sha256",
            "pipeline_version",
            "error_code",
        ):
            _validate_nonempty(getattr(criteria, name), name)


def _cursor_value(value: CursorValue) -> CursorValue:
    if isinstance(value, datetime):
        normalized = (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )
        return normalized.isoformat().replace("+00:00", "Z")
    return value


class SearchService:
    def __init__(
        self,
        repository: SearchRepository,
        settings: Settings,
    ) -> None:
        secret = (
            settings.search_cursor_secret.get_secret_value().encode("utf-8")
            if settings.search_cursor_secret is not None
            else _DEVELOPMENT_CURSOR_SECRET
        )
        self._repository = repository
        self._codec = SearchCursorCodec(secret)
        self._max_page_size = settings.search_max_page_size

    def _cursor(
        self, resource: str, sort: str, direction: SortDirection, token: str | None
    ) -> SearchCursor | None:
        if token is None:
            return None
        cursor = self._codec.decode(
            token,
            resource=resource,
            sort=sort,
            direction=direction,
        )
        if sort in {"created_at", "first_seen", "last_seen", "timestamp", "completed_at"}:
            if cursor.value is not None and not isinstance(cursor.value, str):
                raise InvalidSearchCursorError()
            if cursor.value is not None:
                try:
                    value = datetime.fromisoformat(cursor.value.replace("Z", "+00:00"))
                except ValueError:
                    raise InvalidSearchCursorError() from None
                cursor = SearchCursor(
                    cursor.resource,
                    cursor.sort,
                    cursor.direction,
                    value,
                    cursor.item_id,
                )
        elif sort == "confidence":
            if cursor.value is not None and not isinstance(cursor.value, (int, float)):
                raise InvalidSearchCursorError()
            cursor = SearchCursor(
                cursor.resource,
                cursor.sort,
                cursor.direction,
                float(cursor.value) if cursor.value is not None else None,
                cursor.item_id,
            )
        return cursor

    def _page(
        self,
        resource: str,
        sort: str,
        direction: SortDirection,
        page: RepositorySearchPage[T],
    ) -> SearchPage[T]:
        next_cursor = None
        if page.next_position is not None:
            value, item_id = page.next_position
            next_cursor = self._codec.encode(
                SearchCursor(resource, sort, direction, _cursor_value(value), item_id)
            )
        return SearchPage(page.items, next_cursor, page.has_more)

    def search_incidents(
        self, criteria: IncidentSearchCriteria
    ) -> SearchPage[IncidentSearchResult]:
        validate_criteria(criteria, max_page_size=self._max_page_size)
        cursor = self._cursor("incidents", criteria.sort, criteria.direction, criteria.cursor)
        return self._page(
            "incidents",
            criteria.sort,
            criteria.direction,
            self._repository.search_incidents(criteria, cursor),
        )

    def search_events(
        self, criteria: EventSearchCriteria
    ) -> SearchPage[EventSearchResult]:
        validate_criteria(criteria, max_page_size=self._max_page_size)
        cursor = self._cursor("events", criteria.sort, criteria.direction, criteria.cursor)
        return self._page(
            "events",
            criteria.sort,
            criteria.direction,
            self._repository.search_events(criteria, cursor),
        )

    def search_signals(
        self, criteria: SignalSearchCriteria
    ) -> SearchPage[SignalSearchResult]:
        validate_criteria(criteria, max_page_size=self._max_page_size)
        cursor = self._cursor("signals", criteria.sort, criteria.direction, criteria.cursor)
        return self._page(
            "signals",
            criteria.sort,
            criteria.direction,
            self._repository.search_signals(criteria, cursor),
        )

    def search_jobs(self, criteria: JobSearchCriteria) -> SearchPage[JobSearchResult]:
        validate_criteria(criteria, max_page_size=self._max_page_size)
        cursor = self._cursor("jobs", criteria.sort, criteria.direction, criteria.cursor)
        return self._page(
            "jobs",
            criteria.sort,
            criteria.direction,
            self._repository.search_jobs(criteria, cursor),
        )
