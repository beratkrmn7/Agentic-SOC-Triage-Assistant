from __future__ import annotations

from collections.abc import MutableSequence
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agent.api.security import trusted_client_address
from agent.config import Settings
from agent.security.abuse_protection import (
    RateLimitCategory,
    RateLimitExceededError,
    RateLimitManager,
)
from agent.security.rate_limiting import (
    RateLimitDecision,
    RateLimiterUnavailableError,
)


RATE_LIMITED_ERROR = {
    "code": "rate_limited",
    "message": "Too many requests. Please retry later.",
}
RATE_LIMIT_UNAVAILABLE_ERROR = {
    "code": "rate_limit_unavailable",
    "message": "The request cannot be processed at this time.",
}
_HEALTH_PATHS = frozenset({"/health/live", "/health/ready"})
_DOCUMENTATION_PATHS = frozenset({
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/openapi.json",
})
_MAX_RESET_TIMESTAMP = 4_102_444_800


def remember_rate_limit_decision(
    scope: Scope,
    decision: RateLimitDecision | None,
) -> None:
    if decision is None:
        return
    state = scope.setdefault("state", {})
    decisions: MutableSequence[RateLimitDecision] = state.setdefault(
        "rate_limit_decisions",
        [],
    )
    decisions.append(decision)


def most_restrictive_decision(scope: Scope) -> RateLimitDecision | None:
    decisions = scope.get("state", {}).get("rate_limit_decisions", [])
    if not decisions:
        return None
    return min(
        decisions,
        key=lambda decision: (
            decision.remaining / decision.limit,
            decision.remaining,
            decision.retry_after_seconds,
        ),
    )


def rate_limit_headers(
    decision: RateLimitDecision,
    *,
    include_retry_after: bool,
) -> dict[str, str]:
    reset_timestamp = int(decision.reset_at.timestamp())
    reset_timestamp = max(0, min(reset_timestamp, _MAX_RESET_TIMESTAMP))
    headers = {
        "X-RateLimit-Limit": str(max(1, min(decision.limit, 1_000_000))),
        "X-RateLimit-Remaining": str(
            max(0, min(decision.remaining, decision.limit))
        ),
        "X-RateLimit-Reset": str(reset_timestamp),
    }
    if include_retry_after:
        headers["Retry-After"] = str(
            max(1, min(decision.retry_after_seconds, 86400))
        )
    return headers


def route_identifier(scope: Scope) -> str:
    route = scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str):
        return f"{scope.get('method', 'UNKNOWN')} {route_path}"
    return f"{scope.get('method', 'UNKNOWN')} application_route"


class RateLimitMiddleware:
    """Applies a broad anonymous ceiling and emits one header set per response."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Settings,
        manager: RateLimitManager,
    ):
        self.app = app
        self.settings = settings
        self.manager = manager

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http" or scope.get("path") in _HEALTH_PATHS:
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        category = (
            RateLimitCategory.DOCUMENTATION
            if path in _DOCUMENTATION_PATHS
            else RateLimitCategory.GENERAL
        )
        state: dict[str, Any] = scope.setdefault("state", {})
        try:
            decision = self.manager.enforce_anonymous(
                category,
                client_address=trusted_client_address(scope, self.settings),
                request_id=state.get("request_id"),
                route=route_identifier(scope),
            )
            remember_rate_limit_decision(scope, decision)
        except RateLimitExceededError as exc:
            remember_rate_limit_decision(scope, exc.decision)
            response = JSONResponse(
                status_code=429,
                content=RATE_LIMITED_ERROR,
                headers=rate_limit_headers(
                    exc.decision,
                    include_retry_after=True,
                ),
            )
            await response(scope, receive, send)
            return
        except RateLimiterUnavailableError:
            response = JSONResponse(
                status_code=503,
                content=RATE_LIMIT_UNAVAILABLE_ERROR,
            )
            await response(scope, receive, send)
            return

        async def send_with_rate_limit_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                selected = most_restrictive_decision(scope)
                if selected is not None:
                    headers = MutableHeaders(scope=message)
                    for name, value in rate_limit_headers(
                        selected,
                        include_retry_after=False,
                    ).items():
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_rate_limit_headers)
