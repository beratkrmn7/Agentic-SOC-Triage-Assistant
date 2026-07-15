from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from enum import StrEnum

from agent.application.authentication import AuthenticatedPrincipal
from agent.config import Settings
from agent.security.rate_limit_keys import RateLimitKeyBuilder
from agent.security.rate_limiting import (
    RateLimitDecision,
    RateLimiter,
    RateLimiterUnavailableError,
    InMemoryRateLimiter,
    RedisRateLimiter,
)


logger = logging.getLogger(__name__)
_DEVELOPMENT_KEY_SECRET = secrets.token_bytes(32)


class RateLimitCategory(StrEnum):
    GENERAL = "general"
    AUTHENTICATION_FAILURE = "authentication_failure"
    JOB_SUBMISSION = "job_submission"
    MUTATION = "mutation"
    READ = "read"
    DOCUMENTATION = "documentation"


@dataclass(frozen=True)
class RateLimitPolicy:
    limit: int
    window_seconds: int


class RateLimitExceededError(Exception):
    def __init__(
        self,
        category: RateLimitCategory,
        decision: RateLimitDecision,
    ) -> None:
        super().__init__("rate_limited")
        self.category = category
        self.decision = decision


class RateLimitManager:
    def __init__(
        self,
        *,
        enabled: bool,
        limiter: RateLimiter,
        key_builder: RateLimitKeyBuilder,
        policies: dict[RateLimitCategory, RateLimitPolicy],
    ):
        self.enabled = enabled
        self.limiter = limiter
        self.key_builder = key_builder
        self.policies = policies

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        limiter: RateLimiter,
        key_secret: bytes,
    ) -> "RateLimitManager":
        return cls(
            enabled=settings.rate_limiting_enabled,
            limiter=limiter,
            key_builder=RateLimitKeyBuilder(
                secret=key_secret,
                prefix=settings.rate_limit_prefix,
            ),
            policies={
                RateLimitCategory.GENERAL: RateLimitPolicy(
                    settings.rate_limit_general_requests,
                    settings.rate_limit_general_window_seconds,
                ),
                RateLimitCategory.AUTHENTICATION_FAILURE: RateLimitPolicy(
                    settings.rate_limit_auth_failures,
                    settings.rate_limit_auth_failure_window_seconds,
                ),
                RateLimitCategory.JOB_SUBMISSION: RateLimitPolicy(
                    settings.rate_limit_job_submissions,
                    settings.rate_limit_job_submission_window_seconds,
                ),
                RateLimitCategory.MUTATION: RateLimitPolicy(
                    settings.rate_limit_mutations,
                    settings.rate_limit_mutation_window_seconds,
                ),
                RateLimitCategory.READ: RateLimitPolicy(
                    settings.rate_limit_reads,
                    settings.rate_limit_read_window_seconds,
                ),
                RateLimitCategory.DOCUMENTATION: RateLimitPolicy(
                    settings.rate_limit_general_requests,
                    settings.rate_limit_general_window_seconds,
                ),
            },
        )

    def enforce_anonymous(
        self,
        category: RateLimitCategory,
        *,
        client_address: str,
        request_id: str | None,
        route: str,
    ) -> RateLimitDecision | None:
        key = self.key_builder.for_anonymous(
            client_address=client_address,
            category=category.value,
        )
        return self._enforce(
            category,
            key=key,
            request_id=request_id,
            route=route,
            authentication_method=None,
            subject_type=None,
        )

    def enforce_principal(
        self,
        category: RateLimitCategory,
        *,
        principal: AuthenticatedPrincipal,
        request_id: str | None,
        route: str,
    ) -> RateLimitDecision | None:
        key = self.key_builder.for_principal(
            subject_type=principal.subject_type,
            subject_id=principal.subject_id,
            authentication_method=principal.authentication_method,
            category=category.value,
        )
        return self._enforce(
            category,
            key=key,
            request_id=request_id,
            route=route,
            authentication_method=principal.authentication_method,
            subject_type=principal.subject_type,
        )

    def check_health(self) -> bool:
        if not self.enabled:
            return True
        return self.limiter.check_health()

    def _enforce(
        self,
        category: RateLimitCategory,
        *,
        key: str,
        request_id: str | None,
        route: str,
        authentication_method: str | None,
        subject_type: str | None,
    ) -> RateLimitDecision | None:
        if not self.enabled:
            return None
        policy = self.policies[category]
        try:
            decision = self.limiter.consume(
                key,
                limit=policy.limit,
                window_seconds=policy.window_seconds,
            )
        except RateLimiterUnavailableError:
            logger.error(
                "rate_limit_backend_unavailable",
                extra={
                    "category": category.value,
                    "request_id": request_id,
                    "route": route,
                    "authentication_method": authentication_method,
                    "subject_type": subject_type,
                },
            )
            raise
        if not decision.allowed:
            logger.warning(
                _event_name(category),
                extra={
                    "category": category.value,
                    "request_id": request_id,
                    "route": route,
                    "authentication_method": authentication_method,
                    "subject_type": subject_type,
                },
            )
            raise RateLimitExceededError(category, decision)
        return decision


def _event_name(category: RateLimitCategory) -> str:
    return {
        RateLimitCategory.AUTHENTICATION_FAILURE: (
            "authentication_rate_limit_exceeded"
        ),
        RateLimitCategory.JOB_SUBMISSION: (
            "job_submission_rate_limit_exceeded"
        ),
        RateLimitCategory.MUTATION: "mutation_rate_limit_exceeded",
    }.get(category, "rate_limit_exceeded")


def build_rate_limit_manager(
    settings: Settings,
    *,
    limiter: RateLimiter | None = None,
) -> RateLimitManager:
    selected_limiter = limiter
    if selected_limiter is None:
        if settings.rate_limit_backend == "redis":
            selected_limiter = RedisRateLimiter(settings.rate_limit_redis_url)
        else:
            selected_limiter = InMemoryRateLimiter()

    configured_secret = settings.rate_limit_key_secret
    key_secret = (
        configured_secret.get_secret_value().encode("utf-8")
        if configured_secret is not None
        else _DEVELOPMENT_KEY_SECRET
    )
    return RateLimitManager.from_settings(
        settings,
        limiter=selected_limiter,
        key_secret=key_secret,
    )
