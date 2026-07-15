from __future__ import annotations

import datetime
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    reset_at: datetime.datetime


class RateLimiterUnavailableError(Exception):
    """The configured transient security-control store is unavailable."""

    def __init__(self) -> None:
        super().__init__("rate_limit_unavailable")


class RateLimiter(Protocol):
    def consume(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitDecision:
        ...

    def check_health(self) -> bool:
        ...


@dataclass
class _MemoryWindow:
    count: int
    reset_timestamp: float


class InMemoryRateLimiter:
    """Thread-safe fixed windows for local use and deterministic unit tests.

    Counters are process-local, disappear on restart, and do not coordinate
    across workers. Production settings therefore reject this backend.
    """

    def __init__(self, *, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._windows: dict[str, _MemoryWindow] = {}
        self._lock = threading.Lock()

    def consume(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitDecision:
        _validate_consumption(limit, window_seconds, cost)
        now = self._clock()
        with self._lock:
            window = self._windows.get(key)
            if window is None or now >= window.reset_timestamp:
                window = _MemoryWindow(
                    count=0,
                    reset_timestamp=now + window_seconds,
                )
                self._windows[key] = window
            window.count = min(window.count + cost, limit + cost)
            allowed = window.count <= limit
            remaining = max(limit - window.count, 0)
            retry_after = max(1, min(
                window_seconds,
                int(window.reset_timestamp - now + 0.999999),
            ))
            reset_at = datetime.datetime.fromtimestamp(
                window.reset_timestamp,
                tz=datetime.timezone.utc,
            )
        return RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            retry_after_seconds=retry_after,
            reset_at=reset_at,
        )

    def check_health(self) -> bool:
        return True


class RedisRateLimiter:
    """Distributed fixed windows using one atomic Redis Lua operation."""

    _CONSUME_SCRIPT = """
local cost = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local current = redis.call('INCRBY', KEYS[1], cost)
if current == cost then
    redis.call('EXPIRE', KEYS[1], window)
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 1 or ttl > window then
    redis.call('EXPIRE', KEYS[1], window)
    ttl = window
end
local maximum = limit + cost
if current > maximum then
    current = maximum
    redis.call('SET', KEYS[1], current, 'EX', ttl)
end
return {current, ttl}
"""

    def __init__(
        self,
        redis_url: str,
        *,
        client: Any | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if client is None:
            import redis

            client = redis.Redis.from_url(
                redis_url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=False,
            )
        self._client: Any = client
        self._clock = clock

    def consume(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        cost: int = 1,
    ) -> RateLimitDecision:
        _validate_consumption(limit, window_seconds, cost)
        try:
            result = self._client.eval(
                self._CONSUME_SCRIPT,
                1,
                key,
                str(cost),
                str(window_seconds),
                str(limit),
            )
            current = int(result[0])
            ttl = max(1, min(window_seconds, int(result[1])))
        except Exception:
            raise RateLimiterUnavailableError() from None

        now = self._clock()
        return RateLimitDecision(
            allowed=current <= limit,
            limit=limit,
            remaining=max(limit - current, 0),
            retry_after_seconds=ttl,
            reset_at=datetime.datetime.fromtimestamp(
                now + ttl,
                tz=datetime.timezone.utc,
            ),
        )

    def check_health(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False


def _validate_consumption(limit: int, window_seconds: int, cost: int) -> None:
    if limit < 1 or window_seconds < 1 or cost < 1 or cost > limit:
        raise ValueError("rate_limit_arguments_invalid")
