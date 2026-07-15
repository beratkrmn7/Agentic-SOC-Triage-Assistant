import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent.application.authentication import AuthenticatedPrincipal
from agent.security.abuse_protection import (
    RateLimitCategory,
    build_rate_limit_manager,
)
from agent.security.rate_limiting import (
    InMemoryRateLimiter,
    RateLimiterUnavailableError,
    RedisRateLimiter,
)
from tests.rate_limiting.conftest import make_rate_settings


class FakeClock:
    def __init__(self, value: float = 1_700_000_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class AtomicFakeRedis:
    def __init__(self):
        self._lock = threading.Lock()
        self.values: dict[str, int] = {}
        self.ttls: dict[str, int] = {}
        self.calls = 0

    def eval(self, script, key_count, key, cost, window, limit):
        assert key_count == 1
        assert "INCRBY" in script
        assert "EXPIRE" in script
        with self._lock:
            self.calls += 1
            current = self.values.get(key, 0) + int(cost)
            current = min(current, int(limit) + int(cost))
            self.values[key] = current
            self.ttls[key] = min(self.ttls.get(key, int(window)), int(window))
            return [current, self.ttls[key]]

    def ping(self):
        return True


class BrokenRedis:
    def eval(self, *args):
        raise RuntimeError("redis://:secret@private.internal:6379/9")

    def ping(self):
        raise RuntimeError("private backend text")


def test_requests_within_limit_succeed():
    limiter = InMemoryRateLimiter()
    assert all(
        limiter.consume("key", limit=3, window_seconds=60).allowed
        for _ in range(3)
    )


def test_request_over_limit_is_denied():
    limiter = InMemoryRateLimiter()
    limiter.consume("key", limit=1, window_seconds=60)
    assert not limiter.consume("key", limit=1, window_seconds=60).allowed


def test_retry_after_is_present_and_bounded_in_decision():
    limiter = InMemoryRateLimiter()
    decision = limiter.consume("key", limit=1, window_seconds=7)
    assert 1 <= decision.retry_after_seconds <= 7


def test_counters_expire_after_window():
    clock = FakeClock()
    limiter = InMemoryRateLimiter(clock=clock)
    assert limiter.consume("key", limit=1, window_seconds=5).allowed
    assert not limiter.consume("key", limit=1, window_seconds=5).allowed
    clock.advance(5)
    assert limiter.consume("key", limit=1, window_seconds=5).allowed


def test_concurrent_requests_cannot_exceed_accepted_count():
    limiter = InMemoryRateLimiter()
    with ThreadPoolExecutor(max_workers=16) as pool:
        decisions = list(pool.map(
            lambda _: limiter.consume("shared", limit=7, window_seconds=60),
            range(50),
        ))
    assert sum(decision.allowed for decision in decisions) == 7


def test_one_principal_does_not_consume_another_principal_allowance():
    manager = build_rate_limit_manager(
        make_rate_settings(rate_limit_reads=1),
        limiter=InMemoryRateLimiter(),
    )
    first = AuthenticatedPrincipal(
        "human_user", "subject-a", "A", "oidc_jwt", ("analyst",), None
    )
    second = AuthenticatedPrincipal(
        "human_user", "subject-b", "B", "oidc_jwt", ("analyst",), None
    )
    assert manager.enforce_principal(
        RateLimitCategory.READ,
        principal=first,
        request_id="r1",
        route="GET /test",
    )
    assert manager.enforce_principal(
        RateLimitCategory.READ,
        principal=second,
        request_id="r2",
        route="GET /test",
    )


def test_redis_counter_operation_is_one_atomic_eval():
    fake = AtomicFakeRedis()
    limiter = RedisRateLimiter("redis://unused", client=fake)
    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(
            lambda _: limiter.consume("opaque", limit=5, window_seconds=30),
            range(20),
        ))
    assert fake.calls == 20
    assert sum(decision.allowed for decision in decisions) == 5


def test_redis_keys_receive_bounded_ttl():
    fake = AtomicFakeRedis()
    limiter = RedisRateLimiter("redis://unused", client=fake)
    decision = limiter.consume("opaque", limit=5, window_seconds=11)
    assert fake.ttls["opaque"] == 11
    assert 1 <= decision.retry_after_seconds <= 11


def test_redis_backend_wraps_raw_errors_safely():
    limiter = RedisRateLimiter("redis://unused", client=BrokenRedis())
    with pytest.raises(RateLimiterUnavailableError) as caught:
        limiter.consume("opaque", limit=1, window_seconds=1)
    assert "secret" not in str(caught.value)
    assert not limiter.check_health()
