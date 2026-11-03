"""Submission rate limiting: token buckets, route scope and app wiring.

Finding #2: the API had no throttle at all. Queue capacity was the only bound,
and because admission coalesced the same repository per submitter key, a client
could mint fresh keys for free and occupy every pending slot. The limiter adds
a per-IP bucket (the anchor a client cannot mint) and a per-key bucket (one
browser's friction), and must never touch status polling.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.middleware.cors import CORSMiddleware

from app.core.config import Settings, settings
from app.core.rate_limit import (
    SubmissionRateLimiter,
    SubmissionRateLimitMiddleware,
    TokenBucket,
    build_submission_limiter,
)
from app.services import metrics as metrics_mod

ORIGIN = "http://localhost:3000"


class FakeClock:
    """Deterministic monotonic clock; the buckets never sleep in tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_burst_is_spent_then_refills_continuously(self):
        clock = FakeClock()
        bucket = TokenBucket(10, 5, clock=clock)

        for _ in range(5):
            assert bucket.retry_after("client") == 0.0
            bucket.consume("client")

        wait = bucket.retry_after("client")
        assert 5.9 < wait <= 6.0  # 10/min = one token every 6s

        clock.advance(6.0)
        assert bucket.retry_after("client") == 0.0

    def test_consumed_tokens_never_exceed_burst_after_long_idle(self):
        clock = FakeClock()
        bucket = TokenBucket(10, 2, clock=clock)
        bucket.consume("client")
        bucket.consume("client")
        clock.advance(600.0)

        allowed = 0
        for _ in range(3):
            if bucket.retry_after("client") == 0.0:
                bucket.consume("client")
                allowed += 1
        assert allowed == 2

    def test_buckets_are_independent_per_key(self):
        clock = FakeClock()
        bucket = TokenBucket(10, 1, clock=clock)
        assert bucket.retry_after("a") == 0.0
        bucket.consume("a")
        assert bucket.retry_after("a") > 0.0
        assert bucket.retry_after("b") == 0.0

    def test_idle_buckets_are_pruned(self):
        clock = FakeClock()
        bucket = TokenBucket(10, 5, clock=clock, max_buckets=100)
        for index in range(20):
            bucket.retry_after(f"key-{index}")

        clock.advance(200.0)  # beyond the idle window
        bucket.retry_after("fresh")
        assert bucket.bucket_count() == 1

    def test_storage_is_capped_under_key_churn(self):
        clock = FakeClock()
        bucket = TokenBucket(10, 5, clock=clock, max_buckets=3)
        for index in range(10):
            bucket.retry_after(f"key-{index}")
        assert bucket.bucket_count() <= 3

    def test_non_positive_configuration_is_rejected(self):
        with pytest.raises(ValueError):
            TokenBucket(0, 1, clock=FakeClock())
        with pytest.raises(ValueError):
            TokenBucket(1, 0, clock=FakeClock())


# ---------------------------------------------------------------------------
# SubmissionRateLimiter
# ---------------------------------------------------------------------------


def _limiter(
    clock: FakeClock,
    *,
    ip_per_minute: int = 10,
    ip_burst: int = 5,
    submitter_per_minute: int = 3,
    submitter_burst: int = 2,
) -> SubmissionRateLimiter:
    return SubmissionRateLimiter(
        ip_per_minute=ip_per_minute,
        ip_burst=ip_burst,
        submitter_per_minute=submitter_per_minute,
        submitter_burst=submitter_burst,
        clock=clock,
    )


class TestSubmissionRateLimiter:
    def test_fresh_keys_cannot_outrun_the_ip_bucket(self):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=2, submitter_burst=100)

        assert limiter.check(ip="203.0.113.7", submitter_key="key-a").allowed
        assert limiter.check(ip="203.0.113.7", submitter_key="key-b").allowed

        decision = limiter.check(ip="203.0.113.7", submitter_key="key-c")
        assert not decision.allowed
        assert decision.retry_after >= 1

    def test_one_key_cannot_consume_the_shared_ip_budget(self):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=100, submitter_burst=1)

        assert limiter.check(ip="203.0.113.7", submitter_key="key-a").allowed
        assert not limiter.check(ip="203.0.113.7", submitter_key="key-a").allowed
        # A different browser on the same network is still welcome.
        assert limiter.check(ip="203.0.113.7", submitter_key="key-b").allowed

    def test_a_rejection_does_not_burn_the_other_bucket(self):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=100)

        assert limiter.check(ip="203.0.113.7", submitter_key=None).allowed
        rejected = limiter.check(ip="203.0.113.7", submitter_key="key-a")
        assert not rejected.allowed

        clock.advance(7.0)  # one token back at 10/min
        assert limiter.check(ip="203.0.113.7", submitter_key="key-a").allowed

    def test_retry_after_rounds_up_to_whole_seconds(self):
        clock = FakeClock()
        limiter = _limiter(clock, ip_per_minute=600, ip_burst=1, submitter_burst=100)
        assert limiter.check(ip="203.0.113.7", submitter_key=None).allowed
        clock.advance(0.05)  # half of the 0.1s refill at 600/min
        decision = limiter.check(ip="203.0.113.7", submitter_key=None)
        assert not decision.allowed
        assert decision.retry_after == 1

    def test_bucket_isolation_between_ips(self):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=100)
        assert limiter.check(ip="198.51.100.1", submitter_key=None).allowed
        assert limiter.check(ip="198.51.100.2", submitter_key=None).allowed
        assert not limiter.check(ip="198.51.100.1", submitter_key=None).allowed

    def test_missing_ip_and_key_are_not_fatal(self):
        clock = FakeClock()
        limiter = _limiter(clock)
        assert limiter.check(ip=None, submitter_key=None).allowed


# ---------------------------------------------------------------------------
# Middleware: scope, response shape and CORS
# ---------------------------------------------------------------------------


def _build_app(limiter: SubmissionRateLimiter, *, enabled: bool = True) -> FastAPI:
    api = FastAPI()
    api.state.rate_limit_enabled = enabled
    api.state.rate_limiter = limiter

    @api.post("/api/check")
    async def create_check() -> dict[str, bool]:
        return {"created": True}

    @api.post("/api/check/upload")
    async def create_upload() -> dict[str, bool]:
        return {"created": True}

    @api.get("/api/check/{task_id}")
    async def read_check(task_id: str) -> dict[str, str]:
        return {"task_id": task_id}

    @api.post("/api/other")
    async def other() -> dict[str, bool]:
        return {"ok": True}

    api.add_middleware(SubmissionRateLimitMiddleware)
    api.add_middleware(
        CORSMiddleware,
        allow_origins=[ORIGIN],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Submitter-Key"],
    )
    return api


@pytest.fixture
def outside_test_env(monkeypatch):
    """The limiter is hard-disabled under APP_ENV=test; re-enable per test."""
    monkeypatch.setattr(settings, "app_env", "development")


class TestSubmissionRateLimitMiddleware:
    def test_rejection_shape_retry_after_and_cors(self, outside_test_env):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=100)
        client = TestClient(_build_app(limiter))

        assert client.post("/api/check", json={}, headers={"Origin": ORIGIN}).status_code == 200
        rejected = client.post("/api/check", json={}, headers={"Origin": ORIGIN})

        assert rejected.status_code == 429
        assert rejected.json()["detail"] == {
            "error_code": "RATE_LIMITED",
            "error_message": "提交过于频繁，请稍后重试。",
        }
        assert int(rejected.headers["Retry-After"]) >= 1
        assert rejected.headers["access-control-allow-origin"] == ORIGIN

    def test_upload_route_is_limited_too(self, outside_test_env):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=100)
        client = TestClient(_build_app(limiter))

        assert client.post("/api/check/upload").status_code == 200
        assert client.post("/api/check/upload").status_code == 429

    def test_status_polling_is_never_throttled(self, outside_test_env):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=100)
        client = TestClient(_build_app(limiter))

        assert client.post("/api/check", json={}).status_code == 200
        assert client.post("/api/check", json={}).status_code == 429

        for index in range(20):
            response = client.get(f"/api/check/0000-{index}")
            assert response.status_code == 200

    def test_unrelated_routes_are_not_limited(self, outside_test_env):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=100)
        client = TestClient(_build_app(limiter))

        assert client.post("/api/check", json={}).status_code == 200
        assert client.post("/api/check", json={}).status_code == 429
        assert client.post("/api/other").status_code == 200

    def test_disabled_limiter_passes_every_request(self, outside_test_env):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=1)
        client = TestClient(_build_app(limiter, enabled=False))

        for _ in range(10):
            assert client.post("/api/check", json={}).status_code == 200

    def test_test_app_env_keeps_the_suite_unthrottled(self, monkeypatch):
        monkeypatch.setattr(settings, "app_env", "test")
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=1)
        client = TestClient(_build_app(limiter))

        for _ in range(10):
            assert client.post("/api/check", json={}).status_code == 200

    def test_rejection_increments_the_metric(self, outside_test_env):
        clock = FakeClock()
        limiter = _limiter(clock, ip_burst=1, submitter_burst=100)
        client = TestClient(_build_app(limiter))

        client.post("/api/check", json={})
        assert client.post("/api/check", json={}).status_code == 429
        assert "vibecheck_rate_limited_total" in metrics_mod.render_prometheus()


# ---------------------------------------------------------------------------
# Application wiring
# ---------------------------------------------------------------------------


class TestAppWiring:
    def test_real_app_registers_the_middleware(self):
        from app.main import app

        assert any(
            middleware.cls is SubmissionRateLimitMiddleware
            for middleware in app.user_middleware
        )

    def test_limiter_is_built_from_settings(self):
        config = Settings(
            rate_limit_ip_per_minute=10,
            rate_limit_ip_burst=5,
            rate_limit_submitter_per_minute=3,
            rate_limit_submitter_burst=2,
        )
        limiter = build_submission_limiter(config)
        assert isinstance(limiter, SubmissionRateLimiter)

    def test_disabled_under_test_env(self):
        from app.main import create_app

        api = create_app(Settings(app_env="test"))
        assert api.state.rate_limit_enabled is False
        assert api.state.rate_limiter is None

    def test_enabled_outside_test_env(self):
        from app.main import create_app

        api = create_app(Settings(app_env="development"))
        assert api.state.rate_limit_enabled is True
        assert isinstance(api.state.rate_limiter, SubmissionRateLimiter)

    def test_operator_can_disable_the_limiter(self):
        from app.main import create_app

        api = create_app(Settings(app_env="development", rate_limit_enabled=False))
        assert api.state.rate_limit_enabled is False

    @pytest.mark.parametrize(
        "field",
        [
            "rate_limit_ip_per_minute",
            "rate_limit_ip_burst",
            "rate_limit_submitter_per_minute",
            "rate_limit_submitter_burst",
        ],
    )
    def test_zero_limits_are_rejected_by_config(self, field):
        with pytest.raises(ValidationError):
            Settings(**{field: 0})
