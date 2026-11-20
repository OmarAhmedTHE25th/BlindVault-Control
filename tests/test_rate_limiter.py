"""Tests for Redis Lua token-bucket rate limiter."""

from typing import Any

import pytest

from blindvault_control.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_handshake_rate_limiting(rate_limiter: RateLimiter) -> None:
    ip = "198.51.100.1"

    # First 10 handshakes within 1 minute are allowed
    for _ in range(10):
        allowed = await rate_limiter.check_handshake(ip)
        assert allowed is True

    # 11th handshake is blocked
    blocked = await rate_limiter.check_handshake(ip)
    assert blocked is False

    # Different IP is not affected
    other_ip_allowed = await rate_limiter.check_handshake("198.51.100.2")
    assert other_ip_allowed is True


@pytest.mark.asyncio
async def test_invite_rate_limiting(rate_limiter: RateLimiter) -> None:
    fp = "a" * 64

    # 10 invites allowed
    for _ in range(10):
        assert await rate_limiter.check_invite(fp) is True

    # 11th blocked
    assert await rate_limiter.check_invite(fp) is False

    # Different peer not affected
    assert await rate_limiter.check_invite("b" * 64) is True


@pytest.mark.asyncio
async def test_claim_rate_limiting(rate_limiter: RateLimiter) -> None:
    fp = "e" * 64
    client_ip = "198.51.100.5"

    # 10 claims allowed
    for _ in range(10):
        assert await rate_limiter.check_claim(fp, client_ip) is True

    # 11th blocked
    assert await rate_limiter.check_claim(fp, client_ip) is False

    # Different peer and IP not affected
    assert await rate_limiter.check_claim("f" * 64, "198.51.100.6") is True


@pytest.mark.asyncio
async def test_relay_rate_limiting(rate_limiter: RateLimiter) -> None:
    fp = "c" * 64

    # 5 relay sessions allowed per minute
    for _ in range(5):
        assert await rate_limiter.check_relay(fp) is True

    # 6th blocked
    assert await rate_limiter.check_relay(fp) is False

    # Different peer not affected
    assert await rate_limiter.check_relay("d" * 64) is True


@pytest.mark.asyncio
async def test_token_bucket_refill(fake_redis: Any) -> None:
    current_time = 1000.0

    def mock_time() -> float:
        return current_time

    limiter = RateLimiter(fake_redis, time_fn=mock_time)
    key = "ratelimit:custom_refill_test"

    # Capacity = 2, rate = 2/min (1 token every 30s)
    assert await limiter.acquire(key, limit_per_minute=2) is True
    assert await limiter.acquire(key, limit_per_minute=2) is True
    # Bucket exhausted
    assert await limiter.acquire(key, limit_per_minute=2) is False

    # Advance time by 30 seconds -> 1 token should refill
    current_time += 30.0
    assert await limiter.acquire(key, limit_per_minute=2) is True
    # Consumed the 1 refilled token, should be empty again
    assert await limiter.acquire(key, limit_per_minute=2) is False

    # Advance time by 60 seconds -> full 2 tokens refilled
    current_time += 60.0
    assert await limiter.acquire(key, limit_per_minute=2) is True
    assert await limiter.acquire(key, limit_per_minute=2) is True
    assert await limiter.acquire(key, limit_per_minute=2) is False
