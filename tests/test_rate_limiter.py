"""Tests for Redis Lua token-bucket rate limiter."""

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
async def test_token_bucket_refill(rate_limiter: RateLimiter) -> None:
    key = "ratelimit:custom_test"

    # Capacity = 2, rate = 2/min (~0.033 tokens/sec)
    assert await rate_limiter.acquire(key, limit_per_minute=2) is True
    assert await rate_limiter.acquire(key, limit_per_minute=2) is True
    assert await rate_limiter.acquire(key, limit_per_minute=2) is False
