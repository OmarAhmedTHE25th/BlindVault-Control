"""Atomic Redis Lua-script token-bucket rate limiter."""

import time
from collections.abc import Callable
from typing import Any

import redis.asyncio as aioredis

from blindvault_control.config import settings

# Atomic Lua Token-Bucket Rate Limiter
TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

local data = redis.call("HMGET", key, "tokens", "last_updated")
local tokens = tonumber(data[1])
local last_updated = tonumber(data[2])

if not tokens or not last_updated then
    tokens = capacity
    last_updated = now
else
    local elapsed = math.max(0, now - last_updated)
    tokens = math.min(capacity, tokens + (elapsed * refill_rate))
    last_updated = now
end

if tokens >= requested then
    tokens = tokens - requested
    redis.call("HSET", key, "tokens", tostring(tokens), "last_updated", tostring(last_updated))
    local ttl = math.max(60, math.ceil(capacity / math.max(refill_rate, 0.001)) * 2)
    redis.call("EXPIRE", key, ttl)
    return 1
else
    redis.call("HSET", key, "tokens", tostring(tokens), "last_updated", tostring(last_updated))
    local ttl = math.max(60, math.ceil(capacity / math.max(refill_rate, 0.001)) * 2)
    redis.call("EXPIRE", key, ttl)
    return 0
end
"""


class RateLimiter:
    """Non-blocking token-bucket rate limiter backed by atomic Redis Lua execution."""

    def __init__(
        self,
        client: aioredis.Redis,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        self._client = client
        self._time_fn = time_fn
        self._script: Any = None

    def _get_script(self) -> Any:
        if self._script is None:
            self._script = self._client.register_script(TOKEN_BUCKET_LUA)
        return self._script

    async def acquire(
        self,
        key: str,
        limit_per_minute: int,
        requested: int = 1,
    ) -> bool:
        """Check if request is within limits and consume tokens atomically.

        Args:
            key: Rate limit key identifier (e.g. ratelimit:handshake:1.2.3.4).
            limit_per_minute: Allowed capacity and refill rate per 60 seconds.
            requested: Number of tokens to consume (default 1).

        Returns:
            True if allowed, False if rate limited.
        """
        capacity = float(limit_per_minute)
        refill_rate = capacity / 60.0
        now = self._time_fn()

        script = self._get_script()
        result = await script(
            keys=[key],
            args=[capacity, refill_rate, now, requested],
            client=self._client,
        )
        return bool(result == 1)

    async def check_handshake(self, client_ip: str) -> bool:
        """Rate limit handshake attempts per IP."""
        key = f"ratelimit:handshake:{client_ip}"
        return await self.acquire(key, settings.RATE_LIMIT_HANDSHAKE_PER_MIN)

    async def check_invite(self, fingerprint: str) -> bool:
        """Rate limit pairing invite creation per peer fingerprint."""
        key = f"ratelimit:invite:{fingerprint}"
        return await self.acquire(key, settings.RATE_LIMIT_INVITE_PER_MIN)

    async def check_claim(self, fingerprint: str, client_ip: str | None = None) -> bool:
        """Rate limit pairing invite claims per fingerprint and per IP."""
        key_fp = f"ratelimit:claim:fp:{fingerprint}"
        allowed_fp = await self.acquire(key_fp, settings.RATE_LIMIT_CLAIM_PER_MIN)
        if not allowed_fp:
            return False

        if client_ip:
            key_ip = f"ratelimit:claim:ip:{client_ip}"
            allowed_ip = await self.acquire(key_ip, settings.RATE_LIMIT_CLAIM_PER_MIN)
            if not allowed_ip:
                return False

        return True

    async def check_relay(self, fingerprint: str) -> bool:
        """Rate limit fallback relay session creation per peer fingerprint."""
        key = f"ratelimit:relay:{fingerprint}"
        return await self.acquire(key, settings.RATE_LIMIT_RELAY_PER_MIN)
