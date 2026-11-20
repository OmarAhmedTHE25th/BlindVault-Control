"""Redis state management for peer presence, challenge nonces, and pairing invites."""

import json
from typing import Any

import redis.asyncio as aioredis

from blindvault_control.config import settings
from blindvault_control.crypto import decode_base64, encode_base64


class RedisStore:
    """Async Redis wrapper for zero-knowledge ephemeral peer state."""

    def __init__(self, client: aioredis.Redis | None = None) -> None:
        self._client: aioredis.Redis = client or aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
        )

    @property
    def client(self) -> aioredis.Redis:
        """Return the underlying async Redis client."""
        return self._client

    async def close(self) -> None:
        """Close Redis connection."""
        await self._client.aclose()

    # ---------- Challenge Nonce Management ----------

    async def store_challenge_nonce(
        self,
        fingerprint: str,
        nonce_bytes: bytes,
        ttl_seconds: int = settings.CHALLENGE_TTL_SECONDS,
    ) -> None:
        """Store an ephemeral cryptographic challenge nonce for a peer fingerprint."""
        key = f"nonce:{fingerprint}"
        nonce_b64 = encode_base64(nonce_bytes)
        await self._client.set(key, nonce_b64, ex=ttl_seconds)

    async def consume_challenge_nonce(self, fingerprint: str) -> bytes | None:
        """Atomically fetch and delete the challenge nonce to prevent replay attacks.

        Uses GETDEL for single-use guarantee.
        """
        key = f"nonce:{fingerprint}"
        val = await self._client.getdel(key)
        if not val:
            return None
        try:
            return decode_base64(val)
        except Exception:
            return None

    # ---------- Peer Presence Management ----------

    async def set_presence(
        self,
        fingerprint: str,
        metadata: dict[str, Any],
        ttl_seconds: int = settings.PRESENCE_TTL_SECONDS,
    ) -> None:
        """Register active peer presence in Redis with TTL expiration."""
        key = f"presence:{fingerprint}"
        payload = json.dumps(metadata)
        await self._client.set(key, payload, ex=ttl_seconds)

    async def refresh_presence(
        self,
        fingerprint: str,
        ttl_seconds: int = settings.PRESENCE_TTL_SECONDS,
    ) -> bool:
        """Extend presence TTL on peer heartbeat (PING/PONG)."""
        key = f"presence:{fingerprint}"
        result = await self._client.expire(key, ttl_seconds)
        return bool(result)

    async def get_presence(self, fingerprint: str) -> dict[str, Any] | None:
        """Check if a peer is currently present and fetch its connection metadata."""
        key = f"presence:{fingerprint}"
        val = await self._client.get(key)
        if not val:
            return None
        try:
            return json.loads(val)  # type: ignore[no-any-return]
        except Exception:
            return None

    async def remove_presence(self, fingerprint: str) -> None:
        """Remove peer presence immediately on disconnect."""
        key = f"presence:{fingerprint}"
        await self._client.delete(key)

    # ---------- Ephemeral Out-of-Band Pairing Invites ----------

    async def store_invite(
        self,
        code: str,
        creator_fingerprint: str,
        endpoints: list[dict[str, Any]] | None = None,
        ttl_seconds: int = settings.INVITE_TTL_SECONDS,
    ) -> None:
        """Store a single-use pairing invite code bound to the creator's fingerprint."""
        key = f"invite:{code}"
        payload = json.dumps(
            {
                "fingerprint": creator_fingerprint,
                "endpoints": endpoints or [],
            }
        )
        await self._client.set(key, payload, ex=ttl_seconds)

    async def consume_invite(self, code: str) -> dict[str, Any] | None:
        """Atomically fetch and consume a pairing invite code (single-use via GETDEL)."""
        key = f"invite:{code}"
        val = await self._client.getdel(key)
        if not val:
            return None
        try:
            return json.loads(val)  # type: ignore[no-any-return]
        except Exception:
            return None

    # ---------- Fallback Relay Sessions ----------

    async def store_relay_session(
        self,
        session_id: str,
        initiator_fp: str,
        responder_fp: str,
        initiator_token: str,
        responder_token: str,
        ttl_seconds: int = settings.RELAY_TOKEN_TTL_SECONDS,
    ) -> None:
        """Register an ephemeral relay rendezvous session with single-use peer tokens."""
        key = f"relay:{session_id}"
        payload = json.dumps(
            {
                "initiator_fp": initiator_fp,
                "responder_fp": responder_fp,
                "initiator_token": initiator_token,
                "responder_token": responder_token,
                "joined_peers": [],
            }
        )
        await self._client.set(key, payload, ex=ttl_seconds)

    async def get_relay_session(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve relay session configuration."""
        key = f"relay:{session_id}"
        val = await self._client.get(key)
        if not val:
            return None
        try:
            return json.loads(val)  # type: ignore[no-any-return]
        except Exception:
            return None

    async def delete_relay_session(self, session_id: str) -> None:
        """Clean up relay session state upon completion or disconnect."""
        key = f"relay:{session_id}"
        await self._client.delete(key)
