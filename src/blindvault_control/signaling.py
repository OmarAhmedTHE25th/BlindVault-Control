"""WebSocket control channel handling authentication, heartbeats, pairing, and signaling."""

import asyncio
import json
import secrets
from typing import Any

import structlog
from fastapi import WebSocket, WebSocketDisconnect

from blindvault_control.config import settings
from blindvault_control.crypto import (
    compute_peer_fingerprint,
    decode_base64,
    encode_base64,
    generate_challenge_nonce,
    generate_crockford_code,
    normalize_crockford_code,
    parse_ec_p256_public_key,
    verify_ecdsa_signature,
)
from blindvault_control.rate_limiter import RateLimiter
from blindvault_control.redis_store import RedisStore
from blindvault_control.relay import RelayManager
from blindvault_control.schemas import (
    AuthFailedMessage,
    AuthMessage,
    AuthOkMessage,
    ChallengeMessage,
    ClaimInviteMessage,
    CreateInviteMessage,
    CreateRelayMessage,
    ErrorMessage,
    HelloMessage,
    InviteCreatedMessage,
    PeerMatchedMessage,
    PongMessage,
    RelayCreatedMessage,
    RelayInviteMessage,
)

logger = structlog.get_logger()


class SignalingManager:
    """Maintains active in-memory WebSocket connections for authenticated peers."""

    def __init__(self) -> None:
        self.active_peers: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def register(self, fingerprint: str, ws: WebSocket) -> None:
        """Register active WebSocket connection for an authenticated peer."""
        async with self._lock:
            self.active_peers[fingerprint] = ws
        logger.info("peer_registered", fingerprint=fingerprint)

    async def unregister(self, fingerprint: str, ws: WebSocket) -> None:
        """Unregister active WebSocket connection on disconnect."""
        async with self._lock:
            current = self.active_peers.get(fingerprint)
            if current is ws:
                del self.active_peers[fingerprint]
        logger.info("peer_unregistered", fingerprint=fingerprint)

    async def send_to_peer(self, fingerprint: str, message: dict[str, Any]) -> bool:
        """Forward a message dictionary to a target peer if online."""
        async with self._lock:
            ws = self.active_peers.get(fingerprint)

        if not ws:
            return False

        try:
            await ws.send_text(json.dumps(message))
            return True
        except Exception as exc:
            logger.warning("forward_to_peer_failed", target=fingerprint, error=str(exc))
            return False


async def receive_control_frame(ws: WebSocket) -> dict[str, Any]:
    """Receive and validate an incoming control channel JSON message.

    Enforces 8 KiB frame limit and JSON syntax.
    """
    raw_frame = await ws.receive()
    if raw_frame.get("type") == "websocket.disconnect":
        raise WebSocketDisconnect()

    text_data = raw_frame.get("text")
    bytes_data = raw_frame.get("bytes")

    if bytes_data is not None:
        if len(bytes_data) > settings.CONTROL_MAX_FRAME_BYTES:
            await ws.close(code=1009, reason="Control frame exceeds 8 KiB")
            raise ValueError("Frame too large")
        text_data = bytes_data.decode("utf-8")

    if not text_data:
        raise ValueError("Empty control frame")

    if len(text_data.encode("utf-8")) > settings.CONTROL_MAX_FRAME_BYTES:
        await ws.close(code=1009, reason="Control frame exceeds 8 KiB")
        raise ValueError("Frame too large")

    try:
        data = json.loads(text_data)
        if not isinstance(data, dict) or "type" not in data:
            raise ValueError("Malformed protocol message: missing 'type'")
        return data
    except json.JSONDecodeError as exc:
        await ws.close(code=1008, reason="Malformed JSON")
        raise ValueError("Malformed JSON") from exc


async def authenticate_peer(
    ws: WebSocket,
    client_ip: str,
    redis_store: RedisStore,
    rate_limiter: RateLimiter,
) -> tuple[str, dict[str, Any]]:
    """Execute ECDSA challenge-response handshake over WebSocket.

    Returns:
        tuple[fingerprint, hello_metadata] upon successful authentication.
    """
    # 1. Rate-limit handshake attempts per client IP
    allowed = await rate_limiter.check_handshake(client_ip)
    if not allowed:
        await ws.send_text(
            AuthFailedMessage(reason="Handshake rate limit exceeded").model_dump_json()
        )
        await ws.close(code=1008, reason="Rate limit exceeded")
        raise PermissionError("Handshake rate limited")

    # 2. Receive HELLO message
    hello_raw = await receive_control_frame(ws)
    if hello_raw.get("type") != "HELLO":
        await ws.close(code=1008, reason="Expected HELLO message")
        raise ValueError("Expected HELLO")

    hello = HelloMessage.model_validate(hello_raw)

    # 3. Parse and validate EC P-256 public key
    try:
        pub_key = parse_ec_p256_public_key(hello.public_key)
        fingerprint = compute_peer_fingerprint(pub_key)
    except Exception as exc:
        await ws.send_text(
            AuthFailedMessage(reason=f"Invalid EC P-256 key: {exc}").model_dump_json()
        )
        await ws.close(code=1008, reason="Invalid public key")
        raise ValueError(f"Invalid key: {exc}") from exc

    # 4. Generate and store challenge nonce (30s TTL in Redis)
    nonce = generate_challenge_nonce(32)
    await redis_store.store_challenge_nonce(
        fingerprint=fingerprint,
        nonce_bytes=nonce,
        ttl_seconds=settings.CHALLENGE_TTL_SECONDS,
    )

    # 5. Send CHALLENGE to peer
    challenge = ChallengeMessage(
        nonce=encode_base64(nonce),
        fingerprint=fingerprint,
    )
    await ws.send_text(challenge.model_dump_json())

    # 6. Receive AUTH response
    auth_raw = await receive_control_frame(ws)
    if auth_raw.get("type") != "AUTH":
        await ws.close(code=1008, reason="Expected AUTH message")
        raise ValueError("Expected AUTH")

    auth = AuthMessage.model_validate(auth_raw)

    # 7. Atomically consume the nonce from Redis (prevents replay attacks)
    stored_nonce = await redis_store.consume_challenge_nonce(fingerprint)
    if not stored_nonce:
        await ws.send_text(
            AuthFailedMessage(reason="Challenge expired or already used").model_dump_json()
        )
        await ws.close(code=1008, reason="Challenge expired or replayed")
        raise PermissionError("Challenge expired")

    # 8. Verify signature
    try:
        sig_bytes = decode_base64(auth.signature)
    except Exception:
        await ws.close(code=1008, reason="Invalid signature encoding")
        raise ValueError("Invalid base64 signature")  # noqa: B904

    is_valid = verify_ecdsa_signature(
        public_key=pub_key,
        signature_bytes=sig_bytes,
        nonce_bytes=stored_nonce,
    )
    if not is_valid:
        await ws.send_text(
            AuthFailedMessage(reason="ECDSA signature verification failed").model_dump_json()
        )
        await ws.close(code=1008, reason="Authentication failed")
        raise PermissionError("Signature verification failed")

    # 9. Register presence in Redis & confirm authentication
    peer_meta = {
        "observed_endpoint": hello.observed_endpoint,
        "client_ip": client_ip,
    }
    await redis_store.set_presence(
        fingerprint=fingerprint,
        metadata=peer_meta,
        ttl_seconds=settings.PRESENCE_TTL_SECONDS,
    )

    await ws.send_text(AuthOkMessage(fingerprint=fingerprint).model_dump_json())
    return fingerprint, peer_meta


async def handle_control_session(
    websocket: WebSocket,
    client_ip: str,
    signaling_manager: SignalingManager,
    relay_manager: RelayManager,
    redis_store: RedisStore,
    rate_limiter: RateLimiter,
) -> None:
    """Maintain authenticated control session loop."""
    await websocket.accept()

    try:
        fingerprint, peer_meta = await authenticate_peer(
            ws=websocket,
            client_ip=client_ip,
            redis_store=redis_store,
            rate_limiter=rate_limiter,
        )
    except Exception as exc:
        logger.debug("control_auth_failed", client_ip=client_ip, error=str(exc))
        return

    await signaling_manager.register(fingerprint, websocket)

    try:
        while True:
            data = await receive_control_frame(websocket)
            msg_type = data.get("type")

            if msg_type == "PING":
                # Heartbeat keepalive: refresh Redis presence TTL
                await redis_store.refresh_presence(
                    fingerprint=fingerprint,
                    ttl_seconds=settings.PRESENCE_TTL_SECONDS,
                )
                await websocket.send_text(PongMessage().model_dump_json())

            elif msg_type == "CREATE_INVITE":
                # Rate limit invite creation per peer fingerprint
                if not await rate_limiter.check_invite(fingerprint):
                    await websocket.send_text(
                        ErrorMessage(
                            code="RATE_LIMITED",
                            message="Invite creation rate limit exceeded",
                        ).model_dump_json()
                    )
                    continue

                req = CreateInviteMessage.model_validate(data)
                code = generate_crockford_code(8)
                await redis_store.store_invite(
                    code=code,
                    creator_fingerprint=fingerprint,
                    endpoints=req.endpoints,
                    ttl_seconds=settings.INVITE_TTL_SECONDS,
                )
                await websocket.send_text(
                    InviteCreatedMessage(
                        code=code,
                        ttl=settings.INVITE_TTL_SECONDS,
                    ).model_dump_json()
                )

            elif msg_type == "CLAIM_INVITE":
                req_claim = ClaimInviteMessage.model_validate(data)
                clean_code = normalize_crockford_code(req_claim.code)
                invite = await redis_store.consume_invite(clean_code)

                if not invite:
                    await websocket.send_text(
                        ErrorMessage(
                            code="INVITE_NOT_FOUND",
                            message="Invite code is invalid or has expired",
                        ).model_dump_json()
                    )
                    continue

                creator_fp = invite["fingerprint"]
                if creator_fp == fingerprint:
                    await websocket.send_text(
                        ErrorMessage(
                            code="SELF_PAIRING",
                            message="Cannot pair with oneself",
                        ).model_dump_json()
                    )
                    continue

                creator_endpoints = invite.get("endpoints", [])
                claimer_presence = await redis_store.get_presence(fingerprint)
                claimer_endpoints = [claimer_presence] if claimer_presence else []

                # Deliver mutual PEER_MATCHED metadata to both peers
                await signaling_manager.send_to_peer(
                    fingerprint=creator_fp,
                    message=PeerMatchedMessage(
                        peer_fingerprint=fingerprint,
                        endpoints=claimer_endpoints,
                        role="creator",
                    ).model_dump(),
                )
                await websocket.send_text(
                    PeerMatchedMessage(
                        peer_fingerprint=creator_fp,
                        endpoints=creator_endpoints,
                        role="claimer",
                    ).model_dump_json()
                )

            elif msg_type in ("SIGNAL_OFFER", "SIGNAL_ANSWER", "HOLE_PUNCH_SYNC"):
                # Forward ICE / hole-punching signaling to target peer
                target_fp = data.get("target_fingerprint")
                if not target_fp or not isinstance(target_fp, str):
                    err_msg = ErrorMessage(
                        code="INVALID_TARGET",
                        message="Missing target_fingerprint",
                    )
                    await websocket.send_text(err_msg.model_dump_json())
                    continue

                payload = dict(data)
                payload["from_fingerprint"] = fingerprint
                delivered = await signaling_manager.send_to_peer(target_fp, payload)
                if not delivered:
                    await websocket.send_text(
                        ErrorMessage(
                            code="PEER_OFFLINE",
                            message="Target peer is not currently connected",
                        ).model_dump_json()
                    )

            elif msg_type == "CREATE_RELAY":
                # Rate limit relay session creation per fingerprint
                if not await rate_limiter.check_relay(fingerprint):
                    await websocket.send_text(
                        ErrorMessage(
                            code="RATE_LIMITED",
                            message="Relay creation rate limit exceeded",
                        ).model_dump_json()
                    )
                    continue

                req_relay = CreateRelayMessage.model_validate(data)
                target_fp = req_relay.target_fingerprint

                session_id = secrets.token_hex(16)
                initiator_token = secrets.token_urlsafe(24)
                responder_token = secrets.token_urlsafe(24)

                await relay_manager.create_session(
                    session_id=session_id,
                    initiator_fp=fingerprint,
                    responder_fp=target_fp,
                    initiator_token=initiator_token,
                    responder_token=responder_token,
                )

                # Send invitation to target peer if connected
                await signaling_manager.send_to_peer(
                    fingerprint=target_fp,
                    message=RelayInviteMessage(
                        session_id=session_id,
                        from_fingerprint=fingerprint,
                        token=responder_token,
                    ).model_dump(),
                )

                # Reply to initiator with session details
                await websocket.send_text(
                    RelayCreatedMessage(
                        session_id=session_id,
                        token=initiator_token,
                    ).model_dump_json()
                )

            else:
                await websocket.send_text(
                    ErrorMessage(
                        code="UNKNOWN_MESSAGE",
                        message=f"Unsupported message type: {msg_type}",
                    ).model_dump_json()
                )

    except (WebSocketDisconnect, ConnectionResetError):
        logger.debug("control_peer_disconnected", fingerprint=fingerprint)
    except Exception as exc:
        logger.warning("control_session_error", fingerprint=fingerprint, error=str(exc))
    finally:
        await signaling_manager.unregister(fingerprint, websocket)
        await redis_store.remove_presence(fingerprint)
