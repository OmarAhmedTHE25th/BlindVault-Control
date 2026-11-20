"""Bounded zero-knowledge encrypted WebSocket fallback relay with backpressure."""

import asyncio
import contextlib

import structlog
from fastapi import WebSocket, WebSocketDisconnect

from blindvault_control.config import settings
from blindvault_control.redis_store import RedisStore

logger = structlog.get_logger()


class RelaySession:
    """Manages an active two-party encrypted streaming relay bridge."""

    def __init__(
        self,
        session_id: str,
        initiator_fp: str,
        responder_fp: str,
        initiator_token: str,
        responder_token: str,
    ) -> None:
        self.session_id = session_id
        self.initiator_fp = initiator_fp
        self.responder_fp = responder_fp
        self.initiator_token = initiator_token
        self.responder_token = responder_token

        self.ws_initiator: WebSocket | None = None
        self.ws_responder: WebSocket | None = None

        self.ready_event = asyncio.Event()
        self.closed_event = asyncio.Event()
        self._lock = asyncio.Lock()

    async def attach_peer(self, ws: WebSocket, token: str) -> str:
        """Attach an incoming WebSocket connection after validating its role token."""
        async with self._lock:
            if token == self.initiator_token and self.ws_initiator is None:
                self.ws_initiator = ws
                role = "initiator"
            elif token == self.responder_token and self.ws_responder is None:
                self.ws_responder = ws
                role = "responder"
            else:
                raise ValueError("Invalid or duplicate relay token for session")

            if self.ws_initiator is not None and self.ws_responder is not None:
                self.ready_event.set()

            return role


class RelayManager:
    """In-memory coordinator for live zero-knowledge relay sessions."""

    def __init__(self, redis_store: RedisStore) -> None:
        self.redis_store = redis_store
        self.sessions: dict[str, RelaySession] = {}
        self._lock = asyncio.Lock()

    async def create_session(
        self,
        session_id: str,
        initiator_fp: str,
        responder_fp: str,
        initiator_token: str,
        responder_token: str,
    ) -> RelaySession:
        """Create and register a relay session in Redis and local memory."""
        session = RelaySession(
            session_id=session_id,
            initiator_fp=initiator_fp,
            responder_fp=responder_fp,
            initiator_token=initiator_token,
            responder_token=responder_token,
        )
        async with self._lock:
            self.sessions[session_id] = session

        await self.redis_store.store_relay_session(
            session_id=session_id,
            initiator_fp=initiator_fp,
            responder_fp=responder_fp,
            initiator_token=initiator_token,
            responder_token=responder_token,
            ttl_seconds=settings.RELAY_TOKEN_TTL_SECONDS,
        )
        return session

    async def get_or_restore_session(self, session_id: str) -> RelaySession | None:
        """Retrieve existing in-memory session or restore from Redis."""
        async with self._lock:
            if session_id in self.sessions:
                return self.sessions[session_id]

        redis_data = await self.redis_store.get_relay_session(session_id)
        if not redis_data:
            return None

        async with self._lock:
            if session_id in self.sessions:
                return self.sessions[session_id]

            session = RelaySession(
                session_id=session_id,
                initiator_fp=redis_data["initiator_fp"],
                responder_fp=redis_data["responder_fp"],
                initiator_token=redis_data["initiator_token"],
                responder_token=redis_data["responder_token"],
            )
            self.sessions[session_id] = session
            return session

    async def cleanup_session(self, session_id: str) -> None:
        """Remove relay session from memory and Redis."""
        async with self._lock:
            session = self.sessions.pop(session_id, None)

        if session:
            session.closed_event.set()

        await self.redis_store.delete_relay_session(session_id)


async def pipe_stream(
    src: WebSocket,
    dst: WebSocket,
    direction: str,
    idle_timeout: int = settings.RELAY_IDLE_TIMEOUT_SECONDS,
    max_frame_bytes: int = settings.RELAY_MAX_FRAME_BYTES,
) -> None:
    """Non-blocking stream pipe with backpressure and oversized frame guards."""
    try:
        while True:
            # Enforce 30-second idle timeout between chunks
            raw_msg = await asyncio.wait_for(
                src.receive(),
                timeout=float(idle_timeout),
            )

            msg_type = raw_msg.get("type")
            if msg_type == "websocket.disconnect":
                break

            bytes_data: bytes | None = raw_msg.get("bytes")
            text_data: str | None = raw_msg.get("text")

            if bytes_data is not None:
                if len(bytes_data) > max_frame_bytes:
                    logger.warning("relay_frame_too_large", size=len(bytes_data))
                    await src.close(code=1009, reason="Frame exceeds 64 KiB")
                    break
                # Backpressure: non-blocking await until dst buffer accepts chunk
                await dst.send_bytes(bytes_data)

            elif text_data is not None:
                encoded = text_data.encode("utf-8")
                if len(encoded) > max_frame_bytes:
                    logger.warning("relay_text_frame_too_large", size=len(encoded))
                    await src.close(code=1009, reason="Frame exceeds 64 KiB")
                    break
                await dst.send_text(text_data)

    except TimeoutError:
        logger.debug("relay_idle_timeout", direction=direction)
    except (WebSocketDisconnect, ConnectionResetError):
        logger.debug("relay_peer_disconnected", direction=direction)
    except Exception as exc:
        logger.debug("relay_pipe_error", direction=direction, error=str(exc))


async def handle_relay_connection(
    websocket: WebSocket,
    session_id: str,
    token: str,
    relay_manager: RelayManager,
) -> None:
    """Handle incoming WebSocket on /ws/relay/{session_id}?token=..."""
    session = await relay_manager.get_or_restore_session(session_id)
    if not session:
        await websocket.close(code=1008, reason="Relay session not found or expired")
        return

    try:
        await websocket.accept()
        role = await session.attach_peer(websocket, token)
        logger.debug("relay_peer_attached", session_id=session_id, role=role)
    except Exception as exc:
        logger.warning("relay_attach_rejected", error=str(exc))
        await websocket.close(code=1008, reason="Invalid relay token")
        return

    # Wait for the counterpart peer to connect within token TTL window
    try:
        await asyncio.wait_for(
            session.ready_event.wait(),
            timeout=float(settings.RELAY_TOKEN_TTL_SECONDS),
        )
    except TimeoutError:
        logger.info("relay_rendezvous_timed_out", session_id=session_id)
        await websocket.close(code=1000, reason="Peer failed to join relay session")
        await relay_manager.cleanup_session(session_id)
        return

    # Only run the bridge workers once (the second attached peer or initiator)
    if role == "initiator":
        # Keep initiator connection alive while responder runs bridge, or vice versa
        await session.closed_event.wait()
        return

    # Responder triggers the bidirectional bridge tasks
    ws_a = session.ws_initiator
    ws_b = session.ws_responder
    if not ws_a or not ws_b:
        return

    pipe_a = asyncio.create_task(pipe_stream(ws_a, ws_b, direction="initiator_to_responder"))
    pipe_b = asyncio.create_task(pipe_stream(ws_b, ws_a, direction="responder_to_initiator"))

    try:
        # Enforce maximum session duration (default 15 minutes)
        done, pending = await asyncio.wait(
            [pipe_a, pipe_b],
            timeout=float(settings.RELAY_MAX_SESSION_SECONDS),
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

    finally:
        session.closed_event.set()
        # Clean teardown of both sides
        for ws in (ws_a, ws_b):
            with contextlib.suppress(Exception):
                await ws.close(code=1000, reason="Relay session finished")
        await relay_manager.cleanup_session(session_id)
        logger.info("relay_session_terminated", session_id=session_id)
