"""Bounded zero-knowledge encrypted WebSocket fallback relay with backpressure."""

import asyncio
import contextlib
import time

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
        self.created_at = time.time()

        self.ws_initiator: WebSocket | None = None
        self.ws_responder: WebSocket | None = None

        self.ready_event = asyncio.Event()
        self.closed_event = asyncio.Event()
        self._bridge_started = False
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

    async def detach_peer(self, role: str) -> None:
        """Detach peer on early disconnect before bridge establishment."""
        async with self._lock:
            if role == "initiator":
                self.ws_initiator = None
            elif role == "responder":
                self.ws_responder = None
            self.ready_event.clear()

    def start_bridge_if_ready(self, relay_manager: "RelayManager") -> bool:
        """Launch dedicated bridge task once both peers are attached."""
        if (
            not self._bridge_started
            and self.ws_initiator is not None
            and self.ws_responder is not None
        ):
            self._bridge_started = True
            asyncio.create_task(self._run_bridge(relay_manager))
            return True
        return False

    async def _run_bridge(self, relay_manager: "RelayManager") -> None:
        """Execute bidirectional stream piping between attached peers."""
        ws_a = self.ws_initiator
        ws_b = self.ws_responder
        if not ws_a or not ws_b:
            self.closed_event.set()
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
                await asyncio.gather(*pending, return_exceptions=True)
        finally:
            self.closed_event.set()
            # Clean teardown of both sides
            for ws in (ws_a, ws_b):
                with contextlib.suppress(Exception):
                    await ws.close(code=1000, reason="Relay session finished")
            await relay_manager.cleanup_session(self.session_id)
            logger.info("relay_session_terminated", session_id=self.session_id)


class RelayManager:
    """In-memory coordinator for live zero-knowledge relay sessions."""

    def __init__(self, redis_store: RedisStore) -> None:
        self.redis_store = redis_store
        self.sessions: dict[str, RelaySession] = {}
        self._lock = asyncio.Lock()

    async def prune_stale_sessions(self) -> None:
        """Prune unattached sessions older than token TTL."""
        now = time.time()
        cutoff = float(settings.RELAY_TOKEN_TTL_SECONDS * 2)
        async with self._lock:
            stale_ids = [
                sid
                for sid, s in self.sessions.items()
                if not s.ready_event.is_set() and (now - s.created_at) > cutoff
            ]
            for sid in stale_ids:
                del self.sessions[sid]

    async def create_session(
        self,
        session_id: str,
        initiator_fp: str,
        responder_fp: str,
        initiator_token: str,
        responder_token: str,
    ) -> RelaySession:
        """Create and register a relay session in Redis and local memory."""
        await self.prune_stale_sessions()
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
        await self.prune_stale_sessions()
        async with self._lock:
            if session_id in self.sessions:
                return self.sessions[session_id]

        redis_data = await self.redis_store.get_relay_session(session_id)
        if not redis_data:
            async with self._lock:
                orphaned = self.sessions.pop(session_id, None)
                if orphaned:
                    orphaned.closed_event.set()
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
    """Non-blocking stream pipe with backpressure and oversized frame guards.

    Enforces binary-only communication. Rejects text frames with code 1003.
    """
    try:
        while True:
            # Enforce 30-second idle timeout between chunks on read side
            raw_msg = await asyncio.wait_for(
                src.receive(),
                timeout=float(idle_timeout),
            )

            msg_type = raw_msg.get("type")
            if msg_type == "websocket.disconnect":
                break

            bytes_data: bytes | None = raw_msg.get("bytes")
            text_data: str | None = raw_msg.get("text")

            # Binary-only enforcement (RFC 6455 1003 Unsupported Data)
            if text_data is not None:
                logger.warning("relay_text_frame_rejected", direction=direction)
                await src.close(code=1003, reason="Unsupported Data: binary frames only")
                break

            if bytes_data is not None:
                if len(bytes_data) > max_frame_bytes:
                    logger.warning("relay_frame_too_large", size=len(bytes_data))
                    await src.close(code=1009, reason="Frame exceeds 64 KiB")
                    break
                # Backpressure: wait for destination buffer with write timeout
                await asyncio.wait_for(
                    dst.send_bytes(bytes_data),
                    timeout=float(idle_timeout),
                )

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
    """Handle incoming WebSocket on /ws/relay/{session_id}."""
    # Origin validation for WebSocket
    origin = websocket.headers.get("origin")
    if origin and "*" not in settings.ALLOWED_ORIGINS and origin not in settings.ALLOWED_ORIGINS:
        logger.warning("origin_not_allowed", origin=origin)
        await websocket.close(code=1008, reason="Origin not allowed")
        return

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

    # Wait for the counterpart peer to connect, or for early disconnect
    async def wait_for_disconnect() -> None:
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
        except (WebSocketDisconnect, ConnectionResetError):
            pass

    disconnect_task = asyncio.create_task(wait_for_disconnect())
    ready_task = asyncio.create_task(session.ready_event.wait())

    try:
        done, pending = await asyncio.wait(
            [ready_task, disconnect_task],
            timeout=float(settings.RELAY_TOKEN_TTL_SECONDS),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()

        if disconnect_task in done:
            raise WebSocketDisconnect()
        if ready_task not in done:
            raise TimeoutError()
    except (TimeoutError, WebSocketDisconnect, Exception):
        logger.info("relay_rendezvous_aborted", session_id=session_id, role=role)
        await session.detach_peer(role)
        with contextlib.suppress(Exception):
            await websocket.close(code=1000, reason="Peer failed to join relay session")
        await relay_manager.cleanup_session(session_id)
        return

    # Once both peers are attached, launch dedicated bridge if not already running
    session.start_bridge_if_ready(relay_manager)

    # Both peers symmetrically wait for the session bridge to terminate
    await session.closed_event.wait()
