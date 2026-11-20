"""Bounded zero-knowledge encrypted WebSocket fallback relay with Redis Pub/Sub bridging."""

import asyncio
import base64
import contextlib
import secrets
import time
from typing import Any

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
        """Launch dedicated bridge task once both peers are attached locally."""
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
        """Execute bidirectional stream piping between locally attached peers."""
        ws_a = self.ws_initiator
        ws_b = self.ws_responder
        if not ws_a or not ws_b:
            self.closed_event.set()
            return

        pipe_a = asyncio.create_task(pipe_stream(ws_a, ws_b, direction="initiator_to_responder"))
        pipe_b = asyncio.create_task(pipe_stream(ws_b, ws_a, direction="responder_to_initiator"))

        try:
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
            for ws in (ws_a, ws_b):
                with contextlib.suppress(Exception):
                    await ws.close(code=1000, reason="Relay session finished")
            await relay_manager.cleanup_session(self.session_id)
            logger.info("relay_session_terminated", session_id=self.session_id)


class RelayManager:
    """In-memory and Redis-coordinated manager for zero-knowledge relay sessions."""

    def __init__(self, redis_store: RedisStore) -> None:
        self.redis_store = redis_store
        self.instance_id = secrets.token_hex(8)
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
        await self.redis_store.client.delete(f"relay_drdy:{session_id}")


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
            raw_msg = await asyncio.wait_for(
                src.receive(),
                timeout=float(idle_timeout),
            )

            msg_type = raw_msg.get("type")
            if msg_type == "websocket.disconnect":
                break

            bytes_data: bytes | None = raw_msg.get("bytes")
            text_data: str | None = raw_msg.get("text")

            if text_data is not None:
                logger.warning("relay_text_frame_rejected", direction=direction)
                await src.close(code=1003, reason="Unsupported Data: binary frames only")
                break

            if bytes_data is not None:
                if len(bytes_data) > max_frame_bytes:
                    logger.warning("relay_frame_too_large", size=len(bytes_data))
                    await src.close(code=1009, reason="Frame exceeds 64 KiB")
                    break
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


async def bridge_via_redis_pubsub(
    websocket: WebSocket,
    session_id: str,
    role: str,
    relay_manager: RelayManager,
    ctrl_pubsub: Any,
    ctrl_channel: str,
    idle_timeout: int = settings.RELAY_IDLE_TIMEOUT_SECONDS,
    max_frame_bytes: int = settings.RELAY_MAX_FRAME_BYTES,
) -> None:
    """Bridge binary relay frames between two replicas over Redis Pub/Sub."""
    other_role = "responder" if role == "initiator" else "initiator"
    in_chan = f"bv:relay:{session_id}:b2a" if role == "initiator" else f"bv:relay:{session_id}:a2b"
    out_chan = f"bv:relay:{session_id}:a2b" if role == "initiator" else f"bv:relay:{session_id}:b2a"

    data_pubsub = relay_manager.redis_store.create_pubsub()
    await data_pubsub.subscribe(in_chan)

    try:
        # Synchronize readiness so neither replica publishes frames before the other subscribes
        drdy_key = f"relay_drdy:{session_id}"
        await relay_manager.redis_store.client.hset(drdy_key, role, "1")
        await relay_manager.redis_store.client.expire(drdy_key, settings.RELAY_MAX_SESSION_SECONDS)
        await relay_manager.redis_store.publish(ctrl_channel, f"DRDY:{role}")

        deadline = time.monotonic() + float(settings.RELAY_TOKEN_TTL_SECONDS)
        while time.monotonic() < deadline:
            flag = await relay_manager.redis_store.client.hget(drdy_key, other_role)
            if flag == "1":
                break
            msg = await ctrl_pubsub.get_message(ignore_subscribe_messages=True, timeout=0.05)
            if msg and msg.get("type") == "message":
                payload = str(msg.get("data", ""))
                if payload == f"DRDY:{other_role}":
                    break
                if payload == "ABORT":
                    return

        with contextlib.suppress(Exception):
            await ctrl_pubsub.unsubscribe(ctrl_channel)
            await ctrl_pubsub.aclose()

        async def ws_to_redis() -> None:
            try:
                while True:
                    raw_msg = await asyncio.wait_for(
                        websocket.receive(),
                        timeout=float(idle_timeout),
                    )
                    if raw_msg.get("type") == "websocket.disconnect":
                        break
                    text_data: str | None = raw_msg.get("text")
                    if text_data is not None:
                        logger.warning("relay_text_frame_rejected", direction=f"{role}_to_pubsub")
                        await websocket.close(
                            code=1003,
                            reason="Unsupported Data: binary frames only",
                        )
                        break
                    bytes_data: bytes | None = raw_msg.get("bytes")
                    if bytes_data is not None:
                        if len(bytes_data) > max_frame_bytes:
                            await websocket.close(code=1009, reason="Frame exceeds 64 KiB")
                            break
                        encoded = "D:" + base64.b64encode(bytes_data).decode("ascii")
                        await relay_manager.redis_store.publish(out_chan, encoded)
            except (TimeoutError, WebSocketDisconnect, ConnectionResetError):
                pass
            except Exception as exc:
                logger.debug("relay_pubsub_tx_error", role=role, error=str(exc))
            finally:
                with contextlib.suppress(Exception):
                    await relay_manager.redis_store.publish(out_chan, "C")

        async def redis_to_ws() -> None:
            last_activity = time.monotonic()
            try:
                while True:
                    msg = await data_pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=0.05,
                    )
                    if msg is None:
                        if (time.monotonic() - last_activity) > float(idle_timeout):
                            break
                        continue
                    if msg.get("type") != "message":
                        continue
                    raw_data = msg.get("data")
                    text = (
                        raw_data.decode("utf-8") if isinstance(raw_data, bytes) else str(raw_data)
                    )
                    if text == "C":
                        break
                    if text.startswith("D:"):
                        last_activity = time.monotonic()
                        chunk = base64.b64decode(text[2:])
                        await asyncio.wait_for(
                            websocket.send_bytes(chunk),
                            timeout=float(idle_timeout),
                        )
            except (TimeoutError, WebSocketDisconnect, ConnectionResetError):
                pass
            except Exception as exc:
                logger.debug("relay_pubsub_rx_error", role=role, error=str(exc))

        tx_task = asyncio.create_task(ws_to_redis())
        rx_task = asyncio.create_task(redis_to_ws())

        done, pending = await asyncio.wait(
            [tx_task, rx_task],
            timeout=float(settings.RELAY_MAX_SESSION_SECONDS),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    finally:
        with contextlib.suppress(Exception):
            await data_pubsub.unsubscribe(in_chan)
            await data_pubsub.aclose()
        with contextlib.suppress(Exception):
            await websocket.close(code=1000, reason="Relay session finished")
        await relay_manager.cleanup_session(session_id)
        logger.info("relay_pubsub_session_terminated", session_id=session_id, role=role)


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
    except Exception as exc:
        logger.warning("relay_attach_rejected", error=str(exc))
        await websocket.close(code=1008, reason="Invalid relay token")
        return

    other_role = "responder" if role == "initiator" else "initiator"
    ctrl_channel = f"bv:relay:{session_id}:ctrl"
    ctrl_pubsub = relay_manager.redis_store.create_pubsub()
    await ctrl_pubsub.subscribe(ctrl_channel)

    claimed = await relay_manager.redis_store.claim_relay_slot(
        session_id=session_id,
        role=role,
        instance_id=relay_manager.instance_id,
        ttl_seconds=settings.RELAY_MAX_SESSION_SECONDS,
    )
    if not claimed:
        await session.detach_peer(role)
        with contextlib.suppress(Exception):
            await ctrl_pubsub.unsubscribe(ctrl_channel)
            await ctrl_pubsub.aclose()
        await websocket.close(code=1008, reason="Relay slot already attached elsewhere")
        return

    logger.debug(
        "relay_peer_attached",
        session_id=session_id,
        role=role,
        instance=relay_manager.instance_id,
    )
    await relay_manager.redis_store.publish(
        ctrl_channel, f"JOIN:{role}:{relay_manager.instance_id}"
    )

    other_instance: str | None = None
    aborted = False

    async def wait_for_disconnect() -> None:
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
        except (WebSocketDisconnect, ConnectionResetError):
            pass

    async def wait_ctrl_join() -> str | None:
        while True:
            slots = await relay_manager.redis_store.get_relay_slots(session_id)
            if other_role in slots:
                return slots[other_role]
            msg = await ctrl_pubsub.get_message(ignore_subscribe_messages=True, timeout=0.05)
            if msg and msg.get("type") == "message":
                payload = str(msg.get("data", ""))
                if payload == "ABORT":
                    return "__ABORT__"
                prefix = f"JOIN:{other_role}:"
                if payload.startswith(prefix):
                    return payload.removeprefix(prefix)

    disconnect_task = asyncio.create_task(wait_for_disconnect())
    ctrl_task = asyncio.create_task(wait_ctrl_join())

    try:
        done, pending = await asyncio.wait(
            [ctrl_task, disconnect_task],
            timeout=float(settings.RELAY_TOKEN_TTL_SECONDS),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

        if disconnect_task in done or ctrl_task not in done:
            aborted = True
        else:
            res = ctrl_task.result()
            if res is None or res == "__ABORT__":
                aborted = True
            else:
                other_instance = res
    except Exception:
        aborted = True

    if aborted or other_instance is None:
        logger.info("relay_rendezvous_aborted", session_id=session_id, role=role)
        await relay_manager.redis_store.publish(ctrl_channel, "ABORT")
        with contextlib.suppress(Exception):
            await ctrl_pubsub.unsubscribe(ctrl_channel)
            await ctrl_pubsub.aclose()
        await session.detach_peer(role)
        with contextlib.suppress(Exception):
            await websocket.close(code=1000, reason="Peer failed to join relay session")
        await relay_manager.cleanup_session(session_id)
        return

    if other_instance == relay_manager.instance_id:
        # Both peers are on this replica -> fast in-memory direct bridge
        with contextlib.suppress(Exception):
            await ctrl_pubsub.unsubscribe(ctrl_channel)
            await ctrl_pubsub.aclose()
        try:
            await asyncio.wait_for(session.ready_event.wait(), timeout=2.0)
        except TimeoutError:
            await session.detach_peer(role)
            with contextlib.suppress(Exception):
                await websocket.close(code=1000, reason="Local peer attachment timeout")
            await relay_manager.cleanup_session(session_id)
            return

        session.start_bridge_if_ready(relay_manager)
        await session.closed_event.wait()
        return

    # Peers are on different replicas -> cross-replica Redis Pub/Sub bridge
    await bridge_via_redis_pubsub(
        websocket=websocket,
        session_id=session_id,
        role=role,
        relay_manager=relay_manager,
        ctrl_pubsub=ctrl_pubsub,
        ctrl_channel=ctrl_channel,
    )
