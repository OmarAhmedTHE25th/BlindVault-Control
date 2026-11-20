"""FastAPI application lifespan, UDP server startup, and WebSocket routers."""

import asyncio
import re
import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, Query, WebSocket, status
from fastapi.responses import JSONResponse

from blindvault_control import __version__
from blindvault_control.config import settings
from blindvault_control.rate_limiter import RateLimiter
from blindvault_control.redis_store import RedisStore
from blindvault_control.relay import RelayManager, handle_relay_connection
from blindvault_control.signaling import SignalingManager, handle_control_session
from blindvault_control.udp_reflector import start_udp_reflector

# Regexes for IPv4 and IPv6 scrubbing in logs
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{0,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,4}\b|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|"
    r"::1\b|::\b"
)


def ip_scrubbing_processor(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Scrub IPv4 and IPv6 addresses from log event dictionaries when
    SCRUB_IPS_IN_LOGS is active.
    """
    if not settings.SCRUB_IPS_IN_LOGS:
        return event_dict

    for k, v in list(event_dict.items()):
        if k in ("client_ip", "host", "peer_ip", "ip"):
            event_dict[k] = "[REDACTED_IP]"
        elif isinstance(v, str):
            v_scrubbed = IPV4_REGEX.sub("[REDACTED_IP]", v)
            event_dict[k] = IPV6_REGEX.sub("[REDACTED_IP]", v_scrubbed)
    return event_dict


def configure_logging() -> None:
    """Configure structured JSON logging with optional PII/IP scrubbing."""
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        ip_scrubbing_processor,
        structlog.processors.JSONRenderer(),
    ]

    structlog.configure(
        processors=processors,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initialize Redis, managers, and the async UDP server."""
    configure_logging()
    logger.info("blindvault_control_starting", version=__version__)

    # 1. State & Managers
    redis_store = getattr(app.state, "redis_store", None)
    if redis_store is None:
        redis_store = RedisStore()
        app.state.redis_store = redis_store

    rate_limiter = getattr(app.state, "rate_limiter", None)
    if rate_limiter is None:
        rate_limiter = RateLimiter(redis_store.client)
        app.state.rate_limiter = rate_limiter

    signaling_manager = getattr(app.state, "signaling_manager", None)
    if signaling_manager is None:
        signaling_manager = SignalingManager()
        app.state.signaling_manager = signaling_manager

    relay_manager = getattr(app.state, "relay_manager", None)
    if relay_manager is None:
        relay_manager = RelayManager(redis_store)
        app.state.relay_manager = relay_manager

    # 2. Check UDP secret configuration
    udp_secret = settings.UDP_SECRET
    if not udp_secret:
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(
                "BLINDVAULT_UDP_SECRET must be explicitly configured in production environment."
            )
        udp_secret = secrets.token_hex(32)
        logger.warning(
            "udp_secret_auto_generated",
            reason=(
                "BLINDVAULT_UDP_SECRET is not configured; ephemeral secret generated. "
                "Reflections will be invalidated across restarts."
            ),
        )

    # 3. Start UDP endpoint reflector
    udp_transport: asyncio.DatagramTransport | None = None
    try:
        udp_transport, _ = await start_udp_reflector(
            host=settings.UDP_HOST,
            port=settings.UDP_PORT,
            secret=udp_secret,
        )
        app.state.udp_transport = udp_transport
        logger.info(
            "udp_reflector_listening",
            host=settings.UDP_HOST,
            port=settings.UDP_PORT,
        )
    except Exception as exc:
        logger.error("udp_reflector_startup_failed", error=str(exc))

    yield

    # 4. Teardown
    if udp_transport is not None:
        udp_transport.close()
        logger.info("udp_reflector_stopped")

    await redis_store.close()
    logger.info("blindvault_control_stopped")


app = FastAPI(
    title="BlindVault Control Plane",
    description=(
        "Zero-knowledge NAT-traversal signaling server and encrypted fallback relay for BlindVault"
    ),
    version=__version__,
    lifespan=lifespan,
)


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> JSONResponse:
    """Liveness probe returning basic service operational status."""
    return JSONResponse(
        {
            "status": "healthy",
            "service": "blindvault-control",
            "version": __version__,
        }
    )


@app.get("/ready")
async def readiness_check() -> JSONResponse:
    """Readiness probe checking Redis connectivity and UDP reflector."""
    redis_store: RedisStore | None = getattr(app.state, "redis_store", None)
    redis_ok = False
    if redis_store is not None:
        try:
            redis_ok = bool(await redis_store.client.ping())
        except Exception as exc:
            logger.warning("readiness_redis_check_failed", error=str(exc))

    udp_transport: asyncio.DatagramTransport | None = getattr(app.state, "udp_transport", None)
    udp_ok = bool(udp_transport is not None and not udp_transport.is_closing())

    if not redis_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "redis": redis_ok,
                "udp_reflector": udp_ok,
            },
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "ready",
            "redis": redis_ok,
            "udp_reflector": udp_ok,
        },
    )


@app.get("/api/v1/info", status_code=status.HTTP_200_OK)
async def service_info() -> JSONResponse:
    """Public parameters for peer client configuration."""
    return JSONResponse(
        {
            "version": __version__,
            "udp_reflector_port": settings.UDP_PORT,
            "supported_curves": ["secp256r1"],
            "max_relay_frame_bytes": settings.RELAY_MAX_FRAME_BYTES,
            "max_control_frame_bytes": settings.CONTROL_MAX_FRAME_BYTES,
        }
    )


@app.websocket("/ws/control")
async def websocket_control_endpoint(websocket: WebSocket) -> None:
    """WebSocket control channel for peer authentication, heartbeat, and signaling."""
    client_host = websocket.client.host if websocket.client else "unknown"

    signaling_manager: SignalingManager = app.state.signaling_manager
    relay_manager: RelayManager = app.state.relay_manager
    redis_store: RedisStore = app.state.redis_store
    rate_limiter: RateLimiter = app.state.rate_limiter

    await handle_control_session(
        websocket=websocket,
        client_ip=client_host,
        signaling_manager=signaling_manager,
        relay_manager=relay_manager,
        redis_store=redis_store,
        rate_limiter=rate_limiter,
    )


@app.websocket("/ws/relay/{session_id}")
async def websocket_relay_endpoint(
    websocket: WebSocket,
    session_id: str,
    token: str | None = Query(None),
) -> None:
    """Zero-knowledge encrypted fallback relay bridge for opaque mutual TLS streams."""
    # Move token to header (Authorization: Bearer ..., X-Relay-Token) or Sec-WebSocket-Protocol
    effective_token = token
    auth_header = websocket.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        effective_token = auth_header[7:].strip()
    elif "x-relay-token" in websocket.headers:
        effective_token = websocket.headers["x-relay-token"]
    elif not effective_token and "sec-websocket-protocol" in websocket.headers:
        subprotocols = [p.strip() for p in websocket.headers["sec-websocket-protocol"].split(",")]
        for proto in subprotocols:
            if proto.startswith("token-"):
                effective_token = proto[6:]
                break

    if not effective_token:
        await websocket.close(code=1008, reason="Missing relay token in headers or query")
        return

    relay_manager: RelayManager = app.state.relay_manager
    await handle_relay_connection(
        websocket=websocket,
        session_id=session_id,
        token=effective_token,
        relay_manager=relay_manager,
    )


def run() -> None:
    """CLI runner entry point."""
    uvicorn.run(
        "blindvault_control.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL.lower(),
        ws_max_size=settings.RELAY_MAX_FRAME_BYTES * 2,
    )


if __name__ == "__main__":
    run()
