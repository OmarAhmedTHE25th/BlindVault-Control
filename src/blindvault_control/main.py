"""FastAPI application lifespan, UDP server startup, and WebSocket routers."""

import asyncio
import re
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

# Regex for IPv4 scrubbing in logs
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def ip_scrubbing_processor(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Scrub IP addresses from log event dictionaries when SCRUB_IPS_IN_LOGS is active."""
    if not settings.SCRUB_IPS_IN_LOGS:
        return event_dict

    for k, v in list(event_dict.items()):
        if isinstance(v, str):
            event_dict[k] = IPV4_REGEX.sub("[REDACTED_IP]", v)
        elif k in ("client_ip", "host", "peer_ip"):
            event_dict[k] = "[REDACTED_IP]"
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

    # 2. Start UDP endpoint reflector
    udp_transport: asyncio.DatagramTransport | None = None
    try:
        udp_transport, _ = await start_udp_reflector(
            host=settings.UDP_HOST,
            port=settings.UDP_PORT,
            secret=settings.UDP_SECRET,
        )
        logger.info(
            "udp_reflector_listening",
            host=settings.UDP_HOST,
            port=settings.UDP_PORT,
        )
    except Exception as exc:
        logger.error("udp_reflector_startup_failed", error=str(exc))

    yield

    # 3. Teardown
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
    """Zero-knowledge health check returning service status."""
    return JSONResponse(
        {
            "status": "healthy",
            "service": "blindvault-control",
            "version": __version__,
        }
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
    token: str = Query(...),
) -> None:
    """Zero-knowledge encrypted fallback relay bridge for opaque mutual TLS streams."""
    relay_manager: RelayManager = app.state.relay_manager
    await handle_relay_connection(
        websocket=websocket,
        session_id=session_id,
        token=token,
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
