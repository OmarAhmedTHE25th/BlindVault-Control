"""Test fixtures for BlindVault Control Plane tests."""

import asyncio
import socket
from collections.abc import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blindvault_control.crypto import compute_peer_fingerprint
from blindvault_control.main import app
from blindvault_control.rate_limiter import RateLimiter
from blindvault_control.redis_store import RedisStore
from blindvault_control.relay import RelayManager
from blindvault_control.signaling import SignalingManager


def get_free_port() -> int:
    """Find an available unallocated TCP/UDP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


EcKeyPair = tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, str, str]


@pytest.fixture
def ec_p256_keypair() -> EcKeyPair:
    """Generate an ephemeral EC P-256 keypair for testing."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    fingerprint = compute_peer_fingerprint(pub)
    return priv, pub, pem, fingerprint


@pytest.fixture
def second_ec_p256_keypair() -> EcKeyPair:
    """Generate a second ephemeral EC P-256 keypair for paired testing."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    fingerprint = compute_peer_fingerprint(pub)
    return priv, pub, pem, fingerprint


@pytest.fixture
def wrong_curve_secp256k1_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate an EC keypair using SECP256K1 (Bitcoin curve) which must be rejected."""
    priv = ec.generate_private_key(ec.SECP256K1())
    pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return priv, pem


@pytest_asyncio.fixture
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """In-memory Redis instance with full Lua script support for tests."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def redis_store(fake_redis: fakeredis.aioredis.FakeRedis) -> AsyncGenerator[RedisStore, None]:
    """RedisStore backed by in-memory FakeRedis."""
    store = RedisStore(client=fake_redis)
    yield store
    await store.close()


@pytest_asyncio.fixture
async def rate_limiter(fake_redis: fakeredis.aioredis.FakeRedis) -> RateLimiter:
    """RateLimiter backed by FakeRedis."""
    return RateLimiter(client=fake_redis)


@pytest_asyncio.fixture
async def live_server(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[tuple[str, int], None]:
    """Spin up an in-process live FastAPI server for real WebSocket network testing."""
    port = get_free_port()

    # Bind state to test's fake_redis
    test_redis_store = RedisStore(client=fake_redis)
    test_rate_limiter = RateLimiter(fake_redis)
    test_signaling = SignalingManager()
    test_relay = RelayManager(test_redis_store)

    app.state.redis_store = test_redis_store
    app.state.rate_limiter = test_rate_limiter
    app.state.signaling_manager = test_signaling
    app.state.relay_manager = test_relay

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        ws_max_size=131072,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())

    # Wait until server is listening
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.02)

    base_url = f"ws://127.0.0.1:{port}"
    try:
        yield base_url, port
    finally:
        server.should_exit = True
        await task
        await test_redis_store.close()
