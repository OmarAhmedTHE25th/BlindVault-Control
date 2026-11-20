"""Tests for WebSocket authentication, nonce single-use, and presence lifecycle."""

import json
from typing import Any

import httpx
import pytest
import websockets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from blindvault_control.crypto import decode_base64, encode_base64


@pytest.mark.asyncio
async def test_successful_auth_and_heartbeat(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    redis_store: Any,
) -> None:
    base_ws_url, _ = live_server
    priv, _, pem, fp = ec_p256_keypair

    async with websockets.connect(f"{base_ws_url}/ws/control") as ws:
        # 1. Send HELLO
        await ws.send(
            json.dumps(
                {
                    "type": "HELLO",
                    "public_key": pem,
                    "observed_endpoint": "192.168.1.100:54321",
                }
            )
        )

        # 2. Receive CHALLENGE
        raw_challenge = await ws.recv()
        challenge_data = json.loads(raw_challenge)
        assert challenge_data["type"] == "CHALLENGE"
        assert challenge_data["fingerprint"] == fp

        nonce_bytes = decode_base64(challenge_data["nonce"])
        assert len(nonce_bytes) == 32

        # 3. Sign nonce and send AUTH
        signature = priv.sign(nonce_bytes, ec.ECDSA(hashes.SHA256()))
        await ws.send(
            json.dumps(
                {
                    "type": "AUTH",
                    "signature": encode_base64(signature),
                }
            )
        )

        # 4. Receive AUTH_OK
        raw_auth_ok = await ws.recv()
        auth_ok_data = json.loads(raw_auth_ok)
        assert auth_ok_data["type"] == "AUTH_OK"
        assert auth_ok_data["fingerprint"] == fp
        assert auth_ok_data["heartbeat_interval_sec"] == 20

        # 5. Verify presence recorded in Redis
        presence = await redis_store.get_presence(fp)
        assert presence is not None
        assert presence["observed_endpoint"] == "192.168.1.100:54321"

        # 6. Test PING / PONG heartbeat
        await ws.send(json.dumps({"type": "PING"}))
        raw_pong = await ws.recv()
        pong_data = json.loads(raw_pong)
        assert pong_data["type"] == "PONG"

    # 7. Verify presence is removed after disconnect
    presence_after = await redis_store.get_presence(fp)
    assert presence_after is None


@pytest.mark.asyncio
async def test_auth_invalid_signature_rejection(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    base_ws_url, _ = live_server
    _, _, pem, _ = ec_p256_keypair

    async with websockets.connect(f"{base_ws_url}/ws/control") as ws:
        await ws.send(
            json.dumps(
                {
                    "type": "HELLO",
                    "public_key": pem,
                }
            )
        )
        raw_challenge = await ws.recv()
        _ = json.loads(raw_challenge)

        # Send invalid signature (random junk)
        await ws.send(
            json.dumps(
                {
                    "type": "AUTH",
                    "signature": encode_base64(b"completely_fake_signature_bytes_12345"),
                }
            )
        )

        # Server should close or send AUTH_FAILED
        try:
            msg = await ws.recv()
            data = json.loads(msg)
            assert data["type"] == "AUTH_FAILED"
        except websockets.exceptions.ConnectionClosed:
            pass


@pytest.mark.asyncio
async def test_nonce_replay_protection(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    redis_store: Any,
) -> None:
    _, _, _, fp = ec_p256_keypair

    # Store a nonce in Redis directly
    await redis_store.store_challenge_nonce(fp, b"A" * 32, ttl_seconds=30)

    # First consumption succeeds
    first = await redis_store.consume_challenge_nonce(fp)
    assert first == b"A" * 32

    # Second consumption must return None (single-use guaranteed)
    second = await redis_store.consume_challenge_nonce(fp)
    assert second is None


@pytest.mark.asyncio
async def test_oversized_control_frame_rejection(
    live_server: tuple[str, int],
) -> None:
    base_ws_url, _ = live_server

    async with websockets.connect(f"{base_ws_url}/ws/control") as ws:
        # Send frame exceeding 8 KiB (e.g. 10 KiB)
        oversized = json.dumps({"type": "HELLO", "data": "X" * 10000})
        await ws.send(oversized)

        with pytest.raises(websockets.exceptions.ConnectionClosed) as exc_info:
            await ws.recv()
        assert exc_info.value.code == 1009


@pytest.mark.asyncio
async def test_readiness_probe(live_server: tuple[str, int]) -> None:
    _, port = live_server
    async with httpx.AsyncClient() as client:
        # Liveness
        resp_health = await client.get(f"http://127.0.0.1:{port}/health")
        assert resp_health.status_code == 200
        assert resp_health.json()["status"] == "healthy"

        # Readiness
        resp_ready = await client.get(f"http://127.0.0.1:{port}/ready")
        assert resp_ready.status_code == 200
        data = resp_ready.json()
        assert data["status"] == "ready"
        assert data["redis"] is True


@pytest.mark.asyncio
async def test_origin_validation_rejection(live_server: tuple[str, int]) -> None:
    base_ws_url, _ = live_server
    # Connecting with a disallowed browser origin must be rejected with HTTP 403
    with pytest.raises(websockets.exceptions.InvalidStatus) as exc_info:
        async with websockets.connect(
            f"{base_ws_url}/ws/control",
            additional_headers={"Origin": "https://malicious-site.example.com"},
        ) as ws:
            await ws.recv()
    assert exc_info.value.response.status_code == 403


def test_ip_scrubbing_processor_ipv4_and_ipv6() -> None:
    from blindvault_control.main import ip_scrubbing_processor

    event = {
        "event": "peer connected from 192.168.1.1 and 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "client_ip": "10.0.0.1",
        "host": "::1",
    }
    scrubbed = ip_scrubbing_processor(None, "info", event)
    assert "192.168.1.1" not in scrubbed["event"]
    assert "2001:0db8:85a3" not in scrubbed["event"]
    assert scrubbed["client_ip"] == "[REDACTED_IP]"
    assert scrubbed["host"] == "[REDACTED_IP]"
