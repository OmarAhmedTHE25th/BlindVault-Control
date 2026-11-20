"""Tests for the zero-knowledge encrypted fallback relay."""

import asyncio
import hashlib
import json
import secrets
from typing import Any

import pytest
import websockets

from tests.test_pairing_and_signaling import do_ws_auth


@pytest.mark.asyncio
async def test_end_to_end_relay_transfer_10mib(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    second_ec_p256_keypair: tuple[Any, Any, str, str],
    redis_store: Any,
) -> None:
    """Test 10 MiB stream transfer between two peers through the fallback relay."""
    base_ws_url, _ = live_server

    async with (
        websockets.connect(f"{base_ws_url}/ws/control") as ws_a,
        websockets.connect(f"{base_ws_url}/ws/control") as ws_b,
    ):
        fp_a = await do_ws_auth(ws_a, ec_p256_keypair)
        fp_b = await do_ws_auth(ws_b, second_ec_p256_keypair)

        # 1. Peer A requests CREATE_RELAY for Peer B
        await ws_a.send(
            json.dumps(
                {
                    "type": "CREATE_RELAY",
                    "target_fingerprint": fp_b,
                }
            )
        )

        # 2. Peer A gets RELAY_CREATED; Peer B gets RELAY_INVITE
        raw_created = await ws_a.recv()
        created_data = json.loads(raw_created)
        assert created_data["type"] == "RELAY_CREATED"
        session_id = created_data["session_id"]
        token_a = created_data["token"]

        raw_invite = await ws_b.recv()
        invite_data = json.loads(raw_invite)
        assert invite_data["type"] == "RELAY_INVITE"
        assert invite_data["session_id"] == session_id
        assert invite_data["from_fingerprint"] == fp_a
        token_b = invite_data["token"]

    # 3. Both peers connect to the relay endpoint
    url_a = f"{base_ws_url}/ws/relay/{session_id}?token={token_a}"
    url_b = f"{base_ws_url}/ws/relay/{session_id}?token={token_b}"

    total_bytes = 10 * 1024 * 1024  # Exactly 10 MiB
    chunk_size = 64 * 1024  # 64 KiB per chunk
    num_chunks = total_bytes // chunk_size

    # Pre-generate deterministic chunks
    hasher_sent = hashlib.sha256()
    chunks = []
    for _ in range(num_chunks):
        chunk = secrets.token_bytes(chunk_size)
        hasher_sent.update(chunk)
        chunks.append(chunk)
    expected_hash = hasher_sent.hexdigest()

    async with (
        websockets.connect(url_a, max_size=131072) as relay_a,
        websockets.connect(url_b, max_size=131072) as relay_b,
    ):
        # Receiver task
        hasher_recv = hashlib.sha256()
        bytes_received = 0

        async def receiver() -> None:
            nonlocal bytes_received
            while bytes_received < total_bytes:
                data = await relay_b.recv()
                assert isinstance(data, bytes)
                hasher_recv.update(data)
                bytes_received += len(data)

        recv_task = asyncio.create_task(receiver())

        # Sender streams 10 MiB in 64 KiB chunks
        for chunk in chunks:
            await relay_a.send(chunk)

        await asyncio.wait_for(recv_task, timeout=15.0)

        assert bytes_received == total_bytes
        assert hasher_recv.hexdigest() == expected_hash

    # 4. Verify Redis session state is cleaned up after disconnect
    await asyncio.sleep(0.1)
    session_after = await redis_store.get_relay_session(session_id)
    assert session_after is None


@pytest.mark.asyncio
async def test_relay_oversized_frame_rejection(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    second_ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    """Ensure relay sockets reject chunks exceeding the 64 KiB bound with code 1009."""
    base_ws_url, _ = live_server

    async with (
        websockets.connect(f"{base_ws_url}/ws/control") as ws_a,
        websockets.connect(f"{base_ws_url}/ws/control") as ws_b,
    ):
        await do_ws_auth(ws_a, ec_p256_keypair)
        fp_b = await do_ws_auth(ws_b, second_ec_p256_keypair)

        await ws_a.send(json.dumps({"type": "CREATE_RELAY", "target_fingerprint": fp_b}))
        created = json.loads(await ws_a.recv())
        session_id = created["session_id"]
        token_a = created["token"]
        token_b = json.loads(await ws_b.recv())["token"]

    url_a = f"{base_ws_url}/ws/relay/{session_id}?token={token_a}"
    url_b = f"{base_ws_url}/ws/relay/{session_id}?token={token_b}"

    async with (
        websockets.connect(url_a, max_size=131072) as relay_a,
        websockets.connect(url_b, max_size=131072),
    ):
        # Send a 70 KiB payload (> 64 KiB limit)
        oversized_payload = b"Z" * 70000
        await relay_a.send(oversized_payload)

        # Peer A should be disconnected with 1009
        with pytest.raises(websockets.exceptions.ConnectionClosed) as exc_info:
            await relay_a.recv()
        assert exc_info.value.code == 1009
