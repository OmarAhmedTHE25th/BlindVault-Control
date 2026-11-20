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

    # 3. Both peers connect to the relay endpoint via Authorization: Bearer <token> headers
    url_relay = f"{base_ws_url}/ws/relay/{session_id}"
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

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
        websockets.connect(url_relay, additional_headers=headers_a, max_size=131072) as relay_a,
        websockets.connect(url_relay, additional_headers=headers_b, max_size=131072) as relay_b,
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


@pytest.mark.asyncio
async def test_relay_rejects_text_frames(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    second_ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    """Ensure relay rejects text frames with code 1003 (binary-only channel)."""
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

    url_relay = f"{base_ws_url}/ws/relay/{session_id}"
    async with (
        websockets.connect(
            url_relay,
            additional_headers={"Authorization": f"Bearer {token_a}"},
        ) as relay_a,
        websockets.connect(
            url_relay,
            additional_headers={"X-Relay-Token": token_b},
        ),
    ):
        # Sending a text frame violates the binary-only specification
        await relay_a.send("this is a text frame, not binary")

        with pytest.raises(websockets.exceptions.ConnectionClosed) as exc_info:
            await relay_a.recv()
        assert exc_info.value.code == 1003


@pytest.mark.asyncio
async def test_relay_early_disconnect_detach(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    second_ec_p256_keypair: tuple[Any, Any, str, str],
    redis_store: Any,
) -> None:
    """Ensure early disconnect of first peer detaches cleanly and tears down session."""
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

    # Verify session initially exists in Redis
    session_before = await redis_store.get_relay_session(session_id)
    assert session_before is not None

    url_relay = f"{base_ws_url}/ws/relay/{session_id}"
    # Peer A connects and immediately closes
    relay_a = await websockets.connect(
        url_relay,
        additional_headers={"Authorization": f"Bearer {token_a}"},
    )
    await relay_a.close(code=1000)

    # Wait for the abort and cleanup handler to execute
    await asyncio.sleep(0.15)

    # Assert that the session is actually gone from Redis
    session_after = await redis_store.get_relay_session(session_id)
    assert session_after is None

    # Assert that a subsequent connection attempt by Peer B is rejected (session is gone)
    with pytest.raises(
        (websockets.exceptions.ConnectionClosed, websockets.exceptions.InvalidStatus)
    ) as exc_info:
        async with websockets.connect(
            url_relay,
            additional_headers={"Authorization": f"Bearer {token_b}"},
        ) as relay_b:
            await relay_b.recv()

    if isinstance(exc_info.value, websockets.exceptions.InvalidStatus):
        assert exc_info.value.response.status_code == 403
    else:
        assert exc_info.value.code == 1008


@pytest.mark.asyncio
async def test_relay_session_detach_peer_unit() -> None:
    """Unit test for RelaySession attach and detach lifecycle."""
    from unittest.mock import MagicMock

    from blindvault_control.relay import RelaySession

    session = RelaySession(
        session_id="test_detach_sess",
        initiator_fp="fp_init",
        responder_fp="fp_resp",
        initiator_token="tok_init",
        responder_token="tok_resp",
    )

    mock_ws_init = MagicMock()
    mock_ws_resp = MagicMock()

    # 1. Attach initiator
    role_init = await session.attach_peer(mock_ws_init, "tok_init")
    assert role_init == "initiator"
    assert session.ws_initiator is mock_ws_init
    assert not session.ready_event.is_set()

    # 2. Detach initiator
    await session.detach_peer("initiator")
    assert session.ws_initiator is None
    assert not session.ready_event.is_set()

    # 3. Attach both peers -> ready_event is set
    await session.attach_peer(mock_ws_init, "tok_init")
    await session.attach_peer(mock_ws_resp, "tok_resp")
    assert session.ready_event.is_set()

    # 4. Detach responder -> ready_event cleared
    await session.detach_peer("responder")
    assert session.ws_responder is None
    assert not session.ready_event.is_set()


@pytest.mark.asyncio
async def test_cross_replica_relay_bridge_via_redis_pubsub(
    two_live_servers: tuple[tuple[str, int], tuple[str, int]],
    ec_p256_keypair: tuple[Any, Any, str, str],
    second_ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    """Verify binary relay works when Peer A attaches to Replica 1 and Peer B to Replica 2."""
    (ws_url_1, _), (ws_url_2, _) = two_live_servers

    async with (
        websockets.connect(f"{ws_url_1}/ws/control") as ws_a,
        websockets.connect(f"{ws_url_2}/ws/control") as ws_b,
    ):
        fp_a = await do_ws_auth(ws_a, ec_p256_keypair)
        fp_b = await do_ws_auth(ws_b, second_ec_p256_keypair)

        await ws_a.send(json.dumps({"type": "CREATE_RELAY", "target_fingerprint": fp_b}))
        created = json.loads(await ws_a.recv())
        invite = json.loads(await ws_b.recv())
        assert created["type"] == "RELAY_CREATED"
        assert invite["type"] == "RELAY_INVITE"
        assert invite["from_fingerprint"] == fp_a

        session_id = created["session_id"]
        token_a = created["token"]
        token_b = invite["token"]

    # Peer A connects to Replica 1; Peer B connects to Replica 2
    total_bytes = 1024 * 1024  # 1 MiB across replicas
    chunk_size = 64 * 1024
    num_chunks = total_bytes // chunk_size
    chunks = [secrets.token_bytes(chunk_size) for _ in range(num_chunks)]
    expected_sha = hashlib.sha256(b"".join(chunks)).hexdigest()

    async with (
        websockets.connect(
            f"{ws_url_1}/ws/relay/{session_id}",
            additional_headers={"Authorization": f"Bearer {token_a}"},
            max_size=131072,
        ) as relay_a,
        websockets.connect(
            f"{ws_url_2}/ws/relay/{session_id}",
            additional_headers={"Authorization": f"Bearer {token_b}"},
            max_size=131072,
        ) as relay_b,
    ):
        recv_chunks_a2b: list[bytes] = []
        recv_len_a2b = 0

        async def rx_b() -> None:
            nonlocal recv_len_a2b
            while recv_len_a2b < total_bytes:
                frame = await relay_b.recv()
                assert isinstance(frame, bytes)
                recv_chunks_a2b.append(frame)
                recv_len_a2b += len(frame)

        rx_task = asyncio.create_task(rx_b())
        for chunk in chunks:
            await relay_a.send(chunk)

        await asyncio.wait_for(rx_task, timeout=10.0)
        assert hashlib.sha256(b"".join(recv_chunks_a2b)).hexdigest() == expected_sha

        # Also verify bidirectional reverse direction (Replica 2 -> Replica 1)
        ack_payload = b"REVERSE_ACK_OK_" + secrets.token_bytes(32)
        await relay_b.send(ack_payload)
        got_ack = await asyncio.wait_for(relay_a.recv(), timeout=5.0)
        assert got_ack == ack_payload
