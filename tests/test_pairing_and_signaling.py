"""Tests for ephemeral pairing invites, atomic single-use claims, and ICE/hole-punch signaling."""

import json
from typing import Any

import pytest
import websockets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from blindvault_control.crypto import decode_base64, encode_base64


async def do_ws_auth(ws: Any, keypair: tuple[Any, Any, str, str]) -> str:
    """Helper to perform full ECDSA challenge-response auth over WebSocket."""
    priv, _, pem, fp = keypair
    await ws.send(json.dumps({"type": "HELLO", "public_key": pem}))
    raw_ch = await ws.recv()
    ch = json.loads(raw_ch)
    nonce = decode_base64(ch["nonce"])
    sig = priv.sign(nonce, ec.ECDSA(hashes.SHA256()))
    await ws.send(json.dumps({"type": "AUTH", "signature": encode_base64(sig)}))
    raw_ok = await ws.recv()
    ok = json.loads(raw_ok)
    assert ok["type"] == "AUTH_OK"
    return fp


@pytest.mark.asyncio
async def test_invite_creation_and_mutual_claim(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    second_ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    base_ws_url, _ = live_server

    async with (
        websockets.connect(f"{base_ws_url}/ws/control") as ws_a,
        websockets.connect(f"{base_ws_url}/ws/control") as ws_b,
    ):
        fp_a = await do_ws_auth(ws_a, ec_p256_keypair)
        fp_b = await do_ws_auth(ws_b, second_ec_p256_keypair)

        # 1. Peer A creates an invite code
        await ws_a.send(
            json.dumps(
                {
                    "type": "CREATE_INVITE",
                    "endpoints": [{"ip": "1.2.3.4", "port": 9000}],
                }
            )
        )
        raw_inv = await ws_a.recv()
        inv_data = json.loads(raw_inv)
        assert inv_data["type"] == "INVITE_CREATED"
        code = inv_data["code"]
        assert len(code) == 8

        # 2. Peer B claims the invite code with client-declared endpoints
        await ws_b.send(
            json.dumps(
                {
                    "type": "CLAIM_INVITE",
                    "code": code,
                    "endpoints": [{"ip": "10.0.0.2", "port": 9002}],
                }
            )
        )

        # 3. Peer B receives PEER_MATCHED (claimer role)
        raw_matched_b = await ws_b.recv()
        matched_b = json.loads(raw_matched_b)
        assert matched_b["type"] == "PEER_MATCHED"
        assert matched_b["peer_fingerprint"] == fp_a
        assert matched_b["role"] == "claimer"
        assert matched_b["endpoints"] == [{"ip": "1.2.3.4", "port": 9000}]

        # 4. Peer A receives PEER_MATCHED (creator role)
        # Zero-knowledge: strictly Peer B's declared endpoints, never client_ip
        raw_matched_a = await ws_a.recv()
        matched_a = json.loads(raw_matched_a)
        assert matched_a["type"] == "PEER_MATCHED"
        assert matched_a["peer_fingerprint"] == fp_b
        assert matched_a["role"] == "creator"
        assert matched_a["endpoints"] == [{"ip": "10.0.0.2", "port": 9002}]
        assert "client_ip" not in json.dumps(matched_a["endpoints"])

        # 5. Second claim with same code fails (atomic single-use verification)
        await ws_b.send(
            json.dumps(
                {
                    "type": "CLAIM_INVITE",
                    "code": code,
                }
            )
        )
        raw_err = await ws_b.recv()
        err_data = json.loads(raw_err)
        assert err_data["type"] == "ERROR"
        assert err_data["code"] == "INVITE_NOT_FOUND"


@pytest.mark.asyncio
async def test_self_pairing_rejection(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    base_ws_url, _ = live_server

    async with websockets.connect(f"{base_ws_url}/ws/control") as ws:
        await do_ws_auth(ws, ec_p256_keypair)

        # Create invite
        await ws.send(json.dumps({"type": "CREATE_INVITE"}))
        raw_inv = await ws.recv()
        code = json.loads(raw_inv)["code"]

        # Try to claim own invite
        await ws.send(json.dumps({"type": "CLAIM_INVITE", "code": code}))
        raw_err = await ws.recv()
        err_data = json.loads(raw_err)
        assert err_data["type"] == "ERROR"
        assert err_data["code"] == "SELF_PAIRING"


@pytest.mark.asyncio
async def test_signaling_forwarding_offer_answer_sync(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
    second_ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    base_ws_url, _ = live_server

    async with (
        websockets.connect(f"{base_ws_url}/ws/control") as ws_a,
        websockets.connect(f"{base_ws_url}/ws/control") as ws_b,
    ):
        fp_a = await do_ws_auth(ws_a, ec_p256_keypair)
        fp_b = await do_ws_auth(ws_b, second_ec_p256_keypair)

        # 1. Forward SIGNAL_OFFER from A to B
        await ws_a.send(
            json.dumps(
                {
                    "type": "SIGNAL_OFFER",
                    "target_fingerprint": fp_b,
                    "session_id": "sess_123",
                    "candidate": {"ip": "1.1.1.1", "port": 1234},
                }
            )
        )

        msg_b = json.loads(await ws_b.recv())
        assert msg_b["type"] == "SIGNAL_OFFER"
        assert msg_b["from_fingerprint"] == fp_a
        assert msg_b["candidate"] == {"ip": "1.1.1.1", "port": 1234}

        # 2. Forward SIGNAL_ANSWER from B to A
        await ws_b.send(
            json.dumps(
                {
                    "type": "SIGNAL_ANSWER",
                    "target_fingerprint": fp_a,
                    "session_id": "sess_123",
                    "candidate": {"ip": "2.2.2.2", "port": 5678},
                }
            )
        )

        msg_a = json.loads(await ws_a.recv())
        assert msg_a["type"] == "SIGNAL_ANSWER"
        assert msg_a["from_fingerprint"] == fp_b
        assert msg_a["candidate"] == {"ip": "2.2.2.2", "port": 5678}

        # 3. Forward HOLE_PUNCH_SYNC from A to B
        await ws_a.send(
            json.dumps(
                {
                    "type": "HOLE_PUNCH_SYNC",
                    "target_fingerprint": fp_b,
                    "stage": "SYN_START",
                    "timestamp": 123456789.0,
                }
            )
        )

        sync_b = json.loads(await ws_b.recv())
        assert sync_b["type"] == "HOLE_PUNCH_SYNC"
        assert sync_b["from_fingerprint"] == fp_a
        assert sync_b["stage"] == "SYN_START"


@pytest.mark.asyncio
async def test_signaling_to_offline_peer(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    base_ws_url, _ = live_server

    async with websockets.connect(f"{base_ws_url}/ws/control") as ws:
        await do_ws_auth(ws, ec_p256_keypair)

        # Send offer to non-existent offline peer
        await ws.send(
            json.dumps(
                {
                    "type": "SIGNAL_OFFER",
                    "target_fingerprint": "0" * 64,
                    "session_id": "none",
                    "candidate": {},
                }
            )
        )

        msg = json.loads(await ws.recv())
        assert msg["type"] == "ERROR"
        assert msg["code"] == "PEER_OFFLINE"


@pytest.mark.asyncio
async def test_claim_invite_invalid_crockford_code(
    live_server: tuple[str, int],
    ec_p256_keypair: tuple[Any, Any, str, str],
) -> None:
    base_ws_url, _ = live_server

    async with websockets.connect(f"{base_ws_url}/ws/control") as ws:
        await do_ws_auth(ws, ec_p256_keypair)

        # Send invalid Crockford code (e.g. wrong length)
        await ws.send(
            json.dumps(
                {
                    "type": "CLAIM_INVITE",
                    "code": "invalid_code",
                }
            )
        )

        msg = json.loads(await ws.recv())
        assert msg["type"] == "ERROR"
        assert msg["code"] == "INVALID_INVITE_CODE"
