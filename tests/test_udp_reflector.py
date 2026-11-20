"""Tests for UDP STUN-like endpoint reflector and Ed25519 signature verification."""

import asyncio
import secrets

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blindvault_control.udp_reflector import (
    CLIENT_NONCE_LEN,
    MAGIC_BYTES,
    build_reflection_response,
    load_or_generate_ed25519_key,
    load_public_key_b64,
    start_udp_reflector,
    verify_reflection_response,
)
from tests.conftest import get_free_port


def test_ed25519_key_loading_formats() -> None:
    priv, auto = load_or_generate_ed25519_key("")
    assert auto is True

    raw_seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_hex, auto_hex = load_or_generate_ed25519_key(raw_seed.hex())
    assert auto_hex is False
    assert priv_hex.public_key() == priv.public_key()

    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    priv_pem, auto_pem = load_or_generate_ed25519_key(pem)
    assert auto_pem is False
    assert priv_pem.public_key() == priv.public_key()


def test_reflection_packet_packing_ipv4() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
    host = "203.0.113.42"
    port = 54321
    ts = 1700000000

    resp = build_reflection_response(
        client_nonce=nonce,
        client_host=host,
        client_port=port,
        private_key=private_key,
        timestamp=ts,
    )

    assert len(resp) == 99  # 4 + 16 + 1 + 4 + 2 + 8 + 64
    unpacked = verify_reflection_response(resp, public_key, expected_nonce=nonce)
    assert unpacked is not None
    unpacked_ip, unpacked_port, unpacked_ts = unpacked
    assert unpacked_ip == host
    assert unpacked_port == port
    assert unpacked_ts == ts


def test_reflection_packet_packing_ipv6() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
    host = "2001:db8::8a2e:370:7334"
    port = 60000
    ts = 1700000000

    resp = build_reflection_response(
        client_nonce=nonce,
        client_host=host,
        client_port=port,
        private_key=private_key,
        timestamp=ts,
    )

    assert len(resp) == 111  # 4 + 16 + 1 + 16 + 2 + 8 + 64
    unpacked = verify_reflection_response(resp, public_key, expected_nonce=nonce)
    assert unpacked is not None
    unpacked_ip, unpacked_port, unpacked_ts = unpacked
    assert unpacked_ip == host
    assert unpacked_port == port
    assert unpacked_ts == ts


def test_reflection_tamper_detection() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    wrong_public_key = Ed25519PrivateKey.generate().public_key()
    nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
    resp = bytearray(
        build_reflection_response(
            client_nonce=nonce,
            client_host="1.2.3.4",
            client_port=12345,
            private_key=private_key,
        )
    )

    # 1. Wrong public key must fail
    assert verify_reflection_response(bytes(resp), wrong_public_key) is None

    # 2. Wrong expected nonce must fail
    assert verify_reflection_response(bytes(resp), public_key, b"\x00" * 16) is None

    # 3. Tampered IP byte must fail Ed25519 verification
    tampered_ip = bytearray(resp)
    tampered_ip[21] ^= 0x01
    assert verify_reflection_response(bytes(tampered_ip), public_key) is None

    # 4. Tampered port must fail Ed25519 verification
    tampered_port = bytearray(resp)
    tampered_port[21 + 4] ^= 0x01
    assert verify_reflection_response(bytes(tampered_port), public_key) is None

    # 5. Tampered timestamp must fail Ed25519 verification
    tampered_ts = bytearray(resp)
    tampered_ts[21 + 4 + 2] ^= 0x01
    assert verify_reflection_response(bytes(tampered_ts), public_key) is None

    # 6. Tampered Ed25519 signature byte must fail
    tampered_sig = bytearray(resp)
    tampered_sig[-1] ^= 0xFF
    assert verify_reflection_response(bytes(tampered_sig), public_key) is None


@pytest.mark.asyncio
async def test_live_udp_reflector_socket() -> None:
    udp_port = get_free_port()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    transport, _ = await start_udp_reflector("127.0.0.1", udp_port, private_key)

    try:
        loop = asyncio.get_running_loop()
        on_response: asyncio.Future[tuple[bytes, tuple[str, int]]] = loop.create_future()

        class ClientProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if not on_response.done():
                    on_response.set_result((data, addr))

        client_transport, _ = await loop.create_datagram_endpoint(
            ClientProtocol,
            local_addr=("127.0.0.1", 0),
        )

        try:
            client_nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
            probe = MAGIC_BYTES + client_nonce
            client_transport.sendto(probe, ("127.0.0.1", udp_port))

            resp_data, _ = await asyncio.wait_for(on_response, timeout=2.0)
            result = verify_reflection_response(resp_data, public_key, client_nonce)
            assert result is not None
            obs_ip, obs_port, _ = result
            assert obs_ip == "127.0.0.1"
            assert obs_port > 0
        finally:
            client_transport.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_api_info_exposes_ed25519_public_key_and_verifies_live_probe(
    live_server: tuple[str, int],
) -> None:
    _, http_port = live_server
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"http://127.0.0.1:{http_port}/api/v1/info")
        assert resp.status_code == 200
        info = resp.json()

    assert info["udp_reflector_signature_alg"] == "ed25519"
    udp_port = int(info["udp_reflector_port"])
    pub_key = load_public_key_b64(info["udp_reflector_public_key"])

    loop = asyncio.get_running_loop()
    on_response: asyncio.Future[bytes] = loop.create_future()

    class ProbeProtocol(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            if not on_response.done():
                on_response.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(ProbeProtocol, local_addr=("127.0.0.1", 0))
    try:
        nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
        transport.sendto(MAGIC_BYTES + nonce, ("127.0.0.1", udp_port))
        pkt = await asyncio.wait_for(on_response, timeout=2.0)
        unpacked = verify_reflection_response(pkt, pub_key, nonce)
        assert unpacked is not None
        assert unpacked[0] == "127.0.0.1"
    finally:
        transport.close()
