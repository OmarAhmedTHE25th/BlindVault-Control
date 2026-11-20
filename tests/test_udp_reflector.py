"""Tests for UDP STUN-like endpoint reflector and HMAC verification."""

import asyncio
import secrets

import pytest

from blindvault_control.udp_reflector import (
    CLIENT_NONCE_LEN,
    MAGIC_BYTES,
    build_reflection_response,
    start_udp_reflector,
    verify_reflection_response,
)
from tests.conftest import get_free_port


def test_reflection_packet_packing_ipv4() -> None:
    secret = b"test_secret_key_123"
    nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
    host = "203.0.113.42"
    port = 54321
    ts = 1700000000

    resp = build_reflection_response(
        client_nonce=nonce,
        client_host=host,
        client_port=port,
        secret_bytes=secret,
        timestamp=ts,
    )

    unpacked = verify_reflection_response(resp, secret, expected_nonce=nonce)
    assert unpacked is not None
    unpacked_ip, unpacked_port, unpacked_ts = unpacked
    assert unpacked_ip == host
    assert unpacked_port == port
    assert unpacked_ts == ts


def test_reflection_packet_packing_ipv6() -> None:
    secret = b"test_secret_key_123"
    nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
    host = "2001:db8::8a2e:370:7334"
    port = 60000
    ts = 1700000000

    resp = build_reflection_response(
        client_nonce=nonce,
        client_host=host,
        client_port=port,
        secret_bytes=secret,
        timestamp=ts,
    )

    unpacked = verify_reflection_response(resp, secret, expected_nonce=nonce)
    assert unpacked is not None
    unpacked_ip, unpacked_port, unpacked_ts = unpacked
    assert unpacked_ip == host
    assert unpacked_port == port
    assert unpacked_ts == ts


def test_reflection_tamper_detection() -> None:
    secret = b"secret_A"
    nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
    resp = bytearray(
        build_reflection_response(
            client_nonce=nonce,
            client_host="1.2.3.4",
            client_port=12345,
            secret_bytes=secret,
        )
    )

    # 1. Verification with wrong secret must fail
    assert verify_reflection_response(bytes(resp), b"secret_B") is None

    # 2. Tampered port must fail HMAC check
    tampered_port = bytearray(resp)
    tampered_port[21 + 4] ^= 0x01
    assert verify_reflection_response(bytes(tampered_port), secret) is None

    # 3. Tampered tag must fail
    tampered_tag = bytearray(resp)
    tampered_tag[-1] ^= 0xFF
    assert verify_reflection_response(bytes(tampered_tag), secret) is None


@pytest.mark.asyncio
async def test_live_udp_reflector_socket() -> None:
    udp_port = get_free_port()
    secret = "live_test_secret"

    # Start reflector
    transport, _ = await start_udp_reflector("127.0.0.1", udp_port, secret)

    try:
        loop = asyncio.get_running_loop()
        on_response = loop.create_future()

        class ClientProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if not on_response.done():
                    on_response.set_result((data, addr))

        # Client socket
        client_transport, _ = await loop.create_datagram_endpoint(
            ClientProtocol,
            local_addr=("127.0.0.1", 0),
        )

        try:
            client_nonce = secrets.token_bytes(CLIENT_NONCE_LEN)
            probe = MAGIC_BYTES + client_nonce
            client_transport.sendto(probe, ("127.0.0.1", udp_port))

            resp_data, _ = await asyncio.wait_for(on_response, timeout=2.0)
            result = verify_reflection_response(resp_data, secret.encode("utf-8"), client_nonce)
            assert result is not None
            obs_ip, obs_port, _ = result
            assert obs_ip == "127.0.0.1"
            assert obs_port > 0
        finally:
            client_transport.close()
    finally:
        transport.close()
