"""Async UDP STUN-like endpoint reflection service with HMAC authentication."""

import asyncio
import hashlib
import hmac
import ipaddress
import struct
import time

import structlog

logger = structlog.get_logger()

# 4-byte protocol magic for UDP reflection probes
MAGIC_BYTES = b"BVST"
CLIENT_NONCE_LEN = 16
REQUEST_LEN = 4 + CLIENT_NONCE_LEN  # 20 bytes


def build_reflection_response(
    client_nonce: bytes,
    client_host: str,
    client_port: int,
    secret_bytes: bytes,
    timestamp: int | None = None,
) -> bytes:
    """Construct an authenticated binary reflection response packet.

    Format:
    [0:4]   Magic bytes (b"BVST")
    [4:20]  Client nonce (16B)
    [20:21] IP version (1B: 4 or 6)
    [21:X]  Packed IP bytes (4B for IPv4, 16B for IPv6)
    [X:X+2] Client port (2B uint16 big-endian)
    [X+2:X+10] Server timestamp (8B uint64 big-endian)
    [X+10:X+42] HMAC-SHA256 tag (32B)
    """
    if len(client_nonce) != CLIENT_NONCE_LEN:
        raise ValueError(f"Client nonce must be exactly {CLIENT_NONCE_LEN} bytes")

    ip = ipaddress.ip_address(client_host)
    ip_version = ip.version
    ip_bytes = ip.packed
    port_bytes = struct.pack("!H", client_port)
    ts = timestamp if timestamp is not None else int(time.time())
    ts_bytes = struct.pack("!Q", ts)

    signed_body = (
        MAGIC_BYTES
        + client_nonce
        + struct.pack("!B", ip_version)
        + ip_bytes
        + port_bytes
        + ts_bytes
    )

    tag = hmac.new(secret_bytes, signed_body, hashlib.sha256).digest()
    return signed_body + tag


def verify_reflection_response(
    data: bytes,
    secret_bytes: bytes,
    expected_nonce: bytes | None = None,
) -> tuple[str, int, int] | None:
    """Verify and unpack a reflection response packet.

    Returns (observed_ip, observed_port, timestamp) if valid, or None if invalid.
    """
    if len(data) < 4 + CLIENT_NONCE_LEN + 1 + 4 + 2 + 8 + 32:  # Min IPv4 len = 67
        return None

    magic = data[:4]
    if magic != MAGIC_BYTES:
        return None

    nonce = data[4:20]
    if expected_nonce and nonce != expected_nonce:
        return None

    ip_version = data[20]
    if ip_version == 4:
        ip_len = 4
    elif ip_version == 6:
        ip_len = 16
    else:
        return None

    expected_len = 21 + ip_len + 2 + 8 + 32
    if len(data) != expected_len:
        return None

    ip_bytes = data[21 : 21 + ip_len]
    offset = 21 + ip_len
    port = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    ts = struct.unpack("!Q", data[offset : offset + 8])[0]
    offset += 8
    received_tag = data[offset : offset + 32]

    signed_body = data[:offset]
    computed_tag = hmac.new(secret_bytes, signed_body, hashlib.sha256).digest()

    if not hmac.compare_digest(received_tag, computed_tag):
        return None

    ip_str = str(ipaddress.ip_address(ip_bytes))
    return ip_str, port, ts


class UdpReflectorProtocol(asyncio.DatagramProtocol):
    """Asynchronous DatagramProtocol reflecting external UDP IP and port to clients."""

    def __init__(self, secret: str) -> None:
        self.secret_bytes = secret.encode("utf-8")
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        logger.info("udp_reflector_started")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.transport:
            return

        # Expect exactly 20 bytes: 4B magic + 16B client nonce
        if len(data) != REQUEST_LEN:
            return

        if data[:4] != MAGIC_BYTES:
            return

        client_nonce = data[4:20]
        host, port = addr[0], addr[1]

        try:
            response = build_reflection_response(
                client_nonce=client_nonce,
                client_host=host,
                client_port=port,
                secret_bytes=self.secret_bytes,
            )
            self.transport.sendto(response, addr)
        except Exception as exc:
            logger.debug("udp_reflection_failed", error=str(exc))

    def error_received(self, exc: Exception) -> None:
        logger.warning("udp_reflector_error", error=str(exc))


async def start_udp_reflector(
    host: str,
    port: int,
    secret: str,
) -> tuple[asyncio.DatagramTransport, UdpReflectorProtocol]:
    """Start the UDP endpoint reflector on the active asyncio event loop."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UdpReflectorProtocol(secret),
        local_addr=(host, port),
    )
    return transport, protocol
