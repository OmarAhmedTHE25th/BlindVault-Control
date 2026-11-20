"""Async UDP STUN-like endpoint reflection service with Ed25519 signatures."""

import asyncio
import base64
import ipaddress
import struct
import time
from typing import cast

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = structlog.get_logger()

# 4-byte protocol magic for UDP reflection probes
MAGIC_BYTES = b"BVST"
CLIENT_NONCE_LEN = 16
REQUEST_LEN = 4 + CLIENT_NONCE_LEN  # 20 bytes
SIGNATURE_LEN = 64  # Ed25519 raw signature size


def load_or_generate_ed25519_key(raw_key: str) -> tuple[Ed25519PrivateKey, bool]:
    """Load an Ed25519 private key from PEM, 64-hex seed, or base64 32B raw key.

    If raw_key is empty, generates an ephemeral keypair and returns (key, True).
    """
    cleaned = raw_key.strip()
    if not cleaned:
        return Ed25519PrivateKey.generate(), True

    if cleaned.startswith("-----BEGIN"):
        loaded = serialization.load_pem_private_key(cleaned.encode("utf-8"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("UDP signing key PEM must be an Ed25519 private key")
        return loaded, False

    raw_bytes: bytes | None = None
    if len(cleaned) == 64:
        try:
            raw_bytes = bytes.fromhex(cleaned)
        except ValueError:
            raw_bytes = None

    if raw_bytes is None:
        try:
            decoded = base64.b64decode(cleaned, validate=True)
            if len(decoded) == 32:
                raw_bytes = decoded
        except Exception as exc:
            raise ValueError("Invalid Ed25519 private key format") from exc

    if raw_bytes is None or len(raw_bytes) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes (PEM, 64-hex, or 44-char base64)")

    return Ed25519PrivateKey.from_private_bytes(raw_bytes), False


def export_public_key_b64(public_key: Ed25519PublicKey) -> str:
    """Export raw 32-byte Ed25519 public key encoded as ASCII base64."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def load_public_key_b64(b64_key: str) -> Ed25519PublicKey:
    """Decode ASCII base64 raw 32-byte Ed25519 public key."""
    raw = base64.b64decode(b64_key.strip(), validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def build_reflection_response(
    client_nonce: bytes,
    client_host: str,
    client_port: int,
    private_key: Ed25519PrivateKey,
    timestamp: int | None = None,
) -> bytes:
    """Construct an authenticated binary reflection response packet signed with Ed25519.

    Format:
    [0:4]        Magic bytes (b"BVST", 0x42565354)
    [4:20]       Client nonce (16B)
    [20:21]      IP version (1B: 4 or 6)
    [21:21+L]    Packed IP bytes (L=4 for IPv4, L=16 for IPv6)
    [21+L:23+L]  Client port (2B uint16 big-endian)
    [23+L:31+L]  Server timestamp (8B uint64 big-endian)
    [31+L:95+L]  Ed25519 signature (64B) over [0:31+L]
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

    sig = private_key.sign(signed_body)
    return signed_body + sig


def verify_reflection_response(
    data: bytes,
    public_key: Ed25519PublicKey,
    expected_nonce: bytes | None = None,
) -> tuple[str, int, int] | None:
    """Verify and unpack an Ed25519-signed reflection response packet.

    Returns (observed_ip, observed_port, timestamp) if valid, or None if invalid.
    """
    min_ipv4_len = 4 + CLIENT_NONCE_LEN + 1 + 4 + 2 + 8 + SIGNATURE_LEN  # 99 bytes
    if len(data) < min_ipv4_len:
        return None

    magic = data[:4]
    if magic != MAGIC_BYTES:
        return None

    nonce = data[4:20]
    if expected_nonce is not None and nonce != expected_nonce:
        return None

    ip_version = data[20]
    if ip_version == 4:
        ip_len = 4
    elif ip_version == 6:
        ip_len = 16
    else:
        return None

    expected_len = 21 + ip_len + 2 + 8 + SIGNATURE_LEN
    if len(data) != expected_len:
        return None

    ip_bytes = data[21 : 21 + ip_len]
    offset = 21 + ip_len
    port = int(struct.unpack("!H", data[offset : offset + 2])[0])
    offset += 2
    ts = int(struct.unpack("!Q", data[offset : offset + 8])[0])
    offset += 8
    received_sig = data[offset : offset + SIGNATURE_LEN]

    signed_body = data[:offset]
    try:
        public_key.verify(received_sig, signed_body)
    except (InvalidSignature, ValueError):
        return None

    ip_str = str(ipaddress.ip_address(ip_bytes))
    return ip_str, port, ts


class UdpReflectorProtocol(asyncio.DatagramProtocol):
    """Asynchronous DatagramProtocol reflecting external UDP IP and port with Ed25519."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)
        logger.info("udp_reflector_started")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.transport:
            return

        # Expect exactly 20 bytes: 4B magic + 16B client nonce
        if len(data) != REQUEST_LEN or data[:4] != MAGIC_BYTES:
            return

        client_nonce = data[4:20]
        host, port = addr[0], addr[1]

        try:
            response = build_reflection_response(
                client_nonce=client_nonce,
                client_host=host,
                client_port=port,
                private_key=self.private_key,
            )
            self.transport.sendto(response, addr)
        except Exception as exc:
            logger.debug("udp_reflection_failed", error=str(exc))

    def error_received(self, exc: Exception) -> None:
        logger.warning("udp_reflector_error", error=str(exc))


async def start_udp_reflector(
    host: str,
    port: int,
    private_key: Ed25519PrivateKey,
) -> tuple[asyncio.DatagramTransport, UdpReflectorProtocol]:
    """Start the UDP endpoint reflector on the active asyncio event loop."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UdpReflectorProtocol(private_key),
        local_addr=(host, port),
    )
    return transport, protocol
