"""Cryptographic identity verification, EC P-256 parsing, fingerprints, and nonces."""

import base64
import hashlib
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class InvalidKeyError(CryptoError):
    """Raised when an identity key is invalid or unsupported."""


class SignatureVerificationError(CryptoError):
    """Raised when an ECDSA signature fails verification."""


# Crockford's Base32 alphabet (excludes I, L, O, U to avoid human transcription errors)
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def parse_ec_p256_public_key(key_material: str | bytes) -> ec.EllipticCurvePublicKey:
    """Parse and validate an EC P-256 (secp256r1) public key from PEM or DER.

    Raises:
        InvalidKeyError: If parsing fails, key is not EC, or curve is not SECP256R1.
    """
    raw_bytes = key_material.encode("utf-8") if isinstance(key_material, str) else key_material

    # Attempt PEM parsing first, then DER
    public_key = None
    if b"-----BEGIN PUBLIC KEY-----" in raw_bytes or b"-----BEGIN EC PUBLIC KEY-----" in raw_bytes:
        try:
            public_key = serialization.load_pem_public_key(raw_bytes)
        except Exception as e:
            raise InvalidKeyError(f"Failed to load PEM public key: {e}") from e
    else:
        try:
            public_key = serialization.load_der_public_key(raw_bytes)
        except Exception as e:
            raise InvalidKeyError(f"Failed to load DER public key: {e}") from e

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise InvalidKeyError("Key is not an Elliptic Curve public key")

    if not isinstance(public_key.curve, ec.SECP256R1):
        raise InvalidKeyError(
            f"Unsupported curve: {public_key.curve.name}. Only SECP256R1 (P-256) is accepted."
        )

    return public_key


def get_public_key_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Export public key to SubjectPublicKeyInfo DER encoding."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def compute_peer_fingerprint(public_key: ec.EllipticCurvePublicKey | str | bytes) -> str:
    """Compute canonical lowercase hex SHA-256 fingerprint of DER-encoded public key.

    Matches BlindVault's identity fingerprint format.
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        der = get_public_key_der(public_key)
    else:
        parsed = parse_ec_p256_public_key(public_key)
        der = get_public_key_der(parsed)
    return hashlib.sha256(der).hexdigest().lower()


def generate_challenge_nonce(num_bytes: int = 32) -> bytes:
    """Generate a cryptographically secure random challenge nonce."""
    return secrets.token_bytes(num_bytes)


def encode_base64(data: bytes) -> str:
    """Encode bytes to ASCII base64 string."""
    return base64.b64encode(data).decode("ascii")


def decode_base64(data: str | bytes) -> bytes:
    """Decode base64 string or bytes to raw bytes."""
    try:
        raw_bytes = data.encode("ascii") if isinstance(data, str) else data
        return base64.b64decode(raw_bytes, validate=True)
    except Exception as e:
        raise CryptoError(f"Invalid base64 payload: {e}") from e


def verify_ecdsa_signature(
    public_key: ec.EllipticCurvePublicKey,
    signature_bytes: bytes,
    nonce_bytes: bytes,
) -> bool:
    """Verify an ECDSA SHA-256 signature over raw nonce bytes.

    Returns True if valid, False otherwise.
    """
    try:
        public_key.verify(signature_bytes, nonce_bytes, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def generate_crockford_code(length: int = 8) -> str:
    """Generate an 8-character human-friendly Crockford Base32 invite code."""
    return "".join(secrets.choice(CROCKFORD_ALPHABET) for _ in range(length))


def normalize_crockford_code(code: str) -> str:
    """Normalize user-typed Crockford Base32 code (case-insensitive, I/L->1, O->0).

    Validates that the code is exactly 8 characters and only contains
    Crockford Base32 alphabet characters.
    Raises ValueError if length != 8 or invalid characters are present.
    """
    cleaned = code.strip().upper().replace("-", "").replace(" ", "")
    trans = str.maketrans({"I": "1", "L": "1", "O": "0"})
    normalized = cleaned.translate(trans)
    if len(normalized) != 8:
        raise ValueError(f"Invalid code length: expected 8 characters, got {len(normalized)}")
    if any(c not in CROCKFORD_ALPHABET for c in normalized):
        invalid_chars = [c for c in normalized if c not in CROCKFORD_ALPHABET]
        raise ValueError(f"Invalid Crockford Base32 character(s): {', '.join(invalid_chars)}")
    return normalized
