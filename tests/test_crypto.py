"""Tests for cryptographic identity, curve validation, fingerprints, and ECDSA verification."""

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from blindvault_control.crypto import (
    CROCKFORD_ALPHABET,
    CryptoError,
    InvalidKeyError,
    compute_peer_fingerprint,
    decode_base64,
    encode_base64,
    generate_challenge_nonce,
    generate_crockford_code,
    get_public_key_der,
    normalize_crockford_code,
    parse_ec_p256_public_key,
    verify_ecdsa_signature,
)


def test_parse_valid_ec_p256_pem(ec_p256_keypair: tuple[Any, Any, str, str]) -> None:
    _, pub, pem, _ = ec_p256_keypair
    parsed = parse_ec_p256_public_key(pem)
    assert isinstance(parsed, ec.EllipticCurvePublicKey)
    assert isinstance(parsed.curve, ec.SECP256R1)
    assert get_public_key_der(parsed) == get_public_key_der(pub)


def test_parse_valid_ec_p256_der(ec_p256_keypair: tuple[Any, Any, str, str]) -> None:
    _, pub, _, _ = ec_p256_keypair
    der = get_public_key_der(pub)
    parsed = parse_ec_p256_public_key(der)
    assert isinstance(parsed, ec.EllipticCurvePublicKey)
    assert isinstance(parsed.curve, ec.SECP256R1)


def test_reject_wrong_curve_secp256k1(wrong_curve_secp256k1_keypair: tuple[Any, str]) -> None:
    _, pem = wrong_curve_secp256k1_keypair
    with pytest.raises(InvalidKeyError, match="Unsupported curve: secp256k1"):
        parse_ec_p256_public_key(pem)


def test_reject_wrong_curve_secp384r1() -> None:
    priv = ec.generate_private_key(ec.SECP384R1())
    pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    with pytest.raises(InvalidKeyError, match="Unsupported curve: secp384r1"):
        parse_ec_p256_public_key(pem)


def test_reject_rsa_key() -> None:
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (
        rsa_priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    with pytest.raises(InvalidKeyError, match="not an Elliptic Curve public key"):
        parse_ec_p256_public_key(pem)


def test_reject_garbage_key() -> None:
    with pytest.raises(InvalidKeyError):
        parse_ec_p256_public_key("not a real key")


def test_compute_peer_fingerprint(ec_p256_keypair: tuple[Any, Any, str, str]) -> None:
    _, pub, pem, fp = ec_p256_keypair
    assert len(fp) == 64
    assert fp.islower()
    # Direct computation from pub and pem must yield the exact same fingerprint
    assert compute_peer_fingerprint(pub) == fp
    assert compute_peer_fingerprint(pem) == fp


def test_nonce_generation_and_base64() -> None:
    nonce = generate_challenge_nonce(32)
    assert len(nonce) == 32
    encoded = encode_base64(nonce)
    decoded = decode_base64(encoded)
    assert decoded == nonce


def test_decode_invalid_base64() -> None:
    with pytest.raises(CryptoError, match="Invalid base64"):
        decode_base64("!@#$%^&*()")


def test_ecdsa_signature_verification(ec_p256_keypair: tuple[Any, Any, str, str]) -> None:
    priv, pub, _, _ = ec_p256_keypair
    nonce = generate_challenge_nonce(32)

    # Valid signature
    sig = priv.sign(nonce, ec.ECDSA(hashes.SHA256()))
    assert verify_ecdsa_signature(pub, sig, nonce) is True

    # Tampered nonce
    tampered_nonce = generate_challenge_nonce(32)
    assert verify_ecdsa_signature(pub, sig, tampered_nonce) is False

    # Corrupted signature
    bad_sig = bytearray(sig)
    bad_sig[-1] ^= 0xFF
    assert verify_ecdsa_signature(pub, bytes(bad_sig), nonce) is False

    # Signature with different key
    other_priv = ec.generate_private_key(ec.SECP256R1())
    assert verify_ecdsa_signature(other_priv.public_key(), sig, nonce) is False


def test_crockford_base32_code() -> None:
    code = generate_crockford_code(8)
    assert len(code) == 8
    assert all(c in CROCKFORD_ALPHABET for c in code)

    # Normalization tests with 8 characters (including hyphen stripping and I/L/O transliteration)
    raw_input = "ab1L-0o23"
    normalized = normalize_crockford_code(raw_input)
    assert len(normalized) == 8
    assert normalized == "AB110023"

    # Invalid length rejection
    with pytest.raises(ValueError, match="Invalid code length"):
        normalize_crockford_code("short")

    with pytest.raises(ValueError, match="Invalid code length"):
        normalize_crockford_code("waytoolongstring123")

    # Invalid character rejection (e.g. U is excluded in Crockford Base32, punctuation)
    with pytest.raises(ValueError, match="Invalid Crockford Base32 character"):
        normalize_crockford_code("AB12345U")

    with pytest.raises(ValueError, match="Invalid Crockford Base32 character"):
        normalize_crockford_code("AB12!456")
