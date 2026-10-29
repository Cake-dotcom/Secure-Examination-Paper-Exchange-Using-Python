"""Established cryptographic primitives with fixed version-1 parameters."""

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import AuthenticationError, KeyError, SignatureError


def oaep() -> padding.OAEP:
    """Version 1 uses the fixed OAEP label None (empty label)."""
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def pss() -> padding.PSS:
    """PSS salt length is exactly the SHA-256 digest size: 32 bytes."""
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def sign(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return key.sign(data, pss(), hashes.SHA256())


def verify(data: bytes, signature: bytes, key: rsa.RSAPublicKey) -> None:
    try:
        key.verify(signature, data, pss(), hashes.SHA256())
    except InvalidSignature as exc:
        raise SignatureError("Sender signature verification failed") from exc


def unwrap(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    try:
        session_key = key.decrypt(data, oaep())
    except ValueError as exc:
        raise KeyError("RSA-OAEP session-key decryption failed") from exc
    if len(session_key) != 32:
        raise KeyError("Recovered AES key has invalid length")
    return session_key


def authenticated_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise AuthenticationError("AES-GCM authentication failed") from exc
