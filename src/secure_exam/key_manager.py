"""Encrypted RSA key storage and explicitly trusted public-key exchange."""

from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .exceptions import KeyError, OutputError
from .validation import atomic_write, check_path, read_bounded


def validate_key(key: object, private: bool = False) -> None:
    expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
    if not isinstance(key, expected) or key.key_size != 4096:
        raise KeyError("Expected an RSA-4096 key")
    public = key.public_key() if private else key
    if public.public_numbers().e != 65537:
        raise KeyError("Expected RSA public exponent 65537")


def load_private(path: Path, password: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(read_bounded(path, 32768), password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyError("Cannot load encrypted private key; check key and password") from exc
    validate_key(key, private=True)
    return key


def load_public(path: Path) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(read_bounded(path, 32768))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyError("Cannot load public key") from exc
    validate_key(key)
    return key


def public_bytes(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def generate_keys(directory: Path, role: str, password: bytes, *, force: bool = False) -> None:
    """Create one participant's encrypted private key and public key."""
    if role not in {"sender", "recipient"} or not password or len(password) > 1023:
        raise KeyError("A valid role and a 1-1023 byte private-key password are required")
    private_path = directory / f"{role}_private.pem"
    public_path = directory / f"{role}_public.pem"
    for path in (private_path, public_path):
        check_path(path)
        if path.exists() and not force:
            raise OutputError("Keys already exist; use --force deliberately")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(password))
    atomic_write(private_path, pem, force=force, private=True)
    atomic_write(public_path, public_bytes(key.public_key()), force=force)


def exchange_public_keys(root: Path, *, force: bool = False) -> None:
    """Simulate an authenticated channel; never copy private keys."""
    for owner, peer in (("sender", "recipient"), ("recipient", "sender")):
        source = root / owner / "keys" / f"{owner}_public.pem"
        target = root / peer / "keys" / f"{owner}_public.pem"
        data = public_bytes(load_public(source))
        if target.exists() and not force:
            if read_bounded(target, 32768) != data:
                raise OutputError("Trusted public key differs; explicit --force required")
            continue
        atomic_write(target, data, force=force)
