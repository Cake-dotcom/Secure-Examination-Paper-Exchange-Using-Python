"""Sender-side hybrid encryption and signing."""

from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_utils import oaep, sign
from .key_manager import load_private, load_public
from .package_format import ALGORITHMS, aad_bytes, canonical, encode, unsigned_bytes, validate
from .validation import DEFAULT_MAX_SIZE, atomic_write, random_bytes, read_bounded, safe_filename


def encrypt(input_path: Path, package_path: Path, sender_private: Path, recipient_public: Path,
            password: bytes, *, sender_id: str = "faculty", recipient_id: str = "coordinator",
            max_size: int = DEFAULT_MAX_SIZE, force: bool = False) -> Path:
    """Encrypt binary input with fresh AES material and sign the whole envelope."""
    filename = safe_filename(input_path.name)
    plaintext = read_bounded(input_path, max_size)
    private = load_private(sender_private, password)
    public = load_public(recipient_public)
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = random_bytes(12)
    package = {
        "version": 1, "sender": sender_id, "recipient": recipient_id, "filename": filename,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "algorithms": dict(ALGORITHMS), "nonce": encode(nonce),
    }
    encrypted = AESGCM(session_key).encrypt(nonce, plaintext, aad_bytes(package))
    package.update(encrypted_key=encode(public.encrypt(session_key, oaep())),
                   ciphertext=encode(encrypted[:-16]), tag=encode(encrypted[-16:]))
    package["signature"] = encode(sign(unsigned_bytes(package), private))
    validate(package, max_size)
    atomic_write(package_path, canonical(package), force=force)
    return package_path
