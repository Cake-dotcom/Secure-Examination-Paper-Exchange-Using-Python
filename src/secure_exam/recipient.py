"""Verify first, decrypt second, publish plaintext only after authentication."""

from pathlib import Path

from .crypto_utils import authenticated_decrypt, unwrap, verify
from .exceptions import RecipientError
from .key_manager import load_private, load_public
from .package_format import aad_bytes, decode, package_limit, parse, unsigned_bytes
from .validation import DEFAULT_MAX_SIZE, atomic_write, read_bounded, safe_filename


def decrypt(package_path: Path, output_dir: Path, sender_public: Path, recipient_private: Path,
            password: bytes, *, sender_id: str = "faculty", recipient_id: str = "coordinator",
            max_size: int = DEFAULT_MAX_SIZE, force: bool = False) -> Path:
    """No plaintext output or temporary plaintext exists before both checks pass."""
    package = parse(read_bounded(package_path, package_limit(max_size)), max_size)
    trusted_sender = load_public(sender_public)
    verify(unsigned_bytes(package), decode(package["signature"]), trusted_sender)
    if package["recipient"] != recipient_id or package["sender"] != sender_id:
        raise RecipientError("Authenticated package identity does not match configured participant")
    private = load_private(recipient_private, password)
    session_key = unwrap(decode(package["encrypted_key"]), private)
    plaintext = authenticated_decrypt(session_key, decode(package["nonce"]),
                                      decode(package["ciphertext"]), decode(package["tag"]), aad_bytes(package))
    target = output_dir / safe_filename(package["filename"])
    atomic_write(target, plaintext, force=force, private=True)
    return target
