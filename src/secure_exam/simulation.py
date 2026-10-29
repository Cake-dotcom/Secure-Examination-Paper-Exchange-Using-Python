"""Local participant setup, explicit delivery, and attacker copies."""

from pathlib import Path

from .exceptions import OutputError, ValidationError
from .key_manager import exchange_public_keys, generate_keys, load_private, load_public
from .package_format import canonical, decode, encode, package_limit, parse
from .validation import DEFAULT_MAX_SIZE, atomic_write, check_path, read_bounded

SAMPLE = b"CONFIDENTIAL - Demonstration Examination\nCourse: Applied Cryptography\n1. Explain authenticated encryption.\n2. Compare RSA-OAEP and RSA-PSS.\n"


def setup(root: Path, sender_password: bytes, recipient_password: bytes, *, force: bool = False) -> None:
    """Idempotent setup; partial key sets require deliberate repair with force."""
    for folder in ("sender", "recipient", "transfer", "attacker", "sender/input", "sender/keys", "recipient/keys", "recipient/output",
                   "transfer/outbox", "transfer/inbox", "attacker/modified_packages", "samples", "results"):
        path = root / folder
        check_path(path)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    for role, password in (("sender", sender_password), ("recipient", recipient_password)):
        directory = root / role / "keys"
        private = directory / f"{role}_private.pem"
        public = directory / f"{role}_public.pem"
        if force or not (private.exists() or public.exists()):
            generate_keys(directory, role, password, force=force)
        elif private.exists() and public.exists():
            key = load_private(private, password)
            if key.public_key().public_numbers() != load_public(public).public_numbers():
                raise ValidationError("Participant key pair does not match")
        else:
            raise OutputError("Incomplete key pair; repair with deliberate --force")
    exchange_public_keys(root, force=force)
    for path in (root / "sender/input/exam_paper.txt", root / "samples/exam_paper.txt"):
        if not path.exists():
            atomic_write(path, SAMPLE)


def deliver(source: Path, target: Path, *, max_size: int = DEFAULT_MAX_SIZE, force: bool = False) -> Path:
    """Copy only a validated encrypted package across the simulated channel."""
    data = read_bounded(source, package_limit(max_size))
    parse(data, max_size)
    atomic_write(target, data, force=force)
    return target


def tamper(source: Path, target: Path, kind: str, *, force: bool = False) -> Path:
    """Mutate only a separate package copy; never update its signature."""
    if source.resolve() == target.resolve():
        raise OutputError("Attacks must write a separate copy")
    package = parse(read_bounded(source, package_limit(DEFAULT_MAX_SIZE)))
    if kind == "metadata":
        package["recipient"] = "attacker"
    elif kind in {"ciphertext", "signature", "tag", "encrypted_key", "nonce"}:
        data = bytearray(decode(package[kind]))
        if not data:
            raise ValidationError("Cannot flip a byte in an empty field")
        data[0] ^= 1
        package[kind] = encode(bytes(data))
    else:
        raise ValidationError("Unknown attack type")
    atomic_write(target, canonical(package), force=force)
    return target
