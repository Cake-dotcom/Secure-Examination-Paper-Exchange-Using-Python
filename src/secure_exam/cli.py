"""Argparse interface. Exit codes: 0 success, 1 rejected/I/O, 2 usage."""

import argparse
import getpass
import logging
import os
from pathlib import Path
import subprocess
import sys

from .exceptions import ExchangeError, KeyError
from .key_manager import generate_keys
from .recipient import decrypt
from .sender import encrypt
from .simulation import deliver, setup, tamper
from .validation import DEFAULT_MAX_SIZE, random_bytes, read_bounded

LOG = logging.getLogger("secure_exam")


def password(role: str, *, confirm: bool = False) -> bytes:
    """Read role-specific environment variable or prompt without echo."""
    value = os.environ.get(f"SECURE_EXAM_{role.upper()}_PASSWORD")
    if value is None:
        value = getpass.getpass(f"{role.title()} private-key password: ")
        if confirm and value != getpass.getpass("Confirm password: "):
            raise KeyError("Passwords do not match")
    if not value:
        raise KeyError("Empty passwords are prohibited")
    return value.encode("utf-8")


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="Secure examination-paper exchange")
    cli.add_argument("--root", type=Path, default=Path.cwd(), help="Participant workspace (before subcommand)")
    cli.add_argument("--verbose", action="store_true")
    sub = cli.add_subparsers(dest="command", required=True)
    for name in ("setup", "simulate"):
        command = sub.add_parser(name)
        if name == "setup":
            command.add_argument("--force", action="store_true", help="Deliberately replace both key pairs and pinned public keys")
    command = sub.add_parser("generate-keys")
    command.add_argument("role", choices=("sender", "recipient"))
    command.add_argument("--output", type=Path, help="Key directory; default ROOT/ROLE/keys")
    command.add_argument("--force", action="store_true")
    command = sub.add_parser("encrypt")
    command.add_argument("input", nargs="?", type=Path)
    command.add_argument("--input", dest="input_option", type=Path)
    command.add_argument("--output", type=Path)
    command.add_argument("--sender-id", default="faculty")
    command.add_argument("--recipient-id", default="coordinator")
    command.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    command.add_argument("--force", action="store_true")
    command = sub.add_parser("decrypt")
    command.add_argument("package", nargs="?", type=Path)
    command.add_argument("--package", dest="package_option", type=Path)
    command.add_argument("--output", type=Path, help="Recipient output directory")
    command.add_argument("--sender-id", default="faculty")
    command.add_argument("--recipient-id", default="coordinator")
    command.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    command.add_argument("--force", action="store_true")
    command = sub.add_parser("deliver")
    command.add_argument("--package", type=Path)
    command.add_argument("--output", type=Path)
    command.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    command.add_argument("--force", action="store_true")
    command = sub.add_parser("attack")
    command.add_argument("kind", choices=("ciphertext", "metadata", "signature", "nonce", "tag", "encrypted_key"))
    command.add_argument("--package", type=Path)
    command.add_argument("--output", type=Path)
    command.add_argument("--force", action="store_true")
    sub.add_parser("attack-demo", help="Run isolated automated attack scenarios, with PASS/FAIL per case")
    sub.add_parser("test", help="Run the full pytest suite")
    return cli


def run(args: argparse.Namespace) -> int:
    root = args.root.absolute()

    def local(path: Path | None, default: str) -> Path:
        chosen = path if path is not None else Path(default)
        return chosen if chosen.is_absolute() else root / chosen

    if args.command in {"test", "attack-demo"}:
        project = Path(__file__).resolve().parents[2]
        command = [sys.executable, "-m", "pytest", "-v", str(project / "tests")]
        if args.command == "attack-demo":
            command += ["-k", "negative"]
        return subprocess.call(command, cwd=project)
    if args.command == "setup":
        setup(root, password("sender", confirm=True), password("recipient", confirm=True), force=args.force)
        print("Setup complete; only public keys exchanged through the simulated trusted channel.")
    elif args.command == "generate-keys":
        generate_keys(local(args.output, f"{args.role}/keys"), args.role,
                      password(args.role, confirm=True), force=args.force)
        print(f"Generated encrypted RSA-4096 key pair for {args.role}.")
    elif args.command == "encrypt":
        source = local(args.input_option or args.input, "sender/input/exam_paper.txt")
        target = local(args.output, f"transfer/outbox/{source.stem}.secure")
        encrypt(source, target, root / "sender/keys/sender_private.pem",
                root / "sender/keys/recipient_public.pem", password("sender"), sender_id=args.sender_id,
                recipient_id=args.recipient_id, max_size=args.max_size, force=args.force)
        print(f"Encrypted and signed package saved: {target}")
    elif args.command == "deliver":
        source = local(args.package, "transfer/outbox/exam_paper.secure")
        target = local(args.output, f"transfer/inbox/{source.name}")
        deliver(source, target, max_size=args.max_size, force=args.force)
        print(f"Delivered encrypted package: {target}")
    elif args.command == "decrypt":
        output = decrypt(local(args.package_option or args.package, "transfer/inbox/exam_paper.secure"),
                         local(args.output, "recipient/output"), root / "recipient/keys/sender_public.pem",
                         root / "recipient/keys/recipient_private.pem", password("recipient"),
                         sender_id=args.sender_id, recipient_id=args.recipient_id,
                         max_size=args.max_size, force=args.force)
        print(f"Recovered {output.name}: sender signature and AES-GCM authentication VERIFIED. Saved: {output}")
    elif args.command == "attack":
        output = tamper(local(args.package, "transfer/outbox/exam_paper.secure"),
                        local(args.output, f"attacker/modified_packages/{args.kind}.secure"),
                        args.kind, force=args.force)
        print(f"Attacker copy created: {output}")
    elif args.command == "simulate":
        sender_password, recipient_password = password("sender", confirm=True), password("recipient", confirm=True)
        # Setup reuses existing matching keys; simulation never rotates keys.
        setup(root, sender_password, recipient_password)
        run_id = random_bytes(8).hex()
        source = root / "sender/input/exam_paper.txt"
        outbox = root / f"transfer/outbox/demo-{run_id}.secure"
        inbox = root / f"transfer/inbox/demo-{run_id}.secure"
        output_dir = root / f"recipient/output/demo-{run_id}"
        encrypt(source, outbox, root / "sender/keys/sender_private.pem",
                root / "sender/keys/recipient_public.pem", sender_password)
        deliver(outbox, inbox)
        result = decrypt(inbox, output_dir, root / "recipient/keys/sender_public.pem",
                         root / "recipient/keys/recipient_private.pem", recipient_password)
        if read_bounded(result, DEFAULT_MAX_SIZE) != read_bounded(source, DEFAULT_MAX_SIZE):
            raise ExchangeError("Demonstration byte comparison failed")
        print(f"PASS: signature verified, GCM authenticated, recovered file is byte-for-byte identical: {result}")
        print(f"Sample encrypted package: {inbox}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")
    try:
        return run(args)
    except (ExchangeError, OSError, EOFError) as exc:
        # OS exception text can include paths; do not print it or a traceback.
        LOG.error("%s", str(exc) if isinstance(exc, ExchangeError) else "Filesystem or password input operation failed")
        return 1
    except KeyboardInterrupt:
        LOG.error("Operation cancelled")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
