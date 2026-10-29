"""Reproduce submission samples through supported CLI commands, without key rotation."""
import hashlib
import json
import os
from pathlib import Path
from secure_exam.cli import main
from secure_exam.package_format import parse, decode
from secure_exam.crypto_utils import unwrap
from secure_exam.key_manager import load_private
from secure_exam.validation import random_bytes


def require(condition: bool, message: str) -> None:
    """Keep verification active even when Python optimization is enabled."""
    if not condition:
        raise RuntimeError(message)


def run() -> None:
    root = Path(__file__).resolve().parents[1]
    workspace = root / "results" / ("workshop-" + random_bytes(8).hex())
    source = workspace / "sender/input/exam_paper.txt"
    source.parent.mkdir(parents=True)
    source.write_bytes((root / "sender/input/exam_paper.txt").read_bytes())
    names = [f"SECURE_EXAM_{role}_PASSWORD" for role in ("SENDER", "RECIPIENT")]
    previous = {name: os.environ.get(name) for name in names}
    commands = []
    try:
        for name in names:
            os.environ[name] = random_bytes(32).hex()
        for args in (["setup"], ["simulate"], ["encrypt"], ["deliver"], ["decrypt"],
                     ["encrypt", "--output", "transfer/outbox/second.secure"]):
            commands.append(["--root", str(workspace), *args])
            require(main(commands[-1]) == 0, "CLI workflow command failed")
        first = workspace / "transfer/outbox/exam_paper.secure"
        second = workspace / "transfer/outbox/second.secure"
        p, q = parse(first.read_bytes()), parse(second.read_bytes())
        key = load_private(workspace / "recipient/keys/recipient_private.pem", os.environ[names[1]].encode())
        require(unwrap(decode(p["encrypted_key"]), key) != unwrap(decode(q["encrypted_key"]), key), "AES keys unexpectedly match")
        require(p["nonce"] != q["nonce"] and p["ciphertext"] != q["ciphertext"], "Repeated encryption did not differ")
        commands.append(["--root", str(workspace), "decrypt", "--package", str(second), "--output", "recipient/second"])
        require(main(commands[-1]) == 0, "Second package decryption failed")
        for destination in ("recipient/output", "recipient/second"):
            require((workspace / destination / source.name).read_bytes() == source.read_bytes(), "Recovered bytes differ")
        # New names preserve historical samples and their associated public keys.
        (root / "samples/workshop_exam_paper.secure").write_bytes(first.read_bytes())
        (root / "samples/workshop_sender_public.pub").write_bytes((workspace / "recipient/keys/sender_public.pem").read_bytes())
        report = {"workspace": str(workspace), "commands": commands,
                  "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "bytes": source.stat().st_size, "both_recoveries_identical": True,
                  "distinct_actual_aes_keys": True, "distinct_nonces": True,
                  "distinct_packages": first.read_bytes() != second.read_bytes()}
        (root / "results/workshop_verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


if __name__ == "__main__":
    run()
