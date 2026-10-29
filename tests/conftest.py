"""Real RSA-4096 fixtures, reused for speed; participant files isolated per test."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from secure_exam.key_manager import public_bytes
from secure_exam.sender import encrypt


@pytest.fixture(scope="session")
def keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=4096) for _ in range(3)]


@pytest.fixture
def exchange(tmp_path, keys):
    # Random test password; never a project key or persisted secret.
    from secure_exam.validation import random_bytes
    password = random_bytes(24).hex().encode()
    for role, key in zip(("sender", "recipient"), keys[:2]):
        directory = tmp_path / role / "keys"
        directory.mkdir(parents=True)
        (directory / f"{role}_private.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password)))
        (directory / f"{role}_public.pem").write_bytes(public_bytes(key.public_key()))
    from secure_exam.key_manager import exchange_public_keys
    exchange_public_keys(tmp_path)
    source = tmp_path / "sender/input/exam_paper.bin"
    source.parent.mkdir()
    source.write_bytes(bytes(range(256)) * 5 + b"\x00\xffExam paper\r\n")
    package = tmp_path / "transfer/outbox/exam_paper.secure"
    encrypt(source, package, tmp_path / "sender/keys/sender_private.pem",
            tmp_path / "sender/keys/recipient_public.pem", password)
    output = tmp_path / "recipient/output"
    output.mkdir()
    (output / "existing.txt").write_bytes(b"must remain unchanged")
    return {"root": tmp_path, "password": password, "source": source, "package": package, "output": output}
