"""Acceptance A-L plus strict parsing, key-policy, file safety and CLI checks."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from secure_exam import crypto_utils
from secure_exam.cli import main
from secure_exam.exceptions import (AuthenticationError, ExchangeError, KeyError, OutputError,
                                    RecipientError, SignatureError, ValidationError)
from secure_exam.key_manager import generate_keys, load_private, load_public, public_bytes
from secure_exam.package_format import (aad_bytes, canonical, decode, encode, parse, unsigned_bytes)
from secure_exam.recipient import decrypt
from secure_exam.sender import encrypt
from secure_exam.simulation import deliver, setup, tamper
from secure_exam.validation import atomic_write, read_bounded


def receive(env, **options):
    root = env["root"]
    return decrypt(options.pop("package", env["package"]), options.pop("output", env["output"]),
                   options.pop("public", root / "recipient/keys/sender_public.pem"),
                   options.pop("private", root / "recipient/keys/recipient_private.pem"),
                   options.pop("password", env["password"]), **options)


def snapshot(directory: Path) -> dict:
    return {p.relative_to(directory).as_posix(): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


def rejected(env, error=ExchangeError, **options):
    """Every negative receive checks both absence and preservation of all output."""
    before = snapshot(env["output"])
    with pytest.raises(error):
        receive(env, **options)
    assert snapshot(env["output"]) == before
    assert not (env["output"] / env["source"].name).exists()
    assert not list(env["output"].glob(".secure-exam-*.tmp"))


def modified(env, mutate, *, signing_key=None):
    package = parse(env["package"].read_bytes())
    mutate(package)
    if signing_key:
        package["signature"] = encode(crypto_utils.sign(unsigned_bytes(package), signing_key))
    path = env["root"] / "attacker/modified.secure"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(canonical(package))
    return path


def flip(package, field):
    value = bytearray(decode(package[field]))
    value[0] ^= 1
    package[field] = encode(bytes(value))


def test_A_authorised_transfer(exchange):
    env = exchange
    inbox = env["root"] / "transfer/inbox/exam_paper.secure"
    deliver(env["package"], inbox)
    assert receive(env, package=inbox).read_bytes() == env["source"].read_bytes()
    assert (env["output"] / "existing.txt").read_bytes() == b"must remain unchanged"


@pytest.mark.parametrize("field", ["ciphertext", "signature", "nonce", "encrypted_key", "tag"])
def test_B_D_negative_tampered_binary(exchange, field):
    path = modified(exchange, lambda p: flip(p, field))
    rejected(exchange, SignatureError, package=path)


@pytest.mark.parametrize("field,value", [("recipient", "attacker"), ("sender", "other-faculty"),
                                         ("filename", "different.txt"), ("created_utc", "2025-01-01T00:00:00Z")])
def test_C_negative_metadata(exchange, field, value):
    rejected(exchange, SignatureError, package=modified(exchange, lambda p: p.update({field: value})))


def test_E_negative_wrong_recipient_private_key(exchange, keys):
    path = exchange["root"] / "third_private.pem"
    path.write_bytes(keys[2].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.BestAvailableEncryption(exchange["password"])))
    rejected(exchange, KeyError, private=path)


def test_F_negative_wrong_sender_public_key(exchange, keys):
    path = exchange["root"] / "third_public.pem"
    path.write_bytes(public_bytes(keys[2].public_key()))
    rejected(exchange, SignatureError, public=path)


def test_G_same_file_twice(exchange):
    env = exchange
    root = env["root"]
    second = root / "transfer/outbox/second.secure"
    encrypt(env["source"], second, root / "sender/keys/sender_private.pem",
            root / "sender/keys/recipient_public.pem", env["password"])
    first_p, second_p = parse(env["package"].read_bytes()), parse(second.read_bytes())
    for field in ("encrypted_key", "nonce", "ciphertext", "signature"):
        assert first_p[field] != second_p[field]
    # OAEP is randomized even for an identical key: inspect actual AES keys too.
    recipient_key = load_private(root / "recipient/keys/recipient_private.pem", env["password"])
    assert crypto_utils.unwrap(decode(first_p["encrypted_key"]), recipient_key) != crypto_utils.unwrap(
        decode(second_p["encrypted_key"]), recipient_key)
    assert receive(env).read_bytes() == env["source"].read_bytes()
    assert receive(env, package=second, output=root / "recipient/second").read_bytes() == env["source"].read_bytes()


MALFORMED = [
    ("missing", lambda p: p.pop("tag")),
    ("extra", lambda p: p.update(extra="ambiguous")),
    ("base64", lambda p: p.update(ciphertext="!?")),
    ("base64_pad_bits", lambda p: p.update(nonce=encode(b"a" * 12) + "=")),
    ("version", lambda p: p.update(version=2)),
    ("bool_version", lambda p: p.update(version=True)),
    ("type", lambda p: p.update(sender=[])),
    ("nonce_short", lambda p: p.update(nonce=encode(b"a" * 11))),
    ("tag_short", lambda p: p.update(tag=encode(b"a" * 15))),
    ("tag_type", lambda p: p.update(tag=12)),
    ("signature_short", lambda p: p.update(signature=encode(b"a" * 511))),
    ("key_short", lambda p: p.update(encrypted_key=encode(b"a" * 511))),
    ("algorithms", lambda p: p["algorithms"].update(content="AES-CBC")),
    ("timestamp", lambda p: p.update(created_utc="2026-02-30T00:00:00Z")),
    ("truncated_ciphertext", lambda p: p.update(ciphertext=encode(decode(p["ciphertext"])[:-1]))),
]


@pytest.mark.parametrize("name,mutate", MALFORMED, ids=[item[0] for item in MALFORMED])
def test_H_negative_fields(exchange, name, mutate):
    rejected(exchange, package=modified(exchange, mutate))


@pytest.mark.parametrize("data", [b"{", b"null", b"[]", b"\xff", b'{"version":1,"version":1}',
                                   b'{"v":NaN}', b"[" * 1500 + b"]" * 1500])
def test_H_negative_json(exchange, data):
    path = exchange["root"] / "malformed.secure"
    path.write_bytes(data)
    rejected(exchange, ValidationError, package=path)


@pytest.mark.parametrize("mode", ["whitespace", "duplicate", "nested_duplicate", "escaped_key", "trailing"])
def test_H_negative_ambiguous_json(exchange, mode):
    data = exchange["package"].read_bytes()
    if mode == "whitespace":
        data = b" " + data
    elif mode == "duplicate":
        data = data.replace(b'"version":1', b'"version":1,"version":1')
    elif mode == "nested_duplicate":
        data = data.replace(b'"content":"AES-256-GCM"', b'"content":"AES-256-GCM","content":"AES-256-GCM"')
    elif mode == "escaped_key":
        data = data.replace(b'"version"', b'"\\u0076ersion"')
    else:
        data += b"{}"
    path = exchange["root"] / "ambiguous.secure"
    path.write_bytes(data)
    rejected(exchange, ValidationError, package=path)


def test_I_negative_recipient_binding(exchange, keys):
    path = modified(exchange, lambda p: p.update(recipient="different-coordinator"), signing_key=keys[0])
    rejected(exchange, RecipientError, package=path)


def test_negative_sender_binding(exchange, keys):
    path = modified(exchange, lambda p: p.update(sender="different-faculty"), signing_key=keys[0])
    rejected(exchange, RecipientError, package=path)


@pytest.mark.parametrize("filename", ["../outside.txt", "/absolute.txt", "C:\\absolute.txt", "..\\outside.txt",
                                       "", ".", "..", "file\x00.txt", "a/b.txt", "a:b.txt", "CON.txt",
                                       "COM1", "trailing.", "trailing ", 42, "a" * 121, "exam\n.txt"])
def test_J_negative_unsafe_filename(exchange, keys, filename):
    before = snapshot(exchange["root"])
    path = modified(exchange, lambda p: p.update(filename=filename), signing_key=keys[0])
    rejected(exchange, ValidationError, package=path)
    after = snapshot(exchange["root"])
    assert {k: v for k, v in after.items() if k != "attacker/modified.secure"} == before


def test_J_negative_existing_output(exchange):
    target = exchange["output"] / exchange["source"].name
    target.write_bytes(b"previous examination")
    before = snapshot(exchange["output"])
    with pytest.raises(OutputError):
        receive(exchange)
    assert snapshot(exchange["output"]) == before
    assert receive(exchange, force=True).read_bytes() == exchange["source"].read_bytes()


@pytest.mark.parametrize("field", ["tag", "ciphertext", "nonce"])
def test_K_negative_valid_signature_gcm_failure(exchange, keys, field):
    path = modified(exchange, lambda p: flip(p, field), signing_key=keys[0])
    rejected(exchange, AuthenticationError, package=path)


def test_K_negative_valid_signature_aad_failure(exchange, keys):
    path = modified(exchange, lambda p: p.update(filename="other.bin"), signing_key=keys[0])
    rejected(exchange, AuthenticationError, package=path)


def test_L_private_key_separation(exchange):
    root = exchange["root"]
    assert not list((root / "sender").rglob("recipient_private.pem"))
    assert not list((root / "recipient").rglob("sender_private.pem"))
    deliver(exchange["package"], root / "transfer/inbox/exam_paper.secure")
    for path in (root / "transfer").rglob("*"):
        if path.is_file():
            assert path.suffix == ".secure"
            assert b"PRIVATE KEY" not in path.read_bytes()
            assert exchange["source"].read_bytes() not in path.read_bytes()


def test_negative_wrong_password(exchange):
    rejected(exchange, KeyError, password=b"incorrect")


def test_negative_package_size(exchange):
    rejected(exchange, ValidationError, max_size=32)


def test_negative_source_size(exchange):
    root = exchange["root"]
    before = snapshot(exchange["output"])
    target = root / "too-large.secure"
    with pytest.raises(ValidationError):
        encrypt(exchange["source"], target, root / "sender/keys/sender_private.pem",
                root / "sender/keys/recipient_public.pem", exchange["password"], max_size=1)
    assert not target.exists()
    assert snapshot(exchange["output"]) == before


def test_negative_keys_no_silent_overwrite(exchange):
    directory = exchange["root"] / "sender/keys"
    before = snapshot(directory)
    with pytest.raises(OutputError):
        generate_keys(directory, "sender", exchange["password"])
    assert snapshot(directory) == before
    assert snapshot(exchange["output"]) == {"existing.txt": b"must remain unchanged"}


@pytest.mark.parametrize("kind", ["small-rsa", "ec", "bad-exponent"])
def test_negative_key_type_size(tmp_path, kind):
    if kind == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=3 if kind == "bad-exponent" else 65537,
                                       key_size=4096 if kind == "bad-exponent" else 2048)
    path = tmp_path / "public.pem"
    path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(KeyError):
        load_public(path)
    assert not (tmp_path / "output").exists()


def test_negative_invalid_recovered_key_length(exchange, keys):
    package = modified(exchange, lambda p: p.update(encrypted_key=encode(keys[1].public_key().encrypt(b"short", crypto_utils.oaep()))),
                       signing_key=keys[0])
    rejected(exchange, KeyError, package=package)


@pytest.mark.parametrize("location", ["file", "directory"])
def test_J_negative_symlink(exchange, location):
    outside = exchange["root"] / "outside"
    outside.mkdir()
    sentinel = outside / exchange["source"].name
    sentinel.write_bytes(b"untouched")
    link = exchange["output"] / (exchange["source"].name if location == "file" else "link")
    try:
        link.symlink_to(sentinel if location == "file" else outside, target_is_directory=location == "directory")
    except OSError:
        pytest.skip("OS does not permit creating symlinks for this account")
    before = snapshot(exchange["output"])
    with pytest.raises(OutputError):
        receive(exchange, output=link if location == "directory" else exchange["output"], force=True)
    assert snapshot(exchange["output"]) == before
    assert sentinel.read_bytes() == b"untouched"


def test_empty_file(exchange):
    env = exchange
    env["source"].write_bytes(b"")
    root = env["root"]
    encrypt(env["source"], env["package"], root / "sender/keys/sender_private.pem",
            root / "sender/keys/recipient_public.pem", env["password"], force=True)
    assert receive(env).read_bytes() == b""


def test_setup_repeat_preserves_keys_and_input(exchange):
    env = exchange
    root = env["root"]
    setup(root, env["password"], env["password"])
    before = snapshot(root / "sender")
    setup(root, env["password"], env["password"])
    assert snapshot(root / "sender") == before
    private_data = (root / "sender/keys/sender_private.pem").read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in private_data


@pytest.mark.parametrize("kind", ["ciphertext", "metadata", "signature"])
def test_negative_attacker_command(exchange, kind):
    before = exchange["package"].read_bytes()
    target = exchange["root"] / "attacker" / f"{kind}.secure"
    tamper(exchange["package"], target, kind)
    assert exchange["package"].read_bytes() == before
    rejected(exchange, SignatureError, package=target)


def test_negative_attack_same_path(exchange):
    before = exchange["package"].read_bytes()
    with pytest.raises(OutputError):
        tamper(exchange["package"], exchange["package"], "ciphertext", force=True)
    assert exchange["package"].read_bytes() == before
    assert snapshot(exchange["output"]) == {"existing.txt": b"must remain unchanged"}


def test_cli_workflow(exchange, monkeypatch, capsys):
    env = exchange
    root = env["root"]
    monkeypatch.setenv("SECURE_EXAM_SENDER_PASSWORD", env["password"].decode())
    monkeypatch.setenv("SECURE_EXAM_RECIPIENT_PASSWORD", env["password"].decode())
    prefix = ["--root", str(root)]
    assert main(prefix + ["setup"]) == 0
    # The fixture's binary-input package uses the default CLI outbox basename.
    # Remove that test-owned fixture before exercising the text-input workflow.
    env["package"].unlink()
    assert main(prefix + ["encrypt"]) == 0
    assert main(prefix + ["deliver"]) == 0
    assert main(prefix + ["decrypt"]) == 0
    assert (root / "recipient/output/exam_paper.txt").read_bytes() == (root / "sender/input/exam_paper.txt").read_bytes()
    assert "VERIFIED" in capsys.readouterr().out
    assert main(prefix + ["simulate"]) == 0
    assert main(prefix + ["simulate"]) == 0


def test_negative_cli_tamper_exit(exchange, monkeypatch):
    monkeypatch.setenv("SECURE_EXAM_RECIPIENT_PASSWORD", exchange["password"].decode())
    before = snapshot(exchange["output"])
    path = modified(exchange, lambda p: flip(p, "signature"))
    assert main(["--root", str(exchange["root"]), "decrypt", str(path)]) == 1
    assert snapshot(exchange["output"]) == before


def test_verification_precedes_private_key_access(exchange, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Private key accessed before signature verification")
    monkeypatch.setattr("secure_exam.recipient.load_private", forbidden)
    rejected(exchange, SignatureError, package=modified(exchange, lambda p: flip(p, "tag")))


def test_negative_temporary_collision_preserves_existing_file(exchange, monkeypatch):
    output = exchange["output"]
    temporary = output / (".secure-exam-" + (b"x" * 16).hex() + ".tmp")
    temporary.write_bytes(b"pre-existing file")
    before = snapshot(output)
    monkeypatch.setattr("secure_exam.validation.random_bytes", lambda length: b"x" * length)
    with pytest.raises(OutputError):
        receive(exchange)
    assert snapshot(output) == before
    assert not (output / exchange["source"].name).exists()


def test_negative_publish_failure_cleans_temporary(exchange, monkeypatch):
    import os

    def fail(*args, **kwargs):
        raise PermissionError("test-only publication denial")

    monkeypatch.setattr("secure_exam.validation.os." + ("rename" if os.name == "nt" else "link"), fail)
    rejected(exchange, OutputError)
