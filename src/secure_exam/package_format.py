"""Strict JSON wire format and one deterministic canonical representation."""

import base64
import binascii
import json
import re
from datetime import datetime

from .exceptions import ValidationError
from .validation import DEFAULT_MAX_SIZE, safe_filename

ALGORITHMS = {
    "content": "AES-256-GCM",
    "key": "RSA-4096-OAEP-SHA256-MGF1-SHA256-LABEL-EMPTY",
    "signature": "RSA-4096-PSS-SHA256-MGF1-SHA256-SALT32",
}
METADATA = {"version", "sender", "recipient", "filename", "created_utc", "algorithms", "nonce"}
BINARY = {"encrypted_key": 512, "nonce": 12, "tag": 16, "signature": 512}
FIELDS = METADATA | {"encrypted_key", "ciphertext", "tag", "signature"}


def canonical(value: object) -> bytes:
    """UTF-8, sorted keys, no whitespace, ASCII escaping, no NaN/Infinity."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValidationError("Binary field must be a Base64 string")
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("Invalid Base64 encoding") from exc
    if encode(result) != value:
        raise ValidationError("Noncanonical Base64 encoding")
    return result


def unsigned_bytes(package: dict) -> bytes:
    """Signature covers every field except signature itself."""
    return canonical({key: value for key, value in package.items() if key != "signature"})


def aad_bytes(package: dict) -> bytes:
    """GCM authenticates exactly the seven METADATA fields, including nonce."""
    return canonical({key: package[key] for key in METADATA})


def package_limit(max_size: int) -> int:
    return 4 * ((max_size + 2) // 3) + 8192


def validate(package: object, max_size: int = DEFAULT_MAX_SIZE) -> dict:
    if type(package) is not dict or set(package) != FIELDS:
        raise ValidationError("Package must contain exactly the version-1 fields")
    if type(package["version"]) is not int or package["version"] != 1:
        raise ValidationError("Unsupported package version")
    for field in ("sender", "recipient"):
        if not isinstance(package[field], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}", package[field]):
            raise ValidationError("Invalid participant identifier")
    safe_filename(package["filename"])
    if package["algorithms"] != ALGORITHMS:
        raise ValidationError("Unsupported algorithm identifiers")
    timestamp = package["created_utc"]
    if not isinstance(timestamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp):
        raise ValidationError("Invalid UTC timestamp")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValidationError("Invalid UTC date") from exc
    for field, length in BINARY.items():
        if len(decode(package[field])) != length:
            raise ValidationError(f"Invalid {field} length")
    if len(decode(package["ciphertext"])) > max_size:
        raise ValidationError("Ciphertext exceeds configured size limit")
    return package


def _unique_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Duplicate JSON key")
        result[key] = value
    return result


def parse(data: bytes, max_size: int = DEFAULT_MAX_SIZE) -> dict:
    if len(data) > package_limit(max_size):
        raise ValidationError("Package exceeds configured size limit")
    try:
        package = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("Invalid JSON constant")))
        validate(package, max_size)
        # Wire bytes must themselves be canonical: reject alternate encodings,
        # whitespace, escaped equivalent keys, number spellings and trailing data.
        if canonical(package) != data:
            raise ValidationError("Package JSON is not canonical")
        return package
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise ValidationError("Malformed JSON package") from exc
