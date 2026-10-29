"""Bounded input and conservative, cross-platform output handling."""

import os
import re
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import OutputError, ValidationError

DEFAULT_MAX_SIZE = 10 * 1024 * 1024


def random_bytes(length: int) -> bytes:
    """Use cryptography's OS-backed key generator for all random material."""
    return b"".join(AESGCM.generate_key(bit_length=256) for _ in range((length + 31) // 32))[:length]


def safe_filename(name: object) -> str:
    """Portable ASCII basename, including Windows device-name protection."""
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,119}", name):
        raise ValidationError("Invalid original filename")
    if name.endswith((".", " ")) or ".." in name:
        raise ValidationError("Unsafe original filename")
    stem = name.split(".")[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} or re.fullmatch(r"(?:COM|LPT)[0-9]", stem):
        raise ValidationError("Reserved original filename")
    return name


def check_path(path: Path) -> None:
    """Reject symlinks and Windows junction/reparse points in a path."""
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OutputError("Symlink or reparse-point path rejected")


def read_bounded(path: Path, limit: int) -> bytes:
    """Read at most limit+1 bytes, also checking regular-file status."""
    if type(limit) is not int or limit < 1:
        raise ValidationError("Maximum file size must be positive")
    check_path(path)
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValidationError("Input must be a regular file")
            data = stream.read(limit + 1)
    except OSError as exc:
        raise ValidationError("Cannot read input file") from exc
    if len(data) > limit:
        raise ValidationError("Input exceeds configured size limit")
    return data


def atomic_write(path: Path, data: bytes, *, force: bool = False, private: bool = False) -> None:
    """Stage in the destination directory, then publish with no clobber by default.

    Windows rename refuses an existing destination. Unix uses hard-link
    publication for atomic exclusive creation. No unsafe fallback is used.
    Output directories must not be writable by adversaries (see README).
    """
    check_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    check_path(path)
    if path.exists() and not force:
        raise OutputError("Output already exists; use --force deliberately")
    if path.exists() and not path.is_file():
        raise OutputError("Output is not a regular file")
    temporary = path.parent / (".secure-exam-" + random_bytes(16).hex() + ".tmp")
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        check_path(path)
        if force:
            os.replace(temporary, path)
        elif os.name == "nt":
            os.rename(temporary, path)
        else:
            os.link(temporary, path)
        if private and os.name != "nt":
            path.chmod(0o600)
    except OSError as exc:
        raise OutputError("Cannot safely publish output (exists, permissions, or filesystem limitation)") from exc
    finally:
        if created:
            temporary.unlink(missing_ok=True)
