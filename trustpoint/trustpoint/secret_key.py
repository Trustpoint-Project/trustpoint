# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Read signing keys and provision private local-development key files."""

import os
import secrets
import tempfile
from contextlib import suppress
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

MAX_SIGNING_KEY_LENGTH = 4096


def load_secret_key(path: str, *, strip_whitespace: bool = True) -> str:
    """Require a readable, nonempty signing-key file."""
    try:
        with Path(path).open(encoding='utf-8') as stream:
            raw_value = stream.read(MAX_SIGNING_KEY_LENGTH + 1)
    except (OSError, UnicodeError) as exception:
        msg = 'The Django signing-key file cannot be read. Check DJANGO_SECRET_KEY_FILE and its permissions.'
        raise ImproperlyConfigured(msg) from exception
    value = raw_value.strip()
    if not value or len(raw_value) > MAX_SIGNING_KEY_LENGTH:
        msg = 'The Django signing-key file must contain a nonempty key of at most 4096 characters.'
        raise ImproperlyConfigured(msg)
    return value if strip_whitespace else raw_value


def _create_development_key(path: Path, value: str) -> None:
    """Publish a private local key atomically without replacing a concurrent winner."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.development-key-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        with suppress(FileExistsError):
            os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink()


def development_secret_key(path: Path) -> str:
    """Keep a local development key outside source control; production never calls this."""
    if not path.exists():
        _create_development_key(path, secrets.token_urlsafe(64))
    return load_secret_key(str(path), strip_whitespace=False)


def development_software_kek(path: Path, *, allow_creation: bool = False) -> Path:
    """Locate the local KEK; callers may permit creation only for a locked, fresh backend."""
    if path.is_symlink() or any(parent.is_symlink() for parent in path.absolute().parents):
        msg = 'The local development software KEK path must not contain symlinks.'
        raise ImproperlyConfigured(msg)
    if allow_creation and not path.exists():
        _create_development_key(path, secrets.token_hex(32))
    return path
