# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Read a deployment-provided Django signing key without exposing its value."""

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


def development_secret_key(path: Path) -> str:
    """Keep a local development key outside source control; production never calls this."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        descriptor, temporary = tempfile.mkstemp(prefix='.django-key-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                stream.write(secrets.token_urlsafe(64))
            with suppress(FileExistsError):
                os.link(temporary, path)
        finally:
            Path(temporary).unlink()
    return load_secret_key(str(path), strip_whitespace=False)
