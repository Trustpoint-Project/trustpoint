#!/usr/bin/env python3
# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provision one host-side Compose signing key; never replace an existing key."""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
import tempfile
from pathlib import Path

MAX_KEY_LENGTH = 4096
ROOT_USER_ID = 0
SECRET_MODE = 0o440
DEFAULT_GROUP_ID = 33  # www-data in the shipped application image.


def validate_key(value: str) -> None:
    """Reject missing/invalid material without exposing its contents."""
    if not value.strip() or len(value) > MAX_KEY_LENGTH:
        msg = 'Signing key must be nonempty and at most 4096 characters.'
        raise ValueError(msg)


def read_key(path: Path) -> str:
    """Read bounded key material, preserving its exact value for migration."""
    with path.open(encoding='utf-8', newline='') as stream:
        value = stream.read(MAX_KEY_LENGTH + 1)
    validate_key(value)
    return value


def keep_existing(path: Path, group_id: int, import_from: Path | None) -> bool:
    """Validate an existing file without changing its bytes or permissions."""
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        msg = 'Secret destination must be a regular file.'
        raise ValueError(msg)
    existing_value = read_key(path)
    if metadata.st_uid != ROOT_USER_ID or metadata.st_gid != group_id or stat.S_IMODE(metadata.st_mode) != SECRET_MODE:
        msg = f'Existing key left unchanged. Set its owner to root, group to {group_id}, and mode to 0440 explicitly.'
        raise PermissionError(msg)
    if import_from and read_key(import_from) != existing_value:
        msg = 'Destination contains a different key and was left unchanged. Resolve the conflict explicitly.'
        raise FileExistsError(msg)
    return False


def initialize_secret(path: Path, *, group_id: int = DEFAULT_GROUP_ID, import_from: Path | None = None) -> bool:
    """Create a private key atomically, returning False when the destination exists."""
    if os.geteuid() != 0:
        msg = 'Run with sudo so the secret can be root-owned and readable by container group 33.'
        raise PermissionError(msg)
    if path.is_symlink():
        msg = 'Refusing a symlinked secret destination.'
        raise ValueError(msg)
    if path.exists():
        return keep_existing(path, group_id, import_from)
    value = read_key(import_from) if import_from else secrets.token_urlsafe(64)
    if path.parent.is_symlink():
        msg = 'Refusing a symlinked secrets directory.'
        raise ValueError(msg)
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700, parents=True)
        # The invoking administrator can traverse the directory for Compose to
        # stat the source file; only root and container group 33 can read the key.
        os.chown(
            path.parent,
            int(os.environ.get('SUDO_UID', str(os.getuid()))),
            int(os.environ.get('SUDO_GID', str(os.getgid()))),
        )
    descriptor, temporary = tempfile.mkstemp(prefix='.django-key-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            os.fchown(stream.fileno(), ROOT_USER_ID, group_id)
            os.fchmod(stream.fileno(), SECRET_MODE)
            stream.write(value)
        try:
            os.link(temporary, path)
        except FileExistsError:
            return initialize_secret(path, group_id=group_id, import_from=import_from)
    finally:
        Path(temporary).unlink()
    return True


def main() -> None:
    """Generate or explicitly import a deployment key without printing it."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--path', type=Path, default=Path(__file__).resolve().parent.parent / 'secrets/django_secret_key'
    )
    parser.add_argument('--import-from', type=Path, help='Copy an existing key exactly, instead of generating one.')
    parser.add_argument('--group-id', type=int, default=DEFAULT_GROUP_ID, help='Django container group (default: 33).')
    args = parser.parse_args()
    try:
        created = initialize_secret(args.path, group_id=args.group_id, import_from=args.import_from)
    except (OSError, ValueError) as exception:
        parser.exit(1, f'Cannot initialize Django signing key: {exception}\n')
    sys.stdout.write(f'{"Created" if created else "Kept existing"} signing-key file: {args.path}\n')


if __name__ == '__main__':
    main()
