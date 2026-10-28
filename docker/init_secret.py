#!/usr/bin/env python3
# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provision host-side Compose secrets; never replace existing keys."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import stat
import sys
from pathlib import Path

MAX_KEY_LENGTH = 4096
ROOT_USER_ID = 0
SECRET_MODE = 0o440
DEFAULT_GROUP_ID = 33  # www-data in the shipped application image.


def validate_key(value: str, kind: str = 'django') -> None:
    """Reject missing/invalid material without exposing its contents."""
    if kind == 'kek':
        if re.fullmatch(r'[0-9a-fA-F]{64}', value) is None:
            msg = 'Software KEK must contain exactly 64 hexadecimal characters, without whitespace.'
            raise ValueError(msg)
        return
    if not value.strip() or len(value) > MAX_KEY_LENGTH:
        msg = 'Signing key must be nonempty and at most 4096 characters.'
        raise ValueError(msg)


def read_key(path: Path, kind: str = 'django') -> str:
    """Read bounded key material, preserving its exact value for migration."""
    with path.open(encoding='utf-8', newline='') as stream:
        value = stream.read(MAX_KEY_LENGTH + 1)
    validate_key(value, kind)
    return value


def keep_existing(parent_fd: int, name: str, group_id: int, import_from: Path | None, kind: str) -> bool:
    """Validate a pinned regular file without following or modifying symlinks."""
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    with os.fdopen(descriptor, encoding='utf-8', newline='') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            msg = 'Secret destination must be a regular file.'
            raise ValueError(msg)
        if (
            metadata.st_uid != ROOT_USER_ID
            or metadata.st_gid != group_id
            or stat.S_IMODE(metadata.st_mode) != SECRET_MODE
        ):
            msg = (
                f'Existing key left unchanged. Set its owner to root, group to {group_id}, and mode to 0440 explicitly.'
            )
            raise PermissionError(msg)
        existing_value = stream.read(MAX_KEY_LENGTH + 1)
    validate_key(existing_value, kind)
    if import_from and read_key(import_from, kind) != existing_value:
        msg = 'Destination contains a different key and was left unchanged. Resolve the conflict explicitly.'
        raise FileExistsError(msg)
    return False


def open_parent(path: Path) -> int:
    """Traverse pinned directories with O_NOFOLLOW, including during creation."""
    if '..' in path.parts:
        msg = 'Secret paths must not contain parent-directory traversal.'
        raise ValueError(msg)
    parent = path.absolute().parent
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parent.parts[1:]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                created = True
            except FileExistsError:
                created = False
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if created:
                os.fchown(
                    descriptor,
                    int(os.environ.get('SUDO_UID', str(os.getuid()))),
                    int(os.environ.get('SUDO_GID', str(os.getgid()))),
                )
    except BaseException:
        os.close(descriptor)
        raise
    else:
        return descriptor


def initialize_secret(
    path: Path, *, group_id: int = DEFAULT_GROUP_ID, import_from: Path | None = None, kind: str = 'django'
) -> bool:
    """Publish a validated private secret atomically without overwriting any file."""
    if os.geteuid() != 0:
        msg = 'Run with sudo so the secret can be root-owned and readable by the container group.'
        raise PermissionError(msg)
    if group_id < 0:
        msg = 'Container group ID must be nonnegative.'
        raise ValueError(msg)
    if kind not in {'django', 'kek'}:
        msg = 'Unsupported secret type.'
        raise ValueError(msg)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.absolute().parents):
        msg = 'Refusing a symlinked secret destination or directory.'
        raise ValueError(msg)
    parent_fd = open_parent(path)
    temporary = '.django-key-' + secrets.token_hex(16)
    temporary_created = False
    try:
        try:
            return keep_existing(parent_fd, path.name, group_id, import_from, kind)
        except FileNotFoundError:
            pass
        value = (
            read_key(import_from, kind)
            if import_from
            else secrets.token_hex(32)
            if kind == 'kek'
            else secrets.token_urlsafe(64)
        )
        validate_key(value, kind)
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode=0o600, dir_fd=parent_fd
        )
        temporary_created = True
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as stream:
            os.fchown(stream.fileno(), ROOT_USER_ID, group_id)
            os.fchmod(stream.fileno(), SECRET_MODE)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        except FileExistsError:
            return keep_existing(parent_fd, path.name, group_id, import_from, kind)
        os.fsync(parent_fd)
        return True
    finally:
        if temporary_created:
            os.unlink(temporary, dir_fd=parent_fd)
        os.close(parent_fd)


def main() -> None:
    """Generate or explicitly import a deployment key without printing it."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--path', type=Path, help='Destination for a single secret type (not supported with --type all).'
    )
    parser.add_argument('--type', choices=['django', 'kek', 'all'], default='django')
    parser.add_argument('--import-from', type=Path, help='Copy an existing key exactly, instead of generating one.')
    parser.add_argument('--group-id', type=int, default=DEFAULT_GROUP_ID, help='Django container group (default: 33).')
    args = parser.parse_args()
    if args.type == 'all' and (args.path or args.import_from):
        parser.error('--path and --import-from require a single secret type.')
    if args.type == 'kek' and args.import_from:
        parser.error('--import-from is supported only for Django signing keys.')
    kinds = ('django', 'kek') if args.type == 'all' else (args.type,)
    for kind in kinds:
        filename = 'django_secret_key' if kind == 'django' else 'trustpoint_software_kek'
        path = args.path or Path(__file__).resolve().parent.parent / 'secrets' / filename
        try:
            created = initialize_secret(path, group_id=args.group_id, import_from=args.import_from, kind=kind)
        except (OSError, ValueError) as exception:
            parser.exit(
                1,
                f'Cannot initialize {kind} secret: {exception}\nPreviously initialized secrets have been preserved.\n',
            )
        sys.stdout.write(f'{"Created" if created else "Kept existing"} {kind} secret file: {path}\n')


if __name__ == '__main__':
    main()
