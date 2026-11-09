# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Copy a staged regular file through no-follow descriptors into a root-owned snapshot."""

# ruff: noqa: INP001

import os
import stat
import sys
from pathlib import Path

MAX_ASSET_BYTES = 32 * 1024 * 1024


def snapshot(staging_root: Path, source: Path, destination: Path | None) -> None:
    """Never reopen an application-writable pathname with root privileges."""
    relative = source.relative_to(staging_root)
    if not staging_root.is_absolute() or '..' in source.parts or not relative.parts:
        msg = 'Expected an absolute staged file path.'
        raise ValueError(msg)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in (*staging_root.parts[1:], *relative.parts[:-1]):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        if destination is None:
            os.unlink(relative.name, dir_fd=directory)
            return
        source_fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(source_fd, 'rb') as staged:
            before = os.fstat(staged.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_ASSET_BYTES:
                msg = 'Expected a singly linked staged regular file of at most 32 MiB.'
                raise ValueError(msg)
            destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(destination_fd, 'wb') as output:
                remaining = before.st_size
                while remaining:
                    chunk = staged.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        msg = 'Staged file changed during snapshot.'
                        raise ValueError(msg)
                    output.write(chunk)
                    remaining -= len(chunk)
            after = os.fstat(staged.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                msg = 'Staged file changed during snapshot.'
                raise ValueError(msg)
    finally:
        os.close(directory)


if __name__ == '__main__':
    if sys.argv[1] == '--remove':
        snapshot(Path(sys.argv[2]), Path(sys.argv[3]), None)
    else:
        snapshot(*(Path(argument) for argument in sys.argv[1:]))
