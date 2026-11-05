# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Archive downloads using Core while preserving repeated member names."""

import io
import tarfile
import zipfile

from trustpoint_core.archiver import ArchiveFormat, Archiver


def archive_named_files(files: list[tuple[str, bytes]], archive_format: ArchiveFormat) -> bytes:
    """Use Core for unique names and retain all members when names collide."""
    unique_files = dict(files)
    if len(unique_files) == len(files):
        return Archiver.archive(unique_files, archive_format)

    # A dictionary cannot represent repeated names, which existing downloads allow.
    buffer = io.BytesIO()
    if archive_format == ArchiveFormat.ZIP:
        with zipfile.ZipFile(buffer, 'w') as archive:
            for name, data in files:
                archive.writestr(name, data)
    elif archive_format == ArchiveFormat.TAR_GZ:
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive_tar:
            for name, data in files:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive_tar.addfile(member, io.BytesIO(data))
    else:
        msg = f'Unsupported archive format: {archive_format}.'
        raise ValueError(msg)
    return buffer.getvalue()
