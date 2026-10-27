# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Archive downloads preserve every member, including colliding backup names."""

import io
import tarfile
import zipfile

import pytest
from trustpoint_core.archiver import ArchiveFormat

from util.archives import archive_named_files


@pytest.mark.parametrize('archive_format', list(ArchiveFormat))
@pytest.mark.parametrize('names', [('one', 'two'), ('backup.zip', 'backup.zip')])
def test_archive_preserves_member_order_names_and_contents(archive_format, names):
    """Using Core must not drop an entry when two backups have the same artifact name."""
    entries = [(names[0], b'first payload'), (names[1], b'second payload')]
    if archive_format == ArchiveFormat.ZIP and names[0] == names[1]:
        with pytest.warns(UserWarning, match='Duplicate name'):
            data = archive_named_files(entries, archive_format)
    else:
        data = archive_named_files(entries, archive_format)

    if archive_format == ArchiveFormat.ZIP:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert [(member.filename, archive.read(member)) for member in archive.infolist()] == entries
            assert all(member.compress_type == zipfile.ZIP_STORED for member in archive.infolist())
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            assert [(member.name, archive.extractfile(member).read()) for member in archive.getmembers()] == entries
