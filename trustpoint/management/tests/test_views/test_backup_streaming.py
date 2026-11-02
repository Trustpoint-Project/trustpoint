# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Backup archives stay on disk and close with their response or on failure."""

import os
import tarfile
import tracemalloc
import zipfile
from tempfile import TemporaryFile

import pytest
from django.http import FileResponse
from django.test import RequestFactory

from management.views.backup import BackupFileDownloadView, BackupFilesDownloadMultipleView


@pytest.fixture
def backup_files(settings, tmp_path, monkeypatch):
    settings.BACKUP_FILE_PATH = tmp_path
    filenames = ['backup_1.dump.gz', 'backup_2.dump.gz']
    for filename in filenames:
        (tmp_path / filename).write_bytes(b'backup payload')
        (tmp_path / f'{filename}.manifest.json').write_bytes(b'manifest')

    files = []

    def temporary_file():
        if len(files) > 1:
            assert files[-1].closed, 'Close the previous inner archive before building another'
        stream = TemporaryFile()
        files.append(stream)
        return stream

    monkeypatch.setattr('management.views.backup.TemporaryFile', temporary_file)
    yield filenames, files
    for stream in files:
        stream.close()


@pytest.mark.parametrize('archive_format', ['zip', 'tar.gz'])
def test_bulk_response_owns_only_outer_file(backup_files, archive_format):
    filenames, files = backup_files
    request = RequestFactory().post('/', {'selected': filenames})

    response = BackupFilesDownloadMultipleView().post(request, archive_format)

    assert isinstance(response, FileResponse)
    assert response.file_to_stream is files[0]
    assert files[0].fileno() >= 0
    assert not files[0].closed
    assert len(files) == 3
    assert all(stream.closed for stream in files[1:])
    response.close()
    assert all(stream.closed for stream in files)


def test_single_bundle_closes_without_consuming_response(backup_files):
    filenames, files = backup_files
    response = BackupFileDownloadView().get(None, filenames[0])

    assert isinstance(response, FileResponse)
    assert response.file_to_stream is files[0]
    assert files[0].fileno() >= 0
    assert not files[0].closed
    response.close()
    assert files[0].closed


@pytest.mark.parametrize('mode', ['single', 'zip', 'tar.gz'])
def test_archive_errors_close_all_temporary_files(backup_files, monkeypatch, mode):
    filenames, files = backup_files

    def fail(*args, **kwargs):
        raise OSError('Disk full')

    if mode == 'tar.gz':
        monkeypatch.setattr(tarfile.TarFile, 'add', fail)
    else:
        monkeypatch.setattr(zipfile.ZipFile, 'write', fail)

    with pytest.raises(OSError, match='Disk full'):
        if mode == 'single':
            BackupFileDownloadView().get(None, filenames[0])
        else:
            request = RequestFactory().post('/', {'selected': filenames})
            BackupFilesDownloadMultipleView().post(request, mode)

    assert files
    assert all(stream.closed for stream in files)


@pytest.mark.parametrize('archive_format', ['zip', 'tar.gz'])
def test_bulk_archive_memory_stays_below_payload_size(backup_files, settings, archive_format):
    filenames, _files = backup_files
    chunk = os.urandom(64 * 1024)
    for filename in filenames:
        with (settings.BACKUP_FILE_PATH / filename).open('wb') as payload:
            for _ in range(64):
                payload.write(chunk)
    request = RequestFactory().post('/', {'selected': filenames})

    tracemalloc.start()
    try:
        response = BackupFilesDownloadMultipleView().post(request, archive_format)
        try:
            size = sum(len(block) for block in response.streaming_content)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            response.close()
    finally:
        tracemalloc.stop()

    assert size > 8 * 1024 * 1024
    assert peak < 4 * 1024 * 1024
