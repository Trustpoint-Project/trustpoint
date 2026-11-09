# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""The privileged installer snapshots staging files without following mutable paths."""

import importlib.util
import os
from pathlib import Path

import pytest


@pytest.fixture
def helper():
    path = Path(__file__).resolve().parents[3] / 'docker/trustpoint/wizard/internal/snapshot_pkcs11_file.py'
    spec = importlib.util.spec_from_file_location('pkcs11_snapshot', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_regular_snapshot_keeps_source_until_install_succeeds(helper, tmp_path):
    root = tmp_path.resolve() / 'staging'
    root.mkdir()
    source = root / 'pin'
    source.write_bytes(b'dummy-pin')
    destination = tmp_path / 'snapshot'
    helper.snapshot(root, source, destination)
    assert destination.read_bytes() == b'dummy-pin'
    assert source.read_bytes() == b'dummy-pin'
    assert destination.stat().st_mode & 0o777 == 0o600
    helper.snapshot(root, source, None)
    assert not source.exists()


@pytest.mark.parametrize('kind', ['symlink', 'directory_symlink', 'hardlink', 'fifo', 'outside'])
def test_snapshot_refuses_unapproved_files(helper, tmp_path, kind):
    root = tmp_path.resolve() / 'staging'
    root.mkdir()
    outside = tmp_path.resolve() / 'outside'
    outside.mkdir()
    dummy = outside / 'dummy'
    dummy.write_bytes(b'private dummy data')
    source = root / 'source'
    if kind == 'symlink':
        source.symlink_to(dummy)
    elif kind == 'directory_symlink':
        source.symlink_to(outside, target_is_directory=True)
        source /= 'dummy'
    elif kind == 'hardlink':
        os.link(dummy, source)
    elif kind == 'fifo':
        os.mkfifo(source)
    else:
        source = dummy
    destination = tmp_path / 'snapshot'
    with pytest.raises((OSError, ValueError)):
        helper.snapshot(root, source, destination)
    assert not destination.exists()
    assert dummy.read_bytes() == b'private dummy data'


def test_replacing_checked_leaf_with_symlink_never_reads_outside_staging(helper, tmp_path, monkeypatch):
    root = tmp_path.resolve() / 'staging'
    root.mkdir()
    source = root / 'source'
    source.write_bytes(b'approved')
    dummy = tmp_path / 'dummy'
    dummy.write_bytes(b'private dummy data')
    real_open = os.open

    def replace_before_open(path, flags, *args, **kwargs):
        if path == 'source':
            source.unlink()
            source.symlink_to(dummy)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(helper.os, 'open', replace_before_open)
    destination = tmp_path / 'snapshot'
    with pytest.raises(OSError):
        helper.snapshot(root, source, destination)
    assert not destination.exists()
    assert dummy.read_bytes() == b'private dummy data'
