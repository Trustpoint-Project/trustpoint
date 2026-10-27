# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Ensure wizard staging cleanup cannot touch files outside its private directory."""

from pathlib import Path
from unittest.mock import patch

import pytest

from setup_wizard import pkcs11_staging as staging


@pytest.fixture
def staging_root(monkeypatch, tmp_path):
    root = tmp_path / 'wizard' / 'pkcs11'
    root.mkdir(parents=True)
    monkeypatch.setattr(staging, 'WIZARD_PKCS11_STAGING_ROOT', root)
    assert staging.wizard_pkcs11_staging_root() == root
    return root


@pytest.mark.parametrize('value', [None, '', '../outside', 42])
def test_invalid_staged_paths_are_ignored(staging_root, value):
    assert staging.resolve_wizard_pkcs11_staged_path(value) is None
    assert staging.existing_wizard_pkcs11_staged_file(value) is None
    staging.cleanup_wizard_pkcs11_staged_path(value)
    assert staging_root.is_dir()


def test_only_existing_regular_staged_files_are_accepted(staging_root):
    file = staging_root / 'module.so'
    assert staging.existing_wizard_pkcs11_staged_file(file) is None
    file.touch()
    assert staging.existing_wizard_pkcs11_staged_file(str(file)) == file
    assert staging.existing_wizard_pkcs11_staged_file(staging_root) is None


@pytest.mark.parametrize('escape', ['absolute', 'parent', 'sibling', 'symlink'])
def test_cleanup_preserves_files_outside_staging_root(staging_root, tmp_path, escape):
    outside = tmp_path / 'pkcs11-other' / 'pin'
    outside.parent.mkdir()
    outside.write_text('private pin')
    candidate = outside
    if escape == 'parent':
        candidate = staging_root / '..' / '..' / 'pkcs11-other' / 'pin'
    elif escape == 'sibling':
        candidate = staging_root.with_name('pkcs11-other') / 'pin'
        candidate.parent.mkdir()
        candidate.write_text('private pin')
    elif escape == 'symlink':
        candidate = staging_root / 'linked-pin'
        candidate.symlink_to(outside)
    assert staging.resolve_wizard_pkcs11_staged_path(candidate) is None
    staging.cleanup_wizard_pkcs11_staged_path(candidate)
    assert outside.read_text() == 'private pin'
    assert candidate.exists()


def test_cleanup_removes_staged_file_and_empty_directories_only(staging_root):
    session = staging_root / 'session' / 'nested'
    session.mkdir(parents=True)
    file = session / 'pin'
    file.touch()
    staging.cleanup_wizard_pkcs11_staged_path(file)
    assert not file.exists()
    assert not staging_root.exists()
    assert staging_root.parent.is_dir()
    staging.cleanup_wizard_pkcs11_staged_path(file)


def test_cleanup_preserves_other_sessions(staging_root):
    file = staging_root / 'module.so'
    file.touch()
    other = staging_root / 'another-session'
    other.mkdir()
    other_file = other / 'pin'
    other_file.write_text('other pin')
    staging.cleanup_wizard_pkcs11_staged_path(file)
    assert not file.exists()
    assert other_file.read_text() == 'other pin'


def test_cleanup_stops_when_unlink_fails(staging_root):
    file = staging_root / 'pin'
    file.touch()
    with patch.object(Path, 'unlink', side_effect=PermissionError('denied')):
        staging.cleanup_wizard_pkcs11_staged_path(file)
    assert file.is_file()
