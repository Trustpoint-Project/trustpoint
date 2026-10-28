# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise the host-side initializer without requiring root on developer machines."""

import importlib.util
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[3] / 'docker/init_secret.py'
spec = importlib.util.spec_from_file_location('secret_initializer', MODULE_PATH)
initializer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(initializer)


@pytest.fixture
def initialize(monkeypatch):
    # The Linux Docker regression verifies real root:33 ownership. These tests
    # use the current owner/group to exercise actual permissions on macOS too.
    monkeypatch.setattr(initializer, 'ROOT_USER_ID', os.getuid())
    monkeypatch.setattr(initializer.os, 'geteuid', lambda: 0)
    return lambda path, **kwargs: initializer.initialize_secret(path, group_id=os.getgid(), **kwargs)


def test_key_is_unique_and_existing_key_is_unchanged(initialize, tmp_path):
    first, second = tmp_path / 'first', tmp_path / 'second'
    assert initialize(first)
    assert initialize(second)
    assert first.read_bytes() != second.read_bytes()
    assert len(first.read_text()) >= 50
    before = first.stat()
    assert not initialize(first)
    assert first.stat().st_ino == before.st_ino
    assert first.stat().st_mtime_ns == before.st_mtime_ns
    assert first.stat().st_mode & 0o777 == 0o440


def test_parallel_initialization_publishes_one_key(initialize, tmp_path):
    path = tmp_path / 'key'
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: initialize(path), range(12)))
    assert sum(results) == 1
    assert len(path.read_text()) >= 50
    assert list(tmp_path.glob('.django-key-*')) == []


@pytest.mark.parametrize('ending', ['\n', '\r\n'])
def test_explicit_import_preserves_exact_value(initialize, tmp_path, ending):
    source = tmp_path / 'previous-key'
    source.write_bytes(('existing-key-with-trailing-newline' + ending).encode())
    target = tmp_path / 'key'
    assert initialize(target, import_from=source)
    assert target.read_bytes() == source.read_bytes()
    source.write_text('another-key')
    with pytest.raises(FileExistsError, match='different key'):
        initialize(target, import_from=source)
    assert target.read_text() == 'existing-key-with-trailing-newline\n'


@pytest.mark.parametrize('contents', ['', ' \n', 'x' * 4097])
def test_invalid_existing_keys_are_never_overwritten(initialize, tmp_path, contents):
    target = tmp_path / 'key'
    target.write_text(contents)
    target.chmod(0o440)
    with pytest.raises(ValueError):
        initialize(target)
    assert target.read_text() == contents


def test_existing_permissions_are_not_modified(initialize, tmp_path):
    target = tmp_path / 'key'
    target.write_text('existing-key')
    target.chmod(0o600)
    with pytest.raises(PermissionError, match='left unchanged'):
        initialize(target)
    assert target.stat().st_mode & 0o777 == 0o600


def test_symlink_is_rejected(initialize, tmp_path):
    source = tmp_path / 'source'
    source.write_text('existing-key')
    target = tmp_path / 'key'
    target.symlink_to(source)
    with pytest.raises(ValueError, match='symlink'):
        initialize(target)
    assert source.read_text() == 'existing-key'


def test_requires_privilege_without_creating_files(monkeypatch, tmp_path):
    monkeypatch.setattr(initializer.os, 'geteuid', lambda: 1000)
    with pytest.raises(PermissionError, match='sudo'):
        initializer.initialize_secret(tmp_path / 'key')
    assert not (tmp_path / 'key').exists()


def test_cli_does_not_print_key(initialize, tmp_path, monkeypatch, capsys):
    target = tmp_path / 'key'
    initialize(target)
    monkeypatch.setattr('sys.argv', ['init_secret.py', '--path', str(target), '--group-id', str(os.getgid())])
    initializer.main()
    output = capsys.readouterr()
    assert 'Kept existing' in output.out
    assert target.read_text() not in output.out + output.err


def test_kek_generation_and_preservation(initialize, tmp_path):
    target = tmp_path / 'kek'
    assert initialize(target, kind='kek')
    value = target.read_text()
    assert len(value) == 64 and len(bytes.fromhex(value)) == 32
    assert not initialize(target, kind='kek')
    assert target.read_text() == value
    assert target.stat().st_mode & 0o777 == 0o440


@pytest.mark.parametrize('value', ['', 'ab' * 31, 'xy' * 32, 'ab' * 32 + '\n'])
def test_malformed_existing_kek_is_preserved(initialize, tmp_path, value):
    target = tmp_path / 'kek'
    target.write_text(value)
    target.chmod(0o440)
    with pytest.raises(ValueError):
        initialize(target, kind='kek')
    assert target.read_text() == value


def test_concurrent_kek_initialization(initialize, tmp_path):
    target = tmp_path / 'new-directory' / 'kek'
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: initialize(target, kind='kek'), range(12)))
    assert sum(results) == 1
    assert len(bytes.fromhex(target.read_text())) == 32


def test_incorrect_ownership_is_rejected_without_modification(initialize, tmp_path, monkeypatch):
    target = tmp_path / 'kek'
    initialize(target, kind='kek')
    before = target.read_bytes()
    monkeypatch.setattr(initializer, 'ROOT_USER_ID', os.getuid() + 1)
    with pytest.raises(PermissionError, match='left unchanged'):
        initialize(target, kind='kek')
    assert target.read_bytes() == before


def test_symlinked_parent_is_rejected(initialize, tmp_path):
    directory = tmp_path / 'actual'
    directory.mkdir()
    link = tmp_path / 'linked'
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        initialize(link / 'kek', kind='kek')
    assert not (directory / 'kek').exists()


def test_unexpected_file_type_is_rejected(initialize, tmp_path):
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match='regular file'):
        initialize(fifo, kind='kek')


def test_all_cli_preserves_partial_result(initialize, tmp_path, monkeypatch, capsys):
    # __file__ determines the default repository secrets directory.
    monkeypatch.setattr(initializer, '__file__', str(tmp_path / 'docker/init_secret.py'))
    monkeypatch.setattr('sys.argv', ['init_secret.py', '--type', 'all', '--group-id', str(os.getgid())])
    initializer.main()
    first = tmp_path / 'secrets/django_secret_key'
    second = tmp_path / 'secrets/trustpoint_software_kek'
    original = first.read_bytes()
    assert len(bytes.fromhex(second.read_text())) == 32
    second.chmod(0o600)
    second.write_text('invalid-kek')
    with pytest.raises(SystemExit) as exception:
        initializer.main()
    assert exception.value.code == 1
    assert first.read_bytes() == original
    assert second.read_text() == 'invalid-kek'
    output = capsys.readouterr()
    assert 'Previously initialized secrets have been preserved' in output.err
    assert original.decode() not in output.out + output.err
    assert 'invalid-kek' not in output.out + output.err


def test_negative_group_id_is_rejected(initialize, tmp_path):
    with pytest.raises(ValueError, match='nonnegative'):
        initializer.initialize_secret(tmp_path / 'key', group_id=-1)
    assert not (tmp_path / 'key').exists()
