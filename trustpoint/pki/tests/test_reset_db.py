# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise database reset without deleting versioned/squashed migration history."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from django.core.management import CommandError, call_command


RESET_SCRIPT = """
import io
import os
from pathlib import Path
from unittest.mock import patch

import django
django.setup()
from django.core.management import call_command
from django.db import connection
from management.models import BackupOptions
from pki.management.commands import reset_db

root = Path(os.environ['RESET_TEST_DIRECTORY'])
call_command('migrate', interactive=False, verbosity=0)
BackupOptions.objects.create(host='remove-on-reset.example')
files = {path: path.read_bytes() for path in Path('trustpoint').glob('*/migrations/*.py')}
calls = []
real_reset_sqlite = reset_db.Command._reset_sqlite

def safe_sqlite_reset(command, _base_path):
    # A regression to the old hard-coded path can touch only this disposable
    # directory, never the real checkout's database.
    sentinel_dir = root / 'other-database'
    sentinel_dir.mkdir(exist_ok=True)
    sentinel = sentinel_dir / 'db.sqlite3'
    sentinel.write_bytes(b'leave this unrelated database alone')
    real_reset_sqlite(command, sentinel_dir)
    assert sentinel.read_bytes() == b'leave this unrelated database alone'

def run_command(name, *args, **kwargs):
    calls.append(name)
    assert name != 'makemigrations', 'Normal reset must not regenerate migration history'
    return call_command(name, *args, **kwargs)

output = io.StringIO()
with (
    patch.object(reset_db.Command, '_remove_migration_files', side_effect=AssertionError('Must preserve migrations')),
    patch.object(reset_db.Command, '_reset_sqlite', safe_sqlite_reset),
    patch.object(reset_db, 'call_command', run_command),
    patch('builtins.input', return_value='y'),
):
    call_command('reset_db', no_user=True,
                 keep_all_migrations=os.environ['RESET_KEEP_ALL'] == '1', stdout=output)

assert 'Keeping existing migration files.' in output.getvalue()
assert 'all migration files' not in output.getvalue()
assert 'migrate' in calls and 'makemigrations' not in calls
assert not BackupOptions.objects.filter(host='remove-on-reset.example').exists()
assert all(path.exists() and path.read_bytes() == contents for path, contents in files.items())
assert connection.introspection.table_names()
connection.close()
print('PASS reset with preserved migrations and configured SQLite file')
"""


@pytest.mark.parametrize('keep_all', ['0', '1'])
def test_reset_preserves_migrations_and_resets_only_configured_database(tmp_path, keep_all):
    key = tmp_path / 'software-kek'
    key.write_text('ab' * 32)
    environment = dict(
        os.environ,
        PYTHONPATH=str(Path(__file__).resolve().parents[2]),
        DJANGO_SETTINGS_MODULE='trustpoint.settings',
        TRUSTPOINT_PHASE='operational',
        TRUSTPOINT_OPERATIONAL_DATABASE='sqlite',
        TRUSTPOINT_OPERATIONAL_SQLITE_PATH=str(tmp_path / 'database.sqlite3'),
        TRUSTPOINT_SOFTWARE_KEK_FILE=str(key),
        RESET_TEST_DIRECTORY=str(tmp_path),
        RESET_KEEP_ALL=keep_all,
    )
    result = subprocess.run(
        [sys.executable, '-c', RESET_SCRIPT],
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS reset with preserved migrations' in result.stdout


def test_conflicting_reset_options_fail_before_any_database_or_file_deletion():
    with pytest.raises(CommandError, match='cannot be combined'):
        call_command('reset_db', force=True, initial_migrations=True, keep_all_migrations=True)
