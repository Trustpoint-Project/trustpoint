# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify deployment-provided signing keys are required and never leaked."""

import pytest
from django.core.exceptions import ImproperlyConfigured

from trustpoint.secret_key import load_secret_key


def test_loads_key_without_trailing_newline(tmp_path):
    path = tmp_path / 'key'
    path.write_text('deployment-specific-key\n')
    assert load_secret_key(str(path)) == 'deployment-specific-key'


@pytest.mark.parametrize('value', ['', ' \n\t', 'a' * 4097])
def test_invalid_key_is_rejected_without_disclosing_value(tmp_path, value):
    path = tmp_path / 'key'
    path.write_text(value)
    with pytest.raises(ImproperlyConfigured, match='nonempty key') as failure:
        load_secret_key(str(path))
    if value:
        assert value not in str(failure.value)


def test_missing_file_fails_closed(tmp_path):
    with pytest.raises(ImproperlyConfigured, match='cannot be read'):
        load_secret_key(str(tmp_path / 'missing'))


def test_settings_honors_external_key_file(monkeypatch, tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    path = tmp_path / 'deployment-key'
    path.write_text('configured-deployment-key\n')
    monkeypatch.setenv('DJANGO_SECRET_KEY_FILE', str(path))
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, '-c',
         "import os; from pathlib import Path; from trustpoint import settings; "
         "assert settings.SECRET_KEY == Path(os.environ['DJANGO_SECRET_KEY_FILE']).read_text()"],
        env={**os.environ, 'PYTHONPATH': str(root)},
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_persisted_default_key_preserves_exact_value(tmp_path):
    path = tmp_path / 'key'
    path.write_text('existing-deployment-key\n')
    assert load_secret_key(str(path), strip_whitespace=False) == 'existing-deployment-key\n'
