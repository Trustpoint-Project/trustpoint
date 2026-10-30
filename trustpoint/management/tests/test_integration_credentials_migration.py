# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify fresh installation of the first stable management schema."""

import os
import subprocess
import sys
from pathlib import Path


def test_integration_credential_initial_schema(tmp_path):
    runner = Path(__file__).with_name('integration_credentials_migration_runner.py')
    environment = os.environ.copy()
    environment.pop('TP_MIGRATION_TEST_DATABASE', None)
    result = subprocess.run(
        [sys.executable, str(runner), str(tmp_path)],
        capture_output=True,
        text=True,
        env=environment,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS initial schema' in result.stdout
