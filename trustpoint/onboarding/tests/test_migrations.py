# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise credential migration against an isolated database, including rollback."""

import os
import subprocess
import sys
from pathlib import Path


def test_reusable_credential_migration(tmp_path):
    runner = Path(__file__).with_name('credential_migration_runner.py')
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
    assert 'PASS credential migration' in result.stdout
