# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for launching the development task worker."""

import os
import subprocess
from unittest.mock import patch

import pytest
from django.conf import settings

from pki.management.commands.runserver_with_qcluster import Command, RunServerCommand


@pytest.mark.parametrize('from_repo_root', [True, False])
def test_qcluster_can_load_settings_from_either_working_directory(*, from_repo_root: bool) -> None:
    """The worker must find the project even when launched outside manage.py's directory."""
    with (
        patch('pki.management.commands.runserver_with_qcluster.subprocess.Popen') as popen,
        patch.object(RunServerCommand, 'handle'),
        patch.dict(os.environ),
    ):
        os.environ.pop('RUN_MAIN', None)
        popen.return_value.poll.return_value = None
        Command().handle()

    popen.return_value.terminate.assert_called_once()
    popen.return_value.wait.assert_called_once()
    environment = os.environ.copy()
    environment.pop('PYTHONPATH', None)
    result = subprocess.run(  # noqa: S603 - execute the captured project command with --help
        [*popen.call_args.args[0], '--help'],
        cwd=settings.BASE_DIR.parent if from_repo_root else settings.BASE_DIR,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'qcluster' in result.stdout
