# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for detached setup apply progress persistence and launch control."""

from pathlib import Path
from unittest.mock import patch

import pytest

from setup_wizard.setup_apply_progress import (
    APPLY_STATUS_FILE_ENV,
    read_setup_apply_status,
    report_setup_apply_activity,
    start_setup_apply_job,
    write_setup_apply_status,
)


def test_write_setup_apply_status_is_atomic_and_keeps_history(tmp_path: Path) -> None:
    """Each stage replaces one JSON file and retains completed stage descriptions."""
    status_path = tmp_path / 'status.json'
    write_setup_apply_status(
        job_id='job-1',
        state='running',
        stage='database',
        detail='Preparing database.',
        progress=10,
        path=status_path,
    )
    write_setup_apply_status(
        job_id='job-1',
        state='running',
        stage='demo-data',
        detail='Generating demo data.',
        progress=65,
        path=status_path,
    )

    status = read_setup_apply_status(status_path)

    assert status is not None
    assert status['stage'] == 'demo-data'
    assert status['progress'] == 65
    assert status['history'][0]['detail'] == 'Preparing database.'
    assert list(tmp_path.glob('*.tmp')) == []


def test_report_setup_apply_activity_preserves_stage_and_progress(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Detailed command activity updates the feed without changing its high-level stage."""
    status_path = tmp_path / 'status.json'
    monkeypatch.setenv(APPLY_STATUS_FILE_ENV, str(status_path))
    monkeypatch.setenv('TRUSTPOINT_SETUP_APPLY_JOB_ID', 'job-1')
    write_setup_apply_status(
        job_id='job-1',
        state='running',
        stage='demo-data',
        detail='Generating demo data and keys.',
        progress=65,
        path=status_path,
    )

    report_setup_apply_activity("Generating RSA-2048 key for 'issuing-ca-a-1'...")

    status = read_setup_apply_status(status_path)
    assert status is not None
    assert status['stage'] == 'demo-data'
    assert status['progress'] == 65
    assert status['detail'] == "Generating RSA-2048 key for 'issuing-ca-a-1'..."
    assert status['history'] == []
    assert status['activity'][-1]['detail'] == "Generating RSA-2048 key for 'issuing-ca-a-1'..."


def test_start_setup_apply_job_does_not_launch_duplicate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A freshly queued setup blocks duplicate summary submissions."""
    status_path = tmp_path / 'status.json'
    monkeypatch.setenv(APPLY_STATUS_FILE_ENV, str(status_path))
    write_setup_apply_status(
        job_id='job-1',
        state='queued',
        stage='queued',
        detail='Queued.',
        progress=0,
        path=status_path,
    )

    with patch('setup_wizard.setup_apply_progress.subprocess.Popen') as popen:
        status, started = start_setup_apply_job()

    assert status['job_id'] == 'job-1'
    assert not started
    popen.assert_not_called()


def test_start_setup_apply_job_launches_detached_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A terminal prior status permits one detached management process."""
    status_path = tmp_path / 'status.json'
    monkeypatch.setenv(APPLY_STATUS_FILE_ENV, str(status_path))
    write_setup_apply_status(
        job_id='old-job',
        state='failed',
        stage='failed',
        detail='Failed.',
        progress=100,
        path=status_path,
    )

    with patch('setup_wizard.setup_apply_progress.subprocess.Popen') as popen:
        status, started = start_setup_apply_job()

    assert started
    assert status['job_id'] != 'old-job'
    assert status['state'] == 'queued'
    assert popen.call_args.kwargs['start_new_session'] is True
