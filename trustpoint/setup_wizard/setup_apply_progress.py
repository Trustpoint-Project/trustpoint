# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Persistent progress reporting for the setup-wizard operational handoff."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from django.conf import settings
from django.utils import timezone

APPLY_JOB_ID_ENV: Final[str] = 'TRUSTPOINT_SETUP_APPLY_JOB_ID'
APPLY_STATUS_FILE_ENV: Final[str] = 'TRUSTPOINT_SETUP_APPLY_STATUS_FILE'
ACTIVE_STATES: Final[frozenset[str]] = frozenset({'queued', 'running', 'switching'})
MAX_HISTORY_ENTRIES: Final[int] = 24
MAX_ACTIVITY_ENTRIES: Final[int] = 100
QUEUED_GRACE_SECONDS: Final[int] = 30


def setup_apply_status_path() -> Path:
    """Return the status file shared by bootstrap and operational processes."""
    configured = os.getenv(APPLY_STATUS_FILE_ENV)
    if configured:
        return Path(configured)
    if getattr(settings, 'DOCKER_CONTAINER', False):
        return Path('/var/lib/trustpoint/bootstrap/setup-apply-status.json')
    return settings.REPO_ROOT / 'var' / 'bootstrap' / 'setup-apply-status.json'


def _timestamp() -> str:
    """Return an ISO timestamp suitable for JSON status responses."""
    return timezone.now().isoformat()


def read_setup_apply_status(path: Path | None = None) -> dict[str, Any] | None:
    """Read the current apply status, returning no status for malformed or missing files."""
    status_path = path or setup_apply_status_path()
    try:
        payload = json.loads(status_path.read_text(encoding='utf-8'))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def write_setup_apply_status(  # noqa: PLR0913 - explicit status fields keep persisted state auditable.
    *,
    job_id: str,
    state: str,
    stage: str,
    detail: str,
    progress: int,
    pid: int | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    """Atomically update setup progress while retaining a bounded stage history."""
    status_path = path or setup_apply_status_path()
    status_path.parent.mkdir(parents=True, exist_ok=True)
    previous = read_setup_apply_status(status_path)
    now = _timestamp()
    history: list[dict[str, str]] = []
    activity: list[dict[str, str]] = []
    started_at = now
    if previous and previous.get('job_id') == job_id:
        previous_history = previous.get('history')
        if isinstance(previous_history, list):
            history = [entry for entry in previous_history if isinstance(entry, dict)][-MAX_HISTORY_ENTRIES:]
        previous_activity = previous.get('activity')
        if isinstance(previous_activity, list):
            activity = [entry for entry in previous_activity if isinstance(entry, dict)][-MAX_ACTIVITY_ENTRIES:]
        started_at = str(previous.get('started_at') or now)
        if previous.get('stage') != stage:
            history.append(
                {
                    'stage': str(previous.get('stage') or ''),
                    'detail': str(previous.get('detail') or ''),
                    'completed_at': now,
                }
            )
        elif previous.get('detail') != detail:
            activity.append(
                {
                    'stage': stage,
                    'detail': detail,
                    'created_at': now,
                }
            )

    payload: dict[str, Any] = {
        'job_id': job_id,
        'state': state,
        'stage': stage,
        'detail': detail,
        'progress': max(0, min(100, progress)),
        'started_at': started_at,
        'updated_at': now,
        'history': history[-MAX_HISTORY_ENTRIES:],
        'activity': activity[-MAX_ACTIVITY_ENTRIES:],
    }
    if pid is not None:
        payload['pid'] = pid
    elif previous and previous.get('job_id') == job_id and isinstance(previous.get('pid'), int):
        payload['pid'] = previous['pid']

    temporary_path = status_path.with_name(f'.{status_path.name}.{job_id}.tmp')
    temporary_path.write_text(json.dumps(payload, sort_keys=True), encoding='utf-8')
    temporary_path.chmod(0o600)
    temporary_path.replace(status_path)
    return payload


def report_setup_apply_progress(stage: str, detail: str, progress: int, *, state: str = 'running') -> None:
    """Report progress when invoked as part of a background setup apply job."""
    job_id = os.getenv(APPLY_JOB_ID_ENV)
    if not job_id:
        return
    write_setup_apply_status(
        job_id=job_id,
        state=state,
        stage=stage,
        detail=detail,
        progress=progress,
        pid=os.getpid(),
    )


def report_setup_apply_activity(detail: str) -> None:
    """Publish detailed activity while preserving the current setup stage and percentage."""
    job_id = os.getenv(APPLY_JOB_ID_ENV)
    if not job_id or not detail.strip():
        return
    current = read_setup_apply_status()
    if not current or current.get('job_id') != job_id or current.get('state') not in ACTIVE_STATES:
        return
    write_setup_apply_status(
        job_id=job_id,
        state=str(current['state']),
        stage=str(current.get('stage') or 'running'),
        detail=detail.strip(),
        progress=int(current.get('progress') or 0),
        pid=os.getpid(),
    )


def _status_is_active(status: dict[str, Any] | None) -> bool:
    """Return whether a status represents a live or freshly queued apply process."""
    if not status or status.get('state') not in ACTIVE_STATES:
        return False
    pid = status.get('pid')
    if isinstance(pid, int):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    try:
        updated_at = datetime.fromisoformat(str(status['updated_at']))
    except (KeyError, TypeError, ValueError):
        return False
    return (timezone.now() - updated_at).total_seconds() < QUEUED_GRACE_SECONDS


def start_setup_apply_job() -> tuple[dict[str, Any], bool]:
    """Start one detached setup apply command, or return the already active job."""
    status_path = setup_apply_status_path()
    status_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = status_path.with_suffix('.lock')
    with lock_path.open('a+', encoding='utf-8') as lock_file:
        lock_path.chmod(0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        current = read_setup_apply_status(status_path)
        if _status_is_active(current):
            return current or {}, False

        job_id = uuid.uuid4().hex
        status = write_setup_apply_status(
            job_id=job_id,
            state='queued',
            stage='queued',
            detail='Setup has been queued.',
            progress=0,
            path=status_path,
        )
        env = os.environ.copy()
        env[APPLY_JOB_ID_ENV] = job_id
        env[APPLY_STATUS_FILE_ENV] = str(status_path)
        log_path = status_path.with_name('setup-apply.log')
        with log_path.open('ab') as log_file:
            log_path.chmod(0o600)
            subprocess.Popen(  # noqa: S603
                [sys.executable, str(settings.BASE_DIR / 'manage.py'), 'apply_setup_wizard'],
                cwd=str(settings.REPO_ROOT),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
            )
        return status, True
