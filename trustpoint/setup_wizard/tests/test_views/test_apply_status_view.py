# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for setup-apply status transport."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Final
from unittest.mock import patch

from django.http import HttpRequest
from django.test import RequestFactory

from setup_wizard.views import FreshInstallApplyStatusView

DEMO_PROGRESS: Final[int] = 65


def _request() -> HttpRequest:
    """Build an authenticated request for the status view."""
    request = RequestFactory().get('/setup-wizard/fresh-install/apply/status/')
    request.user = SimpleNamespace(is_authenticated=True)
    return request


def _status() -> dict[str, object]:
    """Return representative persisted setup state."""
    return {
        'job_id': 'job-1',
        'state': 'running',
        'stage': 'demo-data',
        'detail': 'Generating demo data.',
        'progress': DEMO_PROGRESS,
        'history': [],
        'activity': [{'stage': 'demo-data', 'detail': 'Created a device.', 'created_at': 'now'}],
    }


def test_status_response_includes_bounded_activity() -> None:
    """One polling response carries both lifecycle state and demo activity."""
    with patch('setup_wizard.views.read_setup_apply_status', return_value=_status()):
        response = FreshInstallApplyStatusView.as_view()(_request())

    payload = json.loads(response.content)
    assert payload['state'] == 'running'
    assert payload['progress'] == DEMO_PROGRESS
    assert payload['activity'] == [{'stage': 'demo-data', 'detail': 'Created a device.', 'created_at': 'now'}]
    assert response['Cache-Control'] == 'no-store'


def test_progress_page_recovers_from_nginx_tls_reload() -> None:
    """A broken polling connection forces a fresh page connection automatically."""
    template_path = Path(__file__).resolve().parents[3] / 'templates/setup_wizard/apply_progress.html'

    template = template_path.read_text(encoding='utf-8')

    assert 'reloadAfterConnectionChange();' in template
    assert 'window.location.reload();' in template
