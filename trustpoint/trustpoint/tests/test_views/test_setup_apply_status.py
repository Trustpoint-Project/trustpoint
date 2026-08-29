# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for operational completion of setup progress."""

import json

from django.test import RequestFactory

from trustpoint.views.setup_apply_status import CompletedSetupApplyStatusView

COMPLETED_PROGRESS = 100


def test_completed_setup_apply_status_is_terminal() -> None:
    """Operational status causes the bootstrap progress page to finish."""
    request = RequestFactory().get('/setup-wizard/fresh-install/apply/status/')

    response = CompletedSetupApplyStatusView.as_view()(request)

    payload = json.loads(response.content)
    assert payload['state'] == 'complete'
    assert payload['progress'] == COMPLETED_PROGRESS
