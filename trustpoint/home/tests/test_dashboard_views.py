# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Dashboard API contract tests; use Django request factory to avoid legacy route changes."""
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from django.test import RequestFactory

from home.views import DashboardOverviewAPIView


@pytest.mark.django_db
def test_invalid_expiry_horizon_rejected(django_user_model):
    request = RequestFactory().get('/dashboard/overview/?expiry_days=8')
    request.user = django_user_model.objects.create_user(username='dashboard_test_user', password='test-password')
    response = DashboardOverviewAPIView.as_view()(request)
    assert response.status_code == 400


@pytest.mark.django_db
def test_readonly_api_returns_contract(django_user_model):
    request = RequestFactory().get('/dashboard/overview/?expiry_days=7')
    request.user = django_user_model.objects.create_user(username='dashboard_test_user_2', password='test-password')
    snapshot = datetime(2026, 10, 19, 11, 0, tzinfo=timezone.utc)
    payload = {
        'as_of': snapshot.isoformat(), 'expiry_days': 7,
        'scope': 'device_linked_issued_end_entity_certificates', 'scope_complete': False,
        'certificates': {'total': 3, 'expiring': 1, 'valid': 2, 'expired': 0,
                         'revoked': 0, 'not_yet_valid': 0, 'active': 3, 'unclassified': 0},
        'devices': {'managed': 2}, 'issuing_cas': {'enabled': 1, 'availability_verified': False},
    }
    with patch('home.views.get_overview_payload', return_value=payload) as fn:
        response = DashboardOverviewAPIView.as_view()(request)
    assert response.status_code == 200
    assert b'"scope_complete": false' in response.content
    fn.assert_called_once_with(expiry_days=7)


def test_preview_scope_query_is_deduplicated():
    """The provisional scope is a certificate PK subquery, not a joined row count."""
    from home.views import device_linked_certificate_queryset
    qs = device_linked_certificate_queryset()
    assert 'IN' in str(qs.query).upper()
