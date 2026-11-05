# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Basic read-only analytics API contract checks."""

import pytest

from django.test import RequestFactory, TestCase
from django.contrib.auth import get_user_model
from home.analytics import DashboardAnalyticsAPIView


class AnalyticsValidationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(username='dashboard_analytics', password='test-only-password')

    def test_rejects_unknown_tab(self):
        request = RequestFactory().get('/dashboard/analytics/?tab=unknown')
        request.user = self.user
        response = DashboardAnalyticsAPIView.as_view()(request)
        self.assertEqual(response.status_code, 400)

    def test_rejects_invalid_period(self):
        request = RequestFactory().get('/dashboard/analytics/?tab=certificates&activity_days=abc')
        request.user = self.user
        response = DashboardAnalyticsAPIView.as_view()(request)
        self.assertEqual(response.status_code, 400)


@pytest.mark.django_db
def test_certificate_profile_counts_follow_the_reference_after_rename(tls_client_credential_instance):
    from home.views import DashboardChartsAndCountsView
    from pki.tests.credential_helpers import issue_test_credential

    issued = tls_client_credential_instance['issued_credential']
    profile = issued.certificate_profile
    profile.display_name = 'Renamed dashboard profile'
    profile.save(update_fields=['display_name'])
    issue_test_credential(issued.device, profile.unique_name, common_name='second-certificate')
    counts = DashboardChartsAndCountsView().get_cert_counts_by_profile(None)
    assert counts['Renamed dashboard profile'] == 2
