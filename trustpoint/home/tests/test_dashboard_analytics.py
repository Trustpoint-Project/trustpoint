# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Basic read-only analytics API contract checks."""
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
