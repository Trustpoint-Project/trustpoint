# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Regression tests for Dashboard grouping and display semantics."""
from __future__ import annotations

from datetime import datetime, UTC
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from home.analytics import (
    application_certificate_device_counts,
    device_domain_counts,
    issuing_ca_status_and_suites,
)


class DashboardAnalyticsSemanticsTests(SimpleTestCase):
    @patch('home.analytics.filter_credential_health')
    @patch('home.analytics.filter_devices_with_expired_or_revoked_application_certificates')
    @patch('home.analytics.filter_devices_with_active_application_certificates')
    @patch('home.analytics.DeviceModel.objects')
    def test_application_certificate_buckets_cover_all_devices_without_double_counting(self, objects, active, bad, future):
        objects.all.return_value.count.return_value = 5
        active.return_value.values_list.return_value = [1, 2]
        bad.return_value.values_list.return_value = [2, 3]
        future.return_value.values_list.return_value = [4]
        actual = application_certificate_device_counts(datetime(2026, 10, 19, tzinfo=UTC))
        self.assertEqual(actual, {'active': 2, 'expired_or_revoked_only': 1, 'not_yet_valid': 1, 'none': 1})
        self.assertEqual(sum(actual.values()), 5)
        objects.all.assert_called_once_with()

    @patch('home.analytics.DeviceModel.objects')
    def test_domain_counts_include_null_domain(self, objects):
        objects.values.return_value.annotate.return_value.order_by.return_value = [
            {'domain__unique_name': 'OT', 'domain_id': 1, 'count': 3},
            {'domain__unique_name': None, 'domain_id': None, 'count': 1},
        ]
        self.assertEqual(device_domain_counts(), [
            {'name': 'OT', 'domain_id': 1, 'count': 3}, {'name': 'No domain assigned', 'domain_id': None, 'count': 1},
        ])

    @patch('home.analytics.CaModel.objects')
    def test_ca_status_expiry_horizon(self, objects):
        now = datetime(2026, 10, 19, tzinfo=UTC)
        from datetime import timedelta
        def ca(days):
            cert = SimpleNamespace(not_valid_after=now + timedelta(days=days), not_valid_before=now - timedelta(days=30))
            return SimpleNamespace(is_active=True, credential_id=1,
                                   credential=SimpleNamespace(certificate=cert),
                                   signature_suite_display='RSA SHA-256')
        objects.exclude.return_value.select_related.return_value = [ca(15), ca(40)]
        status, suites = issuing_ca_status_and_suites(now, 30)
        self.assertEqual(status['expiring'], 1)
        self.assertEqual(status['active'], 1)
        self.assertEqual(suites['RSA SHA-256'], 2)
