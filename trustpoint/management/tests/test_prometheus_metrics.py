# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Prometheus metrics endpoint requires an explicit scrape token."""

from __future__ import annotations

import pytest
from django.test import RequestFactory, override_settings

from management.models.prometheus import PrometheusConfig
from trustpoint.views.prometheus import prometheus_metrics_view

TOKEN = 'test-metrics-token'


@pytest.fixture
def enabled_metrics() -> None:
    config = PrometheusConfig.get()
    config.enabled = True
    config.save(update_fields=['enabled'])


@pytest.mark.django_db
def test_enabled_endpoint_fails_closed_without_token(enabled_metrics: None) -> None:
    response = prometheus_metrics_view(RequestFactory().get('/prometheus/metrics'))

    assert response.status_code == 503


@pytest.mark.django_db
@override_settings(TRUSTPOINT_PROMETHEUS_METRICS_TOKEN=TOKEN)
def test_endpoint_requires_the_configured_bearer_token(enabled_metrics: None) -> None:
    factory = RequestFactory()
    assert prometheus_metrics_view(factory.get('/prometheus/metrics')).status_code == 401
    assert (
        prometheus_metrics_view(
            factory.get('/prometheus/metrics', HTTP_AUTHORIZATION='Bearer wrong-token')
        ).status_code
        == 401
    )

    response = prometheus_metrics_view(
        factory.get('/prometheus/metrics', HTTP_AUTHORIZATION=f'Bearer {TOKEN}')
    )
    assert response.status_code == 200
