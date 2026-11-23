# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Prometheus metrics endpoint view."""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from django.conf import settings
from django.http import Http404, HttpResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from management.models.prometheus import PrometheusConfig

if TYPE_CHECKING:
    from django.http import HttpRequest

MISSING_CONFIGURATION_MESSAGE = 'Prometheus metrics token is not configured.'
DENIED_MESSAGE = 'Unauthorized.'


def prometheus_metrics_view(request: HttpRequest) -> HttpResponse:
    """Serve Prometheus metrics to a bearer-authenticated scrape when enabled."""
    config = PrometheusConfig.get()
    if not config.enabled:
        raise Http404
    token = settings.TRUSTPOINT_PROMETHEUS_METRICS_TOKEN
    if not token:
        return HttpResponse(MISSING_CONFIGURATION_MESSAGE, status=503, content_type='text/plain')
    supplied = request.headers.get('Authorization', '')
    if not hmac.compare_digest(supplied, f'Bearer {token}'):
        response = HttpResponse(DENIED_MESSAGE, status=401, content_type='text/plain')
        response['WWW-Authenticate'] = 'Bearer'
        return response
    return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)
