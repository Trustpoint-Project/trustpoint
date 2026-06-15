"""Prometheus metrics endpoint view."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.http import Http404, HttpResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from management.models.prometheus import PrometheusConfig

if TYPE_CHECKING:
    from django.http import HttpRequest


def prometheus_metrics_view(_request: HttpRequest) -> HttpResponse:
    """Serve Prometheus metrics if the endpoint is enabled in configuration."""
    config = PrometheusConfig.get()
    if not config.enabled:
        raise Http404
    return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)
