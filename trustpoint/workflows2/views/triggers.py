"""Serve trigger metadata used by the Workflow 2 editor."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views import View

from workflows2.catalog.build import build_event_catalog


class Workflow2TriggerCatalogView(LoginRequiredMixin, View):
    """UI helper: return allowlisted triggers to populate dropdowns.

    Response:
      {
        "events": [
          {"key": "device.created", "description": "..."},
          ...
        ]
      }
    """

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Return the registered Workflow 2 trigger definitions."""
        return JsonResponse({'events': build_event_catalog()})
