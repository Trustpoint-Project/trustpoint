"""Serve trigger metadata used by the Workflow 2 editor."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views import View

from workflows2.events.registry import get_event_registry


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
        reg = get_event_registry()
        events = [{'key': key, 'description': reg.describe(key) or ''} for key in reg.all_keys()]
        return JsonResponse({'events': events})
