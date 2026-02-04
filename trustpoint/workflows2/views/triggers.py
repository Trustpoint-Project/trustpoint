from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.views import View

from workflows2.events.registry import get_event_registry


class Workflow2TriggerCatalogView(LoginRequiredMixin, View):
    """
    UI helper: return allowlisted triggers to populate dropdowns.

    Response:
      {
        "events": [
          {"key": "device.created", "description": "..."},
          ...
        ]
      }
    """

    def get(self, _request, *_args, **_kwargs):
        reg = get_event_registry()
        events = [{"key": k, "description": reg.describe(k) or ""} for k in reg.all_keys()]
        return JsonResponse({"events": events})
