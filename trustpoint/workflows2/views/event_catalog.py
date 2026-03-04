from __future__ import annotations

from django.http import JsonResponse
from django.views import View

from workflows2.events.registry import get_event_registry


class EventCatalogView(View):
    def get(self, request, *args, **kwargs):
        reg = get_event_registry()
        items = []

        for spec in reg.all_specs():
            items.append(
                {
                    "key": spec.key,
                    "description": spec.description,
                    "allowed_step_types": (
                        sorted(list(spec.allowed_step_types))
                        if spec.allowed_step_types is not None
                        else None
                    ),
                    "context_vars": [
                        {
                            "path": v.path,
                            "type": v.type,
                            "description": v.description,
                            "example": v.example,
                        }
                        for v in (spec.context_vars or [])
                    ],
                }
            )

        return JsonResponse({"events": items})
