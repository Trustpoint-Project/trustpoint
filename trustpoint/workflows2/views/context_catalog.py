# workflows2/views/context_catalog.py
"""Serve the editor context catalog used by the Workflow 2 frontend."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views import View

from workflows2.catalog.build import build_context_catalog


class ContextCatalogView(LoginRequiredMixin, View):
    """Return the frontend catalog as JSON."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Return the Workflow 2 context catalog."""
        return JsonResponse(build_context_catalog())
