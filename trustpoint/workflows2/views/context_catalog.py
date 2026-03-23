# workflows2/views/context_catalog.py
from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.views import View

from workflows2.catalog.build import build_context_catalog


class ContextCatalogView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        return JsonResponse(build_context_catalog())
