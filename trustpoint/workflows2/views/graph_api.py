"""Return graph data for saved Workflow 2 definitions."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View

from workflows2.models import Workflow2Definition
from workflows2.services.graph import WorkflowGraphService


class Workflow2DefinitionGraphView(LoginRequiredMixin, View):
    """Serve graph JSON for a stored workflow definition."""

    def get(self, _request: HttpRequest, *_args: Any, **kwargs: Any) -> HttpResponse:
        """Return graph JSON for the requested definition."""
        definition_id = kwargs.get('definition_id') or kwargs.get('pk')
        definition = get_object_or_404(Workflow2Definition, id=definition_id)
        graph = WorkflowGraphService().definition_graph(definition=definition)
        return JsonResponse(graph)
