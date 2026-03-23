from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View

from workflows2.models import Workflow2Definition
from workflows2.services.graph import WorkflowGraphService


class Workflow2DefinitionGraphView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        definition_id = kwargs.get("definition_id") or kwargs.get("pk")
        definition = get_object_or_404(Workflow2Definition, id=definition_id)
        graph = WorkflowGraphService().definition_graph(definition=definition)
        return JsonResponse(graph)
