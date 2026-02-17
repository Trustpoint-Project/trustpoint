from __future__ import annotations

from typing import Any
from uuid import UUID

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from django.views.generic import ListView

from workflows2.forms import Workflow2DefinitionForm
from workflows2.models import Workflow2Definition
from workflows2.services.definitions import WorkflowDefinitionService


class Workflow2DefinitionListView(LoginRequiredMixin, ListView[Workflow2Definition]):
    model = Workflow2Definition
    template_name = "workflows2/definition_list.html"
    context_object_name = "definitions"
    paginate_by = 50

    def get_queryset(self):
        return Workflow2Definition.objects.order_by("-created_at")


class Workflow2DefinitionCreateView(LoginRequiredMixin, View):
    template_name = "workflows2/definition_editor.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        form = Workflow2DefinitionForm(
            initial={
                "name": "New workflow",
                "enabled": True,
                "yaml_text": '',
            }
        )
        return render(
            request,
            self.template_name,
            {
                "mode": "create",
                "form": form,
                "definition": None,
                "compile_error": None,
                "ir_json": None,
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        form = Workflow2DefinitionForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "mode": "create",
                    "form": form,
                    "definition": None,
                    "compile_error": None,
                    "ir_json": None,
                },
            )

        svc = WorkflowDefinitionService()
        obj, res = svc.create_definition(
            name=form.cleaned_data["name"],
            enabled=bool(form.cleaned_data["enabled"]),
            yaml_text=form.cleaned_data["yaml_text"],
        )

        if not res.ok:
            return render(
                request,
                self.template_name,
                {
                    "mode": "create",
                    "form": form,
                    "definition": None,
                    "compile_error": res.error,
                    "ir_json": None,
                },
            )

        assert obj is not None
        messages.success(request, "Workflow saved.")
        return redirect("workflows2:definitions_edit", pk=obj.id)


class Workflow2DefinitionEditView(LoginRequiredMixin, View):
    template_name = "workflows2/definition_editor.html"

    def get(self, request: HttpRequest, pk: UUID) -> HttpResponse:
        obj = get_object_or_404(Workflow2Definition, pk=pk)
        form = Workflow2DefinitionForm(
            initial={
                "name": obj.name,
                "enabled": obj.enabled,
                "yaml_text": obj.yaml_text,
            }
        )

        return render(
            request,
            self.template_name,
            {
                "mode": "edit",
                "form": form,
                "definition": obj,
                "compile_error": None,
                "ir_json": obj.ir_json,
            },
        )

    def post(self, request: HttpRequest, pk: UUID) -> HttpResponse:
        obj = get_object_or_404(Workflow2Definition, pk=pk)
        form = Workflow2DefinitionForm(request.POST)

        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "mode": "edit",
                    "form": form,
                    "definition": obj,
                    "compile_error": None,
                    "ir_json": obj.ir_json,
                },
            )

        svc = WorkflowDefinitionService()
        updated, res = svc.update_definition(
            definition=obj,
            name=form.cleaned_data["name"],
            enabled=bool(form.cleaned_data["enabled"]),
            yaml_text=form.cleaned_data["yaml_text"],
        )

        if not res.ok:
            return render(
                request,
                self.template_name,
                {
                    "mode": "edit",
                    "form": form,
                    "definition": obj,
                    "compile_error": res.error,
                    "ir_json": obj.ir_json,
                },
            )

        assert updated is not None
        messages.success(request, "Workflow updated.")
        return redirect("workflows2:definitions_edit", pk=updated.id)


