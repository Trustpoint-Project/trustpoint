"""Workflow definition list and editor views for Workflow 2."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import ListView

from workflows2.forms import Workflow2DefinitionForm
from workflows2.models import Workflow2Definition
from workflows2.services.definitions import WorkflowDefinitionService

if TYPE_CHECKING:
    from uuid import UUID

    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse


class Workflow2DefinitionListView(LoginRequiredMixin, ListView[Workflow2Definition]):
    """Show saved Workflow 2 definitions."""

    model = Workflow2Definition
    template_name = 'workflows2/definition_list.html'
    context_object_name = 'definitions'
    paginate_by = 50

    def get_queryset(self) -> QuerySet[Workflow2Definition]:
        """Return definitions ordered by newest first."""
        return Workflow2Definition.objects.order_by('-created_at')


class Workflow2DefinitionCreateView(LoginRequiredMixin, View):
    """Create a new Workflow 2 definition from YAML."""

    template_name = 'workflows2/definition_editor.html'

    default_yaml = textwrap.dedent(
        """
        schema: trustpoint.workflow.v2
        name: New workflow
        enabled: true

        trigger:
          on: certificate.issued
          sources:
            trustpoint: true
            ca_ids: []
            domain_ids: []
            device_ids: []

        apply: []

        workflow:
          start:
          steps: {}
          flow: []
        """
    ).strip()

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the create form with a starter workflow."""
        form = Workflow2DefinitionForm(
            initial={
                'name': 'New workflow',
                'enabled': True,
                'yaml_text': self.default_yaml,
            }
        )
        return render(
            request,
            self.template_name,
            {
                'mode': 'create',
                'form': form,
                'definition': None,
                'compile_error': None,
                'ir_json': None,
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        """Validate the submitted YAML and create the workflow definition."""
        form = Workflow2DefinitionForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    'mode': 'create',
                    'form': form,
                    'definition': None,
                    'compile_error': None,
                    'ir_json': None,
                },
            )

        svc = WorkflowDefinitionService()
        obj, res = svc.create_definition(
            name=form.cleaned_data['name'],
            enabled=bool(form.cleaned_data['enabled']),
            yaml_text=form.cleaned_data['yaml_text'],
        )

        if not res.ok:
            return render(
                request,
                self.template_name,
                {
                    'mode': 'create',
                    'form': form,
                    'definition': None,
                    'compile_error': res.error,
                    'ir_json': None,
                },
            )

        if obj is None:
            return render(
                request,
                self.template_name,
                {
                    'mode': 'create',
                    'form': form,
                    'definition': None,
                    'compile_error': 'Workflow save succeeded without returning a definition.',
                    'ir_json': None,
                },
            )
        messages.success(request, 'Workflow saved.')
        return redirect('workflows2:definitions_edit', pk=obj.id)


class Workflow2DefinitionEditView(LoginRequiredMixin, View):
    """Edit an existing Workflow 2 definition."""

    template_name = 'workflows2/definition_editor.html'

    def get(self, request: HttpRequest, pk: UUID) -> HttpResponse:
        """Render the editor for an existing workflow definition."""
        obj = get_object_or_404(Workflow2Definition, pk=pk)
        form = Workflow2DefinitionForm(
            initial={
                'name': obj.name,
                'enabled': obj.enabled,
                'yaml_text': obj.yaml_text,
            }
        )

        return render(
            request,
            self.template_name,
            {
                'mode': 'edit',
                'form': form,
                'definition': obj,
                'compile_error': None,
                'ir_json': obj.ir_json,
            },
        )

    def post(self, request: HttpRequest, pk: UUID) -> HttpResponse:
        """Validate the submitted YAML and update the workflow definition."""
        obj = get_object_or_404(Workflow2Definition, pk=pk)
        form = Workflow2DefinitionForm(request.POST)

        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    'mode': 'edit',
                    'form': form,
                    'definition': obj,
                    'compile_error': None,
                    'ir_json': obj.ir_json,
                },
            )

        svc = WorkflowDefinitionService()
        updated, res = svc.update_definition(
            definition=obj,
            name=form.cleaned_data['name'],
            enabled=bool(form.cleaned_data['enabled']),
            yaml_text=form.cleaned_data['yaml_text'],
        )

        if not res.ok:
            return render(
                request,
                self.template_name,
                {
                    'mode': 'edit',
                    'form': form,
                    'definition': obj,
                    'compile_error': res.error,
                    'ir_json': obj.ir_json,
                },
            )

        if updated is None:
            return render(
                request,
                self.template_name,
                {
                    'mode': 'edit',
                    'form': form,
                    'definition': obj,
                    'compile_error': 'Workflow update succeeded without returning a definition.',
                    'ir_json': obj.ir_json,
                },
            )
        messages.success(request, 'Workflow updated.')
        return redirect('workflows2:definitions_edit', pk=updated.id)
