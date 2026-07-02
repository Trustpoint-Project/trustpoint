"""Views for the Organization management section of the management app."""

from typing import Any

from django.contrib import messages
from django.forms import BaseModelForm
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views.generic.list import ListView

from management.forms import OrganizationForm
from management.models.audit_log import AuditLog
from management.models.organization import OrganizationModel
from trustpoint.logger import LoggerMixin
from trustpoint.views.base import ContextDataMixin, SuperuserRequiredMixin


class OrganizationContextMixin(ContextDataMixin):
    """Mixin providing sidebar context for organization management pages."""

    context_page_category = 'management'
    context_page_name = 'organization'


class OrganizationTableView(
    OrganizationContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    ListView[OrganizationModel],
):
    """List view displaying all organizations."""

    model = OrganizationModel
    template_name = 'management/organization/organization_management.html'
    context_object_name = 'organizations'


class OrganizationCreateView(
    OrganizationContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    CreateView[OrganizationModel, BaseModelForm[OrganizationModel]],
):
    """View for creating a new organization."""

    model = OrganizationModel
    form_class = OrganizationForm
    template_name = 'management/organization/organization_add.html'
    success_url = reverse_lazy('management:organization')

    def form_valid(self, form: BaseModelForm[OrganizationModel]) -> HttpResponse:
        """Save the new organization, write audit log, and show a success message."""
        response = super().form_valid(form)

        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.ORGANIZATION_UPDATED,
            target=self.object,
            target_display=f'Organization: {self.object.name}',
            actor=actor,
            details={'action': 'created'},
        )

        messages.success(
            self.request,
            _('Organization "%(name)s" created successfully.') % {'name': self.object.name},
        )
        return response


class OrganizationEditView(
    OrganizationContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    UpdateView[OrganizationModel, BaseModelForm[OrganizationModel]],
):
    """View for editing an existing organization."""

    model = OrganizationModel
    form_class = OrganizationForm
    template_name = 'management/organization/organization_edit.html'
    success_url = reverse_lazy('management:organization')

    def form_valid(self, form: BaseModelForm[OrganizationModel]) -> HttpResponse:
        """Save organization changes, write audit log, and show a success message."""
        response = super().form_valid(form)

        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.ORGANIZATION_UPDATED,
            target=self.object,
            target_display=f'Organization: {self.object.name}',
            actor=actor,
            details={'action': 'updated'},
        )

        messages.success(
            self.request,
            _('Organization "%(name)s" updated successfully.') % {'name': self.object.name},
        )
        return response


class OrganizationDeleteView(
    OrganizationContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    DeleteView[OrganizationModel, Any],
):
    """View for deleting an organization."""

    model = OrganizationModel
    template_name = 'management/organization/organization_confirm_delete.html'
    success_url = reverse_lazy('management:organization')

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete the organization, write audit log, and show a success message."""
        self.object = self.get_object()

        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.ORGANIZATION_UPDATED,
            target=self.object,
            target_display=f'Organization: {self.object.name}',
            actor=actor,
            details={'action': 'deleted'},
        )

        messages.success(
            self.request,
            _('Organization "%(name)s" deleted successfully.') % {'name': self.object.name},
        )
        return super().form_valid(form)
