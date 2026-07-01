"""Views for managing organization."""

from typing import Any, cast

from django import forms
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.views.generic.edit import FormView

from management.forms import OrganizationForm
from management.models.audit_log import AuditLog


class OrganizationContextMixin:
    """Mixin which adds data to the context for the organization."""

    page_category: str = 'management'
    page_name: str = 'organization'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add page_category and page_name to context."""
        context = cast('dict[str, Any]', super().get_context_data(**kwargs))  # type: ignore[misc]
        context['page_category'] = self.page_category
        context['page_name'] = self.page_name
        return context


class OrganizationView(OrganizationContextMixin, FormView[forms.Form]):
    """View to display organization details."""

    http_method_names = ('get', 'post')

    form_class: type[forms.Form] = OrganizationForm
    template_name = 'management/organization/organization.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{self.page_category}:{self.page_name}'
        return context

    def form_valid(self, form: forms.Form) -> HttpResponse:
        """Saves the form / creates the organization model object.

        Args:
            form: The valid form.

        Returns:
            The HTTP Response to be returned.
        """
        self.object = form.save()  # type: ignore[attr-defined]

        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.ORGANIZATION_UPDATED,
            target=self.object,
            target_display=f'Organization: {self.object.name}',
            actor=actor,
        )

        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        return str(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}'
            )
        )
