"""Views for the Role Management section of the management app.

Provides CRUD operations for Django ``Group`` instances (used as roles)
and their associated permissions.  Only the Admin group is protected and
cannot be deleted or renamed.
"""

from typing import Any

from django.contrib import messages
from django.contrib.auth.models import Group
from django.forms import BaseModelForm
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views.generic.list import ListView

from trustpoint.logger import LoggerMixin
from trustpoint.views.base import ContextDataMixin, SuperuserRequiredMixin
from users.form import GroupPermissionForm
from users.models import Role

# Only Admin is protected — all other roles can be edited/deleted.
_PROTECTED_GROUP_NAMES: frozenset[str] = frozenset({Role.ADMIN.value})


class RoleContextMixin(ContextDataMixin):
    """Mixin providing sidebar context for the Role Management page."""

    context_page_category = 'management'
    context_page_name = 'role_management'


class RoleTableView(
    RoleContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    ListView[Group],
):
    """List view displaying all Django groups in a table."""

    model = Group
    template_name = 'management/role_management.html'
    context_object_name = 'groups'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the set of protected group names to the template context.

        Returns:
            The template context dictionary augmented with
            ``protected_group_names``.
        """
        context = super().get_context_data(**kwargs)
        context['protected_group_names'] = _PROTECTED_GROUP_NAMES
        return context


class RoleCreateView(
    RoleContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    CreateView[Group, BaseModelForm[Group]],
):
    """View for creating a new Django group with permissions."""

    model = Group
    form_class = GroupPermissionForm
    template_name = 'management/role_add.html'
    success_url = reverse_lazy('management:role_management')

    def form_valid(self, form: BaseModelForm[Group]) -> HttpResponse:
        """Save the new group and show a success message.

        Args:
            form: The validated group form.

        Returns:
            Redirect to the role management list.
        """
        response = super().form_valid(form)
        name = self.object.name if self.object else ''
        messages.success(
            self.request,
            _('Role "%(name)s" created successfully.') % {'name': name},
        )
        return response


class RoleEditView(
    RoleContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    UpdateView[Group, BaseModelForm[Group]],
):
    """View for editing an existing group's name and permissions.

    For protected groups the name field is rendered read-only by the
    template (the ``is_protected`` context flag).
    """

    model = Group
    form_class = GroupPermissionForm
    template_name = 'management/role_edit.html'
    success_url = reverse_lazy('management:role_management')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the ``is_protected`` flag to the template context.

        Returns:
            The template context dictionary with ``is_protected`` set to
            ``True`` when the group is one of the built-in roles.
        """
        context = super().get_context_data(**kwargs)
        context['is_protected'] = self.object.name in _PROTECTED_GROUP_NAMES
        return context

    def form_valid(self, form: BaseModelForm[Group]) -> HttpResponse:
        """Save permission changes and show a success message.

        Args:
            form: The validated group form.

        Returns:
            Redirect to the role management list.
        """
        response = super().form_valid(form)
        messages.success(
            self.request,
            _('Role "%(name)s" updated successfully.') % {'name': self.object.name},
        )
        return response


class RoleDeleteView(
    RoleContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    DeleteView[Group, Any],
):
    """View for deleting a Django group.

    Refuses to delete protected (built-in) groups and groups that still
    have users assigned to them.
    """

    model: type[Group] = Group
    template_name = 'management/role_confirm_delete.html'
    success_url = reverse_lazy('management:role_management')

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete the group after checking protection rules.

        Overrides ``form_valid`` because Django 5+ ``DeleteView`` no longer
        calls ``delete()`` — it uses the form-based flow instead.

        Args:
            form: The deletion confirmation form.

        Returns:
            Redirect to the role management list on success, or back to
            the list with an error message if the group is protected or
            still has assigned users.
        """
        self.object = self.get_object()

        if self.object.name in _PROTECTED_GROUP_NAMES:
            messages.error(
                self.request,
                _('Cannot delete "%(name)s": this is a built-in role.') % {'name': self.object.name},
            )
            return HttpResponseRedirect(self.success_url)

        if self.object.trustpoint_users.exists():
            messages.error(
                self.request,
                _('Cannot delete "%(name)s": there are still users assigned to this role.') % {
                    'name': self.object.name,
                },
            )
            return HttpResponseRedirect(self.success_url)

        messages.success(
            self.request,
            _('Role "%(name)s" deleted successfully.') % {'name': self.object.name},
        )
        return super().form_valid(form)
