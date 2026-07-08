"""Views for the User Management section of the management app."""

from typing import Any

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.forms import BaseModelForm
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views.generic.list import ListView

from trustpoint.logger import LoggerMixin
from trustpoint.views.base import ContextDataMixin, SortableTableMixin, SuperuserRequiredMixin
from users.form import TrustpointUserCreationForm, TrustpointUserRoleForm
from users.models import Role, TrustpointUser


def _is_last_admin(user: TrustpointUser) -> bool:
    """Return True if the given user is the only remaining admin.

    Used to prevent accidental lock-out by deleting or downgrading the
    sole admin account.

    Args:
        user: The TrustpointUser instance to check.

    Returns:
        True when the user has the ADMIN role and no other admin exists.
    """
    return (
        user.role.name == Role.ADMIN
        and get_user_model().objects.filter(role__name=Role.ADMIN).count() == 1
    )


class UserContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the User Management -> Management page."""

    context_page_category = 'management'
    context_page_name = 'user_management'


class UserTableView(
    UserContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    SortableTableMixin[TrustpointUser],
    ListView[TrustpointUser],
):
    """List view displaying all Trustpoint users in a sortable table."""

    model = TrustpointUser
    template_name = 'management/user_management.html'
    context_object_name = 'users'
    default_sort_param = 'username'


class UserCreateView(
    UserContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    CreateView[TrustpointUser, BaseModelForm[TrustpointUser]],
):
    """View for creating a new TrustpointUser."""

    model = TrustpointUser
    form_class = TrustpointUserCreationForm
    template_name = 'management/user_add.html'
    success_url = reverse_lazy('management:user_management')

    def form_valid(self, form: BaseModelForm[TrustpointUser]) -> HttpResponse:
        """Save the new user and show a success message.

        Args:
            form: The validated creation form.

        Returns:
            Redirect to the user management list.
        """
        response = super().form_valid(form)
        username = self.object.username if self.object else ''
        messages.success(
            self.request,
            _('User "%(username)s" created successfully.') % {'username': username},
        )
        return response


class UserDeleteView(
    UserContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    DeleteView[TrustpointUser, Any],
):
    """View for deleting a TrustpointUser.

    Refuses to delete the last remaining admin account to prevent lock-out.
    """

    model: type[TrustpointUser] = TrustpointUser
    template_name = 'management/user_confirm_delete.html'
    success_url = reverse_lazy('management:user_management')

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete the user unless they are the last admin.

        Overrides ``form_valid`` because Django 5+ ``DeleteView`` no longer
        calls ``delete()`` — it uses the form-based flow instead.

        Args:
            form: The deletion confirmation form.

        Returns:
            Redirect to the user management list on success, or back to the
            list with an error message if the last admin would be removed.
        """
        self.object = self.get_object()

        if _is_last_admin(self.object):
            messages.error(
                self.request,
                _('Cannot delete "%(username)s": at least one admin must remain.') % {'username': self.object.username},
            )
            return HttpResponseRedirect(self.success_url)

        messages.success(
            self.request,
            _('User "%(username)s" deleted successfully.') % {'username': self.object.username},
        )
        return super().form_valid(form)


class UserChangeRoleView(
    UserContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    UpdateView[TrustpointUser, BaseModelForm[TrustpointUser]],
):
    """View for changing the role of an existing TrustpointUser.

    Refuses to downgrade the last remaining admin account.
    """

    model = TrustpointUser
    form_class = TrustpointUserRoleForm
    template_name = 'management/user_change_role.html'
    success_url = reverse_lazy('management:user_management')

    def form_valid(self, form: BaseModelForm[TrustpointUser]) -> HttpResponse:
        """Save the role change unless it would remove the last admin.

        Args:
            form: The validated role form.

        Returns:
            Redirect to the user management list on success, or re-render the
            form with an error message if the last admin would be downgraded.
        """
        user: TrustpointUser = self.get_object()
        new_role = form.cleaned_data['role']

        if _is_last_admin(user) and new_role.name != Role.ADMIN:
            messages.error(
                self.request,
                _('Cannot change role of "%(username)s": at least one admin must remain.')
                % {'username': user.username},
            )
            return self.render_to_response(self.get_context_data(form=form))

        response = super().form_valid(form)
        messages.success(
            self.request,
            _('Role of "%(username)s" changed successfully.') % {'username': user.username},
        )
        return response
