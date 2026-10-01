# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for the User Management section of the management app."""

from typing import Any

from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeView
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import QuerySet
from django.forms import BaseModelForm
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views.generic.list import ListView
from drf_spectacular.utils import extend_schema
from rest_framework import status, viewsets
from rest_framework.request import Request
from rest_framework.response import Response

from management.permissions import IsSuperUser
from management.serializer.user import UserSerializer
from trustpoint.logger import LoggerMixin
from trustpoint.views.base import ContextDataMixin, SortableTableMixin, SuperuserRequiredMixin
from users.form import (
    TrustpointUserCreationForm,
    TrustpointUserDetailsForm,
    TrustpointUserRoleForm,
    TrustpointUserSetPasswordForm,
)
from users.models import BuiltinRole, TrustpointUser, UserOTPDevice, is_last_admin_user
from users.permissions import AppPermissions


def _reset_user_otp(user: TrustpointUser) -> None:
    """Delete the authenticator and recovery codes while the caller holds the user row lock."""
    device = UserOTPDevice.objects.select_for_update().filter(user=user).first()
    if device is not None:
        device.delete()


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
        user.role.name == BuiltinRole.ADMIN
        and get_user_model().objects.filter(role__name=BuiltinRole.ADMIN).count() == 1
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
    template_name = 'management/users/user_management.html'
    context_object_name = 'users'
    default_sort_param = 'username'

    def get_queryset(self) -> QuerySet[TrustpointUser]:
        """Return human users only."""
        return TrustpointUser.objects.filter(account_type=TrustpointUser.AccountType.HUMAN)


class UserCreateView(
    UserContextMixin,
    LoggerMixin,
    SuperuserRequiredMixin,
    CreateView[TrustpointUser, BaseModelForm[TrustpointUser]],
):
    """View for creating a new TrustpointUser."""

    model = TrustpointUser
    form_class = TrustpointUserCreationForm
    template_name = 'management/users/user_add.html'
    success_url = reverse_lazy('management:user_management')

    def form_valid(self, form: BaseModelForm[TrustpointUser]) -> HttpResponse:
        """Save the new user and show a success message.

        Args:
            form: The validated creation form.

        Returns:
            Redirect to the user management list.
        """
        if not self.request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
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
    template_name = 'management/users/user_confirm_delete.html'
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
        if not self.request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied

        self.object = self.get_object()

        if is_last_admin_user(self.object):
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


class UserConfigurationMixin(UserContextMixin, LoginRequiredMixin, SuperuserRequiredMixin):
    """Share access rules and navigation for configuring a human user."""

    model = TrustpointUser
    queryset = TrustpointUser.objects.filter(account_type=TrustpointUser.AccountType.HUMAN)
    template_name = 'management/user_edit.html'
    object: TrustpointUser

    def get_success_url(self) -> str:
        """Return to the selected user's configuration page after saving."""
        return reverse('management:configure_user', kwargs={'pk': self.object.pk})


class UserConfigureView(UserConfigurationMixin, DetailView[TrustpointUser]):
    """Select which part of a user's configuration to edit."""

    template_name = 'management/user_configure.html'


class UserDetailsView(UserConfigurationMixin, UpdateView[TrustpointUser, BaseModelForm[TrustpointUser]]):
    """Edit the user's name and email address."""

    form_class = TrustpointUserDetailsForm
    page_title = _('Details')

    def form_valid(self, form: BaseModelForm[TrustpointUser]) -> HttpResponse:
        """Save personal details for an authorized administrator."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
        response = super().form_valid(form)
        messages.success(self.request, _('User details saved.'))
        return response


class UserChangeRoleView(
    UserConfigurationMixin,
    LoggerMixin,
    UpdateView[TrustpointUser, BaseModelForm[TrustpointUser]],
):
    """View for changing the role of an existing TrustpointUser.

    Refuses to downgrade the last remaining admin account.
    """

    form_class = TrustpointUserRoleForm
    template_name = 'management/users/user_change_role.html'
    success_url = reverse_lazy('management:user_management')
    page_title = _('Roles & Organization')

    def form_valid(self, form: BaseModelForm[TrustpointUser]) -> HttpResponse:
        """Save the role change unless it would remove the last admin.

        Raises:
            PermissionDenied: If the current user does not have permission to manage users.

        Args:
            form: The validated role form.

        Returns:
            Redirect to the user's configuration page on success, or re-render the
            form with an error message if the last admin would be downgraded.
        """
        if not self.request.user.has_perm(AppPermissions.MANAGE_ROLES):
            raise PermissionDenied
        user: TrustpointUser = self.get_object()
        new_role = form.cleaned_data['role']

        if is_last_admin_user(user) and new_role.name != BuiltinRole.ADMIN:
            messages.error(
                self.request,
                _('Cannot change role of "%(username)s": at least one admin must remain.')
                % {'username': user.username},
            )
            return self.render_to_response(self.get_context_data(form=form))

        response = super().form_valid(form)
        messages.success(
            self.request,
            _('Role and organization of "%(username)s" saved.') % {'username': user.username},
        )
        return response


class UserChangePasswordView(UserConfigurationMixin, PasswordChangeView):
    """Allow an administrator to set a password using the configured password policy."""

    form_class = TrustpointUserSetPasswordForm
    page_title = _('Change Password')

    def get_form(self, form_class: type[SetPasswordForm] | None = None) -> SetPasswordForm:
        """Hide password requirements help text."""
        form = super().get_form(form_class)
        form.fields['new_password1'].help_text = ''
        return form

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the selected user to Django's password-setting form."""
        kwargs = super().get_form_kwargs()
        self.object = get_object_or_404(self.queryset, pk=self.kwargs['pk'])
        kwargs['user'] = self.object
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Show the selected user in the shared form layout."""
        context = super().get_context_data(**kwargs)
        context['object'] = self.object
        return context

    def form_valid(self, form: SetPasswordForm) -> HttpResponse:
        """Save the password and optional authenticator reset in one transaction."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
        with transaction.atomic():
            form.user = get_object_or_404(self.queryset.select_for_update(), pk=self.object.pk)
            user = form.save()
            if form.cleaned_data['reset_otp']:
                _reset_user_otp(user)
        if user.pk == self.request.user.pk:
            update_session_auth_hash(self.request, user)
        if form.cleaned_data['reset_otp']:
            messages.success(self.request, _('Password changed and authenticator reset successfully.'))
        else:
            messages.success(self.request, _('Password changed successfully.'))
        return HttpResponseRedirect(self.get_success_url())


class UserResetOTPView(UserConfigurationMixin, View):
    """Allow an administrator to reset a human user's authenticator without changing their password."""

    http_method_names = ('post',)

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Remove the authenticator and recovery codes after checking management permissions."""
        if not request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
        with transaction.atomic():
            self.object = get_object_or_404(self.queryset.select_for_update(), pk=self.kwargs['pk'])
            _reset_user_otp(self.object)
        messages.success(request, _('Authenticator reset. The user will need to set it up again when signing in.'))
        return HttpResponseRedirect(self.get_success_url())


@extend_schema(tags=['User Management'])
class UserViewSet(viewsets.ModelViewSet[TrustpointUser]):
    """API view for user."""
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsSuperUser,)

    def destroy(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Delete the user unless they are the last remaining admin.

        Raises:
            PermissionDenied: If the current user does not have permission to manage users.
        """
        if not request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
        instance = self.get_object()
        if is_last_admin_user(instance):
            return Response(
                {'detail': 'Cannot delete this user: at least one admin must remain.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Update the user, refusing to change the role of the last remaining admin.

        Raises:
            PermissionDenied: If the current user does not have permission to manage users.
        """
        if not request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
        instance = self.get_object()
        new_role = request.data.get('role') if isinstance(request.data, dict) else None
        if is_last_admin_user(instance) and new_role is not None and str(new_role) != str(instance.role_id):
            return Response(
                {'detail': 'Cannot change role of this user: at least one admin must remain.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().update(request, *args, **kwargs)
