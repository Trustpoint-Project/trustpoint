# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for the users application."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError
from django.shortcuts import redirect
from django.utils import timezone, translation
from django.utils.translation import gettext
from django.views.generic import FormView, UpdateView

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse

from setup_wizard.models import SetupWizardCompletedModel
from users.permissions import AppPermissions

from .form import TrustpointPasswordChangeForm, TrustpointPasswordSetForm, TrustpointUserProfileForm
from .models import TrustpointUser


class PasswordChangeRequiredView(LoginRequiredMixin, FormView[TrustpointPasswordChangeForm]):
    """View shown when a user must change their password before continuing."""

    template_name = 'users/password_change_required.html'
    form_class = TrustpointPasswordChangeForm
    success_url = '/'

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind the password form to the authenticated user."""
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form: TrustpointPasswordChangeForm) -> HttpResponse:
        """Change the password, clear the requirement, and keep the session active."""
        user = cast('TrustpointUser', self.request.user)
        form.save()
        user.must_change_password = False
        user.save(update_fields=['must_change_password'])
        update_session_auth_hash(self.request, user)
        messages.success(self.request, gettext('Password changed successfully.'))
        return super().form_valid(form)


class TrustpointProfileView(LoginRequiredMixin, UpdateView[TrustpointUser, TrustpointUserProfileForm]):
    """Dedicated profile page for the current user and their preferences."""

    form_class = TrustpointUserProfileForm
    template_name = 'users/profile.html'
    success_url = '/users/profile/'

    def get_object(self, _queryset: QuerySet[TrustpointUser] | None = None) -> TrustpointUser:
        """Return the requested user when self-editing or managing users."""
        current_user = cast('TrustpointUser', self.request.user)
        target_pk = self.kwargs.get('pk')
        if target_pk is None or target_pk == current_user.pk:
            return current_user
        if not current_user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied
        return TrustpointUser.objects.get(pk=target_pk)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the current user so role/organization fields can be permission-aware."""
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the separate account-security form to the profile page."""
        context = super().get_context_data(**kwargs)
        profile_user = self.object
        context['can_change_password'] = (
            profile_user.pk == self.request.user.pk
            or self.request.user.has_perm(AppPermissions.MANAGE_USERS)
        )
        context['can_manage_account_security'] = (
            context['can_change_password']
            or self.request.user.has_perm(AppPermissions.MANAGE_USERS)
        )
        context['failed_login_blocked'] = bool(profile_user.blocked_by_failed_logins)
        context['can_unblock_failed_login'] = (
            profile_user.blocked_by_failed_logins
            and self.request.user.has_perm(AppPermissions.MANAGE_USERS)
        )
        if context['can_change_password']:
            if profile_user.pk == self.request.user.pk:
                context.setdefault('password_form', TrustpointPasswordChangeForm(user=profile_user))
            else:
                context.setdefault('password_form', TrustpointPasswordSetForm(user=profile_user))
        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle either profile preferences or account-security updates."""
        if request.POST.get('form_name') == 'password_change':
            return self._post_password_change(request)

        if request.POST.get('form_name') == 'require_password_change':
            self.object = self.get_object()
            if self.object.pk == request.user.pk or request.user.has_perm(AppPermissions.MANAGE_USERS):
                self.object.must_change_password = True
                self.object.save(update_fields=['must_change_password'])
                if self.object.pk == request.user.pk:
                    request.session['password_change_current_session'] = True
                messages.success(
                    request,
                    gettext('The user will be required to change their password at their next login.'),
                )
            return redirect(request.path)

        if request.POST.get('form_name') == 'unblock_failed_login':
            self.object = self.get_object()
            if not request.user.has_perm(AppPermissions.MANAGE_USERS):
                raise PermissionDenied
            if self.object.blocked_by_failed_logins:
                self.object.is_active = True
                self.object.failed_login_attempts = 0
                self.object.blocked_by_failed_logins = False
                self.object.save(
                    update_fields=['is_active', 'failed_login_attempts', 'blocked_by_failed_logins'],
                )
                messages.success(request, gettext('The user has been unblocked and can log in again.'))
            return redirect(request.path)

        return super().post(request, *args, **kwargs)

    def _post_password_change(self, request: HttpRequest) -> HttpResponse:
        """Change the current user's or a managed user's password."""
        self.object = self.get_object()
        is_self_change = self.object.pk == request.user.pk
        if not is_self_change and not request.user.has_perm(AppPermissions.MANAGE_USERS):
            raise PermissionDenied

        if is_self_change:
            password_form: TrustpointPasswordChangeForm | TrustpointPasswordSetForm = TrustpointPasswordChangeForm(
                user=self.object,
                data=request.POST,
            )
        else:
            password_form = TrustpointPasswordSetForm(user=self.object, data=request.POST)

        if not password_form.is_valid():
            return self.render_to_response(self.get_context_data(password_form=password_form))

        password_form.save()
        if is_self_change:
            update_session_auth_hash(request, self.object)
        messages.success(request, gettext('Password changed successfully.'))
        return redirect(request.path)

    def form_valid(self, form: TrustpointUserProfileForm) -> HttpResponse:
        """Persist the user and apply the chosen language/timezone immediately."""
        super().form_valid(form)
        user = cast('TrustpointUser', self.request.user)
        translation.activate(user.language)
        timezone.activate(user.timezone)
        if self.object.pk == user.pk:
            return redirect('home:index')
        return redirect(self.request.path)


class TrustpointLoginView(LoginView):
    """Login view for the trustpoint application."""

    http_method_names = ('get', 'post')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add context about initial bootstrap login if applicable."""
        context = super().get_context_data(**kwargs)

        username = getattr(settings, 'TRUSTPOINT_BOOTSTRAP_USERNAME', 'admin')
        user_model = get_user_model()

        try:
            setup_completed = SetupWizardCompletedModel.setup_wizard_completed()
            if not setup_completed:
                bootstrap_user = user_model.objects.get(username=username)
                if bootstrap_user.last_login is None:
                    context['show_bootstrap_hint'] = True
                    context['bootstrap_username'] = username
        except (user_model.DoesNotExist, DatabaseError):
            pass

        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Redirects to the appropriate startup wizard section if the setup wizard is not completed.

        Args:
            request: The django request object.
            *args: All positional arguments are passed to super().get().
            **kwargs: All keyword arguments are passed to super().get().

        Returns:
            The HttpResponse object, which may be a redirect.
        """
        for _message in messages.get_messages(self.request):
            pass

        return super().get(request, *args, **kwargs)


    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Redirects to the appropriate startup wizard section if the setup wizard is not completed.

        Args:
            request: The django request object.
            *args: All positional arguments are passed to super().post().
            **kwargs: All keyword arguments are passed to super().post().

        Returns:
            The HttpResponse object, which may be a redirect.
        """
        for _message in messages.get_messages(self.request):
            pass

        return super().post(request, *args, **kwargs)
