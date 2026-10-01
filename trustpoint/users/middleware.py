# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Middleware for web authentication and service account security and per-user preferences."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, REDIRECT_FIELD_NAME, login, logout
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ValidationError
from django.shortcuts import redirect, resolve_url
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _
from django_otp import DEVICE_ID_SESSION_KEY
from django.utils import timezone, translation

from management.i18n_context import reset_current_user, set_current_user
from management.models import AccountSecurityConfig

from management.models import PasswordPolicy

from .authentication import (
    CERTIFICATE_BACKEND,
    CERTIFICATE_LOGIN_ERROR_SESSION_KEY,
    REJECTED_CERTIFICATE_SESSION_KEY,
    ClientCertificateBackend,
)
from .models import TrustpointUser, UserOTPDevice

SESSION_ACTIVITY_WRITE_INTERVAL_SECONDS = 60

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.contrib.auth.models import AnonymousUser
    from django.http import HttpRequest, HttpResponse


class ClientCertificateAuthenticationMiddleware:
    """Sign in users with registered TLS certificates and recheck certificate sessions."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Store the next middleware and the certificate validation backend."""
        self.get_response = get_response
        self.backend = ClientCertificateBackend()
        self.login_path = reverse('users:login')
        self.logout_path = reverse('users:logout')

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Authenticate web requests without interfering with password login or public APIs."""
        certificate_session = request.session.get(BACKEND_SESSION_KEY) == CERTIFICATE_BACKEND
        if self._skip_authentication(request, certificate_session=certificate_session):
            return self.get_response(request)
        if not request.META.get('HTTP_SSL_CLIENT_CERT') and not certificate_session:
            return self.get_response(request)

        try:
            user = self._authenticate(request)
        except ValidationError as exc:
            return self._authentication_failed(request, exc)

        if not request.user.is_authenticated or request.user.pk != user.pk or not certificate_session:
            # Django flushes a different user's session and replaces request.user, including its permissions.
            login(request, user, backend=CERTIFICATE_BACKEND)
        request.session.pop(CERTIFICATE_LOGIN_ERROR_SESSION_KEY, None)
        request.session.pop(REJECTED_CERTIFICATE_SESSION_KEY, None)
        if request.path_info == self.login_path:
            next_url = request.GET.get(REDIRECT_FIELD_NAME, '')
            if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}, require_https=True):
                next_url = resolve_url(settings.LOGIN_REDIRECT_URL)
            return redirect(next_url)
        return self.get_response(request)

    def _authenticate(self, request: HttpRequest) -> TrustpointUser:
        """Select the authenticated user exclusively from the validated certificate."""
        user = self.backend.authenticate(request, certificate_login=True)
        if user is None:
            raise ValidationError(_('No valid client certificate was supplied.'))
        return user

    def _authentication_failed(self, request: HttpRequest, error: ValidationError) -> HttpResponse:
        """Allow password fallback only for the same rejected certificate after a fresh password login."""
        certificate_digest = hashlib.sha256(request.META.get('HTTP_SSL_CLIENT_CERT', '').encode('utf-8')).hexdigest()
        if (
            request.user.is_authenticated
            and request.session.get(BACKEND_SESSION_KEY) == 'django.contrib.auth.backends.ModelBackend'
            and request.session.get(REJECTED_CERTIFICATE_SESSION_KEY) == certificate_digest
        ):
            return self.get_response(request)
        logout(request)
        request.session[REJECTED_CERTIFICATE_SESSION_KEY] = certificate_digest
        request.session[CERTIFICATE_LOGIN_ERROR_SESSION_KEY] = ' '.join(error.messages)
        next_path = request.get_full_path() if request.path_info != self.login_path else ''
        return redirect_to_login(next_path, f'{self.login_path}?password=1')

    def _skip_authentication(self, request: HttpRequest, *, certificate_session: bool) -> bool:
        """Leave password/OTP fallback, logout, bootstrap, and unauthenticated public requests usable."""
        path = request.path_info
        if settings.TRUSTPOINT_IS_BOOTSTRAP:
            return True
        if (
            not certificate_session and not request.user.is_authenticated
            and any(path.startswith(prefix) for prefix in settings.PUBLIC_PATHS)
        ):
            return True
        if path.startswith('/static/') or path == self.logout_path:
            return True
        if path.startswith(self.login_path) and (
            path != self.login_path or request.method != 'GET' or request.GET.get('password') == '1'
        ):
            return True
        # Login rotates CSRF tokens; authenticate new sessions on navigation, before forms are submitted.
        return not request.user.is_authenticated and request.method not in {'GET', 'HEAD'}


class PasswordOTPRequiredMiddleware:
    """Enforce OTP on web sessions authenticated by the password backend."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Store the next middleware or view."""
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Require a fresh password and OTP for existing unverified password sessions."""
        if (
            not request.path_info.startswith('/api/')
            and request.user.is_authenticated
            and request.session.get(BACKEND_SESSION_KEY) == 'django.contrib.auth.backends.ModelBackend'
            and PasswordPolicy.is_otp_required()
        ):
            device = UserOTPDevice.objects.filter(user=request.user, confirmed=True).only('id').first()
            if device is None or request.session.get(DEVICE_ID_SESSION_KEY) != device.persistent_id:
                logout(request)
                next_path = '' if request.path_info.startswith('/users/') else request.get_full_path()
                return redirect_to_login(next_path, reverse('users:login'))
        return self.get_response(request)


class UserPreferencesMiddleware:
    """Apply the authenticated user's language, timezone, and theme for the request."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware."""
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Activate the current user's settings for this request."""
        user = request.user
        user_token = set_current_user(user if user.is_authenticated else None)
        if user.is_authenticated:
            language = getattr(user, 'language', None) or settings.LANGUAGE_CODE
            tz_name = getattr(user, 'timezone', None) or settings.TIME_ZONE
            translation.activate(language)
            timezone.activate(tz_name)
            request.__dict__['LANGUAGE_CODE'] = language
            request.__dict__['timezone_name'] = tz_name

        try:
            return self.get_response(request)
        finally:
            reset_current_user(user_token)
            if user.is_authenticated:
                translation.deactivate()
                timezone.deactivate()


class PasswordChangeRequiredMiddleware:
    """Force users marked for password rotation through the change-password page."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware."""
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Redirect flagged authenticated users until they change their password."""
        if (
            request.user.is_authenticated
            and (
                getattr(request.user, 'must_change_password', False)
                or (
                    getattr(request.user, 'account_type', None) == TrustpointUser.AccountType.HUMAN
                    and request.user.password_is_expired()
                )
            )
            and not request.session.get('password_change_current_session')
            and request.path != reverse('users:password-change-required')
        ):
            return redirect(reverse('users:password-change-required'))
        return self.get_response(request)


class IdleSessionTimeoutMiddleware:
    """Expire inactive interactive human-user sessions using runtime policy."""

    SESSION_KEY = '_trustpoint_last_activity'

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware."""
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Enforce inactivity timeout without affecting API authentication."""
        user = request.user
        if not self._is_interactive_human_request(request, user):
            return self.get_response(request)

        now = timezone.now().timestamp()
        last_activity = request.session.get(self.SESSION_KEY)
        timeout_seconds = AccountSecurityConfig.get().idle_timeout_minutes * 60
        if last_activity is not None and now - float(last_activity) >= timeout_seconds:
            logout(request)
            return redirect(f'{reverse("users:login")}?next={request.path}')

        # Avoid rewriting the session on every request while still recording
        # activity often enough for the configured timeout to be accurate.
        if (
            last_activity is None
            or now - float(last_activity) >= SESSION_ACTIVITY_WRITE_INTERVAL_SECONDS
        ):
            request.session[self.SESSION_KEY] = now
        return self.get_response(request)

    @staticmethod
    def _is_interactive_human_request(
        request: HttpRequest,
        user: TrustpointUser | AnonymousUser,
    ) -> bool:
        """Return whether the request belongs to a human browser session."""
        return bool(
            isinstance(user, TrustpointUser)
            and user.is_authenticated
            and user.account_type == TrustpointUser.AccountType.HUMAN
            and not request.path.startswith('/api/')
            and request.path not in {reverse('users:login'), reverse('users:logout')}
        )


class ServiceAccountMiddleware:
    """Middleware to prevent service accounts from logging into the Web UI.

    Service accounts should only use API authentication, not interactive Web UI login.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware.

        Args:
            get_response: The next middleware or view.
        """
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request.

        Args:
            request: The HTTP request.

        Returns:
            The HTTP response.
        """
        if (
            request.user.is_authenticated
            and hasattr(request.user, 'account_type')
            and request.user.account_type == TrustpointUser.AccountType.SERVICE
        ):
            if self._is_api_path(request.path):
                return self.get_response(request)

            logout(request)
            return redirect(f"{reverse('users:login')}?error=service_account")

        return self.get_response(request)

    @staticmethod
    def _is_api_path(path: str) -> bool:
        """Check if the path is an API endpoint.

        Args:
            path: The request path.

        Returns:
            True if it's an API path.
        """
        return path.startswith('/api/')
