# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Middleware for service account security and per-user preferences."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone, translation

from management.i18n_context import reset_current_user, set_current_user

from .models import TrustpointUser

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse


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
            and getattr(request.user, 'must_change_password', False)
            and not request.session.get('password_change_current_session')
            and request.path != reverse('users:password-change-required')
        ):
            return redirect(reverse('users:password-change-required'))
        return self.get_response(request)


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
