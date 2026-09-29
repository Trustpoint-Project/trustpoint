# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Middleware for service account security."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth import BACKEND_SESSION_KEY, logout
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import redirect
from django.urls import reverse
from django_otp import DEVICE_ID_SESSION_KEY

from management.models import PasswordPolicy

from .models import TrustpointUser, UserOTPDevice

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse


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
