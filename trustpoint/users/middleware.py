# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Middleware for service account security."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse

from .models import TrustpointUser

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse


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
        api_prefixes = [
            '/api/',
            '/rest/',
            '/.well-known/',
            '/aoki/',
        ]
        return any(path.startswith(prefix) for prefix in api_prefixes)
