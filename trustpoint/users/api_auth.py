# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""REST Framework authentication for service accounts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from .authentication import ServiceAccountBackend
from .models import TrustpointUser

if TYPE_CHECKING:
    from django.http import HttpRequest


class ServiceAccountAuthentication(BaseAuthentication):
    """DRF authentication class for service accounts using API keys.

    Expects the credentials to be provided in the Authorization header:
        Authorization: ServiceAccount <client_id>:<secret>
    """

    keyword = 'ServiceAccount'

    def authenticate(self, request: HttpRequest) -> tuple[TrustpointUser, None] | None:
        """Authenticate service account from Authorization header.

        Args:
            request: The HTTP request.

        Returns:
            A tuple of (user, auth) or None.

        Raises:
            AuthenticationFailed: If authentication fails.
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header.startswith(f'{self.keyword} '):
            return None

        try:
            credentials = auth_header[len(self.keyword) + 1:]
            client_id, secret = credentials.split(':', 1)
        except ValueError as exc:
            msg = _('Invalid service account credentials format. Use: ServiceAccount <client_id>:<secret>')
            raise exceptions.AuthenticationFailed(msg) from exc

        client_id = client_id.strip()
        secret = secret.strip()
        if not client_id or not secret:
            msg = _('Invalid service account credentials format. Use: ServiceAccount <client_id>:<secret>')
            raise exceptions.AuthenticationFailed(msg)

        backend = ServiceAccountBackend()
        user = backend.authenticate(request=request, client_id=client_id, secret=secret)

        if user is None:
            msg = _('Invalid service account credentials.')
            raise exceptions.AuthenticationFailed(msg)

        if user.account_type != TrustpointUser.AccountType.SERVICE:
            msg = _('This authentication method is only for service accounts.')
            raise exceptions.AuthenticationFailed(msg)

        if not user.is_active:
            msg = _('Service account is inactive.')
            raise exceptions.AuthenticationFailed(msg)

        return (user, None)

    def authenticate_header(self, request: HttpRequest) -> str:  # noqa: ARG002
        """Return the WWW-Authenticate header value.

        Args:
            request: The HTTP request.

        Returns:
            The authentication scheme.
        """
        return self.keyword
