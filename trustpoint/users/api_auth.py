# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""REST Framework authentication for service accounts."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from .authentication import ServiceAccountBackend
from .models import TrustpointUser

if TYPE_CHECKING:
    from django.http import HttpRequest


class ServiceAccountAuthentication(BaseAuthentication):
    """DRF authentication class for service accounts using standard OAuth client credentials."""

    @staticmethod
    def _parse_basic_credentials(auth_header: str) -> tuple[str, str]:
        """Parse an HTTP Basic authorization header for client_id:client_secret."""
        try:
            credentials = base64.b64decode(auth_header[6:], validate=True).decode('utf-8')
        except (ValueError, UnicodeDecodeError) as exc:
            msg = _('Invalid service account credentials format. Use: Basic base64(client_id:client_secret)')
            raise exceptions.AuthenticationFailed(msg) from exc

        try:
            client_id, secret = credentials.split(':', 1)
        except ValueError as exc:
            msg = _('Invalid service account credentials format. Use: Basic base64(client_id:client_secret)')
            raise exceptions.AuthenticationFailed(msg) from exc

        return client_id.strip(), secret.strip()

    def _authenticate_credentials(
        self,
        request: HttpRequest,
        client_id: str,
        secret: str,
    ) -> tuple[TrustpointUser, None]:
        """Verify the supplied client credentials against the backend."""
        if not client_id or not secret:
            msg = _('Invalid service account credentials format. Use: Basic base64(client_id:client_secret)')
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

        if not user.has_perm('users.use_rest_api'):
            msg = _('Service account is not permitted to use the REST API.')
            raise exceptions.AuthenticationFailed(msg)

        return (user, None)

    def authenticate(self, request: HttpRequest) -> tuple[TrustpointUser, None] | None:
        """Authenticate service account credentials from a standard HTTP Basic header."""
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header or not auth_header.lower().startswith('basic '):
            return None

        client_id, secret = self._parse_basic_credentials(auth_header)
        return self._authenticate_credentials(request, client_id, secret)

    def authenticate_header(self, request: HttpRequest) -> str:  # noqa: ARG002
        """Return the standard WWW-Authenticate challenge for service-account API auth."""
        return 'Basic realm="api"'
