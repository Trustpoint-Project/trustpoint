# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Authentication backends for service accounts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password

from .models import ServiceAccountCredential, TrustpointUser

if TYPE_CHECKING:
    from django.http import HttpRequest


class ServiceAccountBackend(BaseBackend):
    """Authentication backend for service accounts using API keys.

    This backend authenticates service accounts using client_id and secret.
    It should not be used for human accounts or Web UI login.
    """

    def authenticate(
        self,
        request: HttpRequest | None = None,  # noqa: ARG002
        client_id: str | None = None,
        secret: str | None = None,
        **kwargs: object,  # noqa: ARG002
    ) -> TrustpointUser | None:
        """Authenticate a service account using client ID and secret.

        Args:
            request: The HTTP request (unused, required for compatibility with BaseBackend).
            client_id: The service account's client ID.
            secret: The service account's API secret (plaintext).
            **kwargs: Additional keyword arguments (unused, required for compatibility with BaseBackend).

        Returns:
            The authenticated TrustpointUser (service account) or None.
        """
        client_id = (client_id or '').strip()
        secret = (secret or '').strip()
        if not client_id or not secret:
            return None

        try:
            credential = ServiceAccountCredential.objects.select_related('service_account').get(
                client_id=client_id,
                is_active=True,
            )
        except ServiceAccountCredential.DoesNotExist:
            return None

        if not credential.is_valid():
            return None

        user = credential.service_account
        if user.account_type != TrustpointUser.AccountType.SERVICE or not user.is_active:
            return None

        if not check_password(secret, credential.hashed_secret):
            return None

        credential.record_usage()

        return user

    def get_user(self, user_id: int) -> TrustpointUser | None:
        """Retrieve a user by ID.

        Args:
            user_id: The user's primary key.

        Returns:
            The TrustpointUser or None if not found.
        """
        try:
            return TrustpointUser.objects.get(pk=user_id)
        except TrustpointUser.DoesNotExist:
            return None
