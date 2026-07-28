# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""OAuth 2.0 token endpoint for service accounts and human users."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from django.contrib.auth import authenticate
from drf_spectacular.utils import OpenApiExample, extend_schema, extend_schema_view
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import TrustpointUser

if TYPE_CHECKING:
    from rest_framework.request import Request


class TokenObtainRequestSerializer(serializers.Serializer):
    """Serializer for token request - supports both authentication methods."""
    username = serializers.CharField(required=False, help_text='Username (for human users)')
    password = serializers.CharField(required=False, help_text='Password (for human users)')
    grant_type = serializers.CharField(
        required=False,
        help_text='Grant type (use "client_credentials" for service accounts)'
    )
    client_id = serializers.CharField(required=False, help_text='Client ID (for service accounts)')
    client_secret = serializers.CharField(required=False, help_text='Client secret (for service accounts)')


class TokenObtainResponseSerializer(serializers.Serializer):
    """Serializer for token response."""
    access = serializers.CharField(help_text='JWT access token')
    refresh = serializers.CharField(required=False, help_text='JWT refresh token (only for username/password)')
    token_type = serializers.CharField(required=False, help_text='Token type (only for service accounts)')
    expires_in = serializers.IntegerField(
        required=False,
        help_text='Token expiration in seconds (only for service accounts)'
    )


@extend_schema_view(
    post=extend_schema(
        tags=['auth'],
        summary='Obtain JWT access token',
        request=TokenObtainRequestSerializer,
        responses={200: TokenObtainResponseSerializer},
        description=(
            'Obtain a JWT access token for API authentication. '
            'Supports two authentication methods:\n\n'
            '1. **Human Users**: Use username and password to get access and refresh tokens.\n'
            '2. **Service Accounts**: Use OAuth 2.0 client credentials grant to get an access token.'
        ),
        examples=[
            OpenApiExample(
                'Human User Authentication',
                value={
                    'username': 'admin',
                    'password': 'your_password',
                },
                request_only=True,
                description='Authenticate using username and password (for human users)',
            ),
            OpenApiExample(
                'Service Account Authentication',
                value={
                    'grant_type': 'client_credentials',
                    'client_id': 'sa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                    'client_secret': 'your_64_character_secret_key_here_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                },
                request_only=True,
                description='Authenticate using OAuth 2.0 client credentials (for service accounts)',
            ),
            OpenApiExample(
                'Human User Token Response',
                value={
                    'access': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                },
                response_only=True,
                status_codes=['200'],
                description='Response for username/password authentication',
            ),
            OpenApiExample(
                'Service Account Token Response',
                value={
                    'access': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                    'token_type': 'Bearer',
                    'expires_in': 3600,
                },
                response_only=True,
                status_codes=['200'],
                description='Response for OAuth 2.0 client credentials authentication',
            ),
        ],
    )
)
class ServiceAccountTokenObtainPairView(TokenObtainPairView):
    """Token endpoint that supports both human users and service accounts.

    Supports two authentication methods:

    1. Human users (username/password):
        POST /api/token/
        {
            "username": "user",
            "password": "pass"
        }

    Returns:
        {
            "access": "...",
            "refresh": "..."
        }

    2. Service accounts (OAuth 2.0 client credentials):
        POST /api/token/
        {
            "grant_type": "client_credentials",
            "client_id": "sa_...",
            "client_secret": "..."
        }

    Returns:
        {
            "access": "...",
            "token_type": "Bearer",
            "expires_in": 3600
        }
    """

    def post(self, request: Request, *args: tuple, **kwargs: dict) -> Response:
        """Handle token request for both human users and service accounts."""
        grant_type = request.data.get('grant_type')
        client_id = request.data.get('client_id')
        client_secret = request.data.get('client_secret')

        if grant_type == 'client_credentials' and client_id and client_secret:
            return self._handle_service_account(request, client_id, client_secret)

        return super().post(request, *args, **kwargs)

    def _handle_service_account(
        self, request: Request, client_id: str, client_secret: str
    ) -> Response:
        """Handle OAuth 2.0 client credentials grant for service accounts."""
        user = authenticate(request=request, client_id=client_id, secret=client_secret)

        if user is None:
            return Response(
                {
                    'error': 'invalid_client',
                    'error_description': 'Invalid client credentials',
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if user.account_type != TrustpointUser.AccountType.SERVICE:
            return Response(
                {
                    'error': 'invalid_client',
                    'error_description': 'These credentials are for service accounts only',
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            return Response(
                {
                    'error': 'invalid_client',
                    'error_description': 'Service account is inactive',
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        expires_in = int(timedelta(hours=1).total_seconds())

        return Response(
            {
                'access': access_token,
                'token_type': 'Bearer',
                'expires_in': expires_in,
            },
            status=status.HTTP_200_OK,
        )
