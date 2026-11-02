# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""OAuth 2.0 token endpoint for service accounts and human users."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.db import transaction
from django.views.decorators.debug import sensitive_variables
from drf_spectacular.utils import OpenApiExample, extend_schema, extend_schema_view
from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.response import Response
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from management.models import PasswordPolicy

from .models import MAX_TOKEN_LENGTH, TrustpointUser, UserOTPDevice

if TYPE_CHECKING:
    from rest_framework.request import Request


class TokenObtainRequestSerializer(serializers.Serializer[Any]):
    """Serializer for token request - supports both authentication methods."""

    username = serializers.CharField(required=False, help_text='Username (for human users)')
    password = serializers.CharField(required=False, help_text='Password (for human users)')
    otp = serializers.CharField(
        required=False,
        write_only=True,
        max_length=MAX_TOKEN_LENGTH,
        help_text='Authenticator or recovery code, required for human login when OTP is enabled.',
    )
    grant_type = serializers.CharField(
        required=False, help_text='Grant type (use "client_credentials" for service accounts)'
    )
    client_id = serializers.CharField(required=False, help_text='Client ID (for service accounts)')
    client_secret = serializers.CharField(required=False, help_text='Client secret (for service accounts)')


class TokenObtainResponseSerializer(serializers.Serializer[Any]):
    """Serializer for token response."""

    access = serializers.CharField(help_text='JWT access token')
    refresh = serializers.CharField(required=False, help_text='JWT refresh token (only for username/password)')
    token_type = serializers.CharField(required=False, help_text='Token type (only for service accounts)')
    expires_in = serializers.IntegerField(
        required=False, help_text='Token expiration in seconds (only for service accounts)'
    )


class HumanUserTokenObtainPairSerializer(TokenObtainSerializer):
    """Authenticate once and check API access and OTP before creating tokens."""

    otp = serializers.CharField(required=False, allow_blank=True, write_only=True, max_length=MAX_TOKEN_LENGTH)

    @sensitive_variables()
    def validate(self, attrs: dict[str, Any]) -> dict[str, str]:
        """Use the existing locked OTP verifier, retaining failed-attempt throttling."""
        super().validate(attrs)
        if self.user is None or not self.user.has_perm('users.use_rest_api'):
            msg = 'User is not permitted to use the REST API.'
            raise PermissionDenied(msg)

        if PasswordPolicy.is_otp_required():
            otp = attrs.get('otp', '')
            with transaction.atomic():
                device = UserOTPDevice.objects.select_for_update().filter(user=self.user, confirmed=True).first()
                verified = device is not None and bool(otp) and device.verify_token(otp)
            # Raise after committing so invalid codes cannot roll back throttling.
            if device is None:
                msg = 'Set up OTP in the web interface before requesting API tokens.'
                raise AuthenticationFailed(msg, code='otp_not_configured')
            if not verified:
                msg = 'A valid authenticator code or unused recovery code is required.'
                raise AuthenticationFailed(msg, code='otp_invalid')

        refresh = RefreshToken.for_user(self.user)
        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(TrustpointUser, self.user)
        return {'refresh': str(refresh), 'access': str(refresh.access_token)}


@extend_schema_view(
    post=extend_schema(
        tags=['auth'],
        summary='Obtain JWT access token',
        request=TokenObtainRequestSerializer,
        responses={200: TokenObtainResponseSerializer},
        description=(
            'Obtain a JWT access token for API authentication. '
            'Supports two authentication methods:\n\n'
            '1. **Human Users**: Use username and password, plus otp when required by policy, '
            'to get access and refresh tokens. Enroll an authenticator through the web UI first.\n'
            '2. **Service Accounts**: Use OAuth 2.0 client credentials grant to get an access token.'
        ),
        examples=[
            OpenApiExample(
                'Human User Authentication',
                value={
                    'username': 'admin',
                    'password': 'your_password',
                    'otp': '012345',
                },
                request_only=True,
                description='Human login; omit otp when the global OTP requirement is disabled.',
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

    serializer_class = HumanUserTokenObtainPairSerializer

    def post(self, request: Request, *args: tuple[Any, ...], **kwargs: dict[str, Any]) -> Response:
        """Handle token request for both human users and service accounts."""
        data = request.data
        if not isinstance(data, dict):
            return Response(
                {
                    'error': 'invalid_request',
                    'error_description': 'Request body must be a JSON object.',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        grant_type = data.get('grant_type')
        client_id = (data.get('client_id') or '').strip()
        client_secret = (data.get('client_secret') or '').strip()

        if grant_type == 'client_credentials':
            if not client_id or not client_secret:
                auth_header = request.META.get('HTTP_AUTHORIZATION', '')
                if auth_header.lower().startswith('basic '):
                    try:
                        decoded = base64.b64decode(auth_header[6:], validate=True).decode('utf-8')
                        client_id, client_secret = decoded.split(':', 1)
                        client_id = client_id.strip()
                        client_secret = client_secret.strip()
                    except (ValueError, UnicodeDecodeError):
                        client_id = ''
                        client_secret = ''
            if not client_id or not client_secret:
                return Response(
                    {
                        'error': 'invalid_request',
                        'error_description': 'client_id and client_secret are required for client_credentials',
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            return self._handle_service_account(request, client_id, client_secret)

        return super().post(request, *args, **kwargs)

    def _handle_service_account(self, request: Request, client_id: str, client_secret: str) -> Response:
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

        if not user.has_perm('users.use_rest_api'):
            return Response(
                {
                    'error': 'invalid_client',
                    'error_description': 'Service account is not permitted to use the REST API',
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        expires_in = int(access_token.lifetime.total_seconds())

        return Response(
            {
                'access': str(access_token),
                'token_type': 'Bearer',
                'expires_in': expires_in,
            },
            status=status.HTTP_200_OK,
        )
