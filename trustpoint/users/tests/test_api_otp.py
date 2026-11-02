# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Human API token issuance must honor the global OTP policy."""

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group, Permission
from django.utils import timezone
from django_otp.oath import TOTP
from rest_framework.test import APIClient

from management.models import AccountSecurityConfig, PasswordPolicy
from users.models import TrustpointUser, UserOTPDevice

pytestmark = pytest.mark.django_db


@pytest.fixture
def otp_device(settings, monkeypatch):
    """Use a confirmed RFC 6238 authenticator and require OTP for this API user."""
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.TRUSTPOINT_IS_BOOTSTRAP = False
    PasswordPolicy.objects.update_or_create(pk=1, defaults={'require_otp': True})
    role = Group.objects.create(name='OTP API access')
    role.permissions.add(Permission.objects.get(codename='use_rest_api'))
    user = TrustpointUser.objects.create_user(username='otp-api-user', password='TestPassword123!', role=role)
    monkeypatch.setattr('users.models.time.time', lambda: 1111111109)
    return UserOTPDevice.objects.create(
        user=user,
        key=b'12345678901234567890'.hex(),
        confirmed=True,
        last_t=0,
    )


@pytest.fixture
def otp_code(otp_device):
    """Keep the leading zero in this fixed six-digit OTP."""
    totp = TOTP(bytes.fromhex(otp_device.key))
    totp.time = 1111111109
    return f'{totp.token():06d}'


def login(**extra):
    return APIClient().post(
        '/api/token/',
        {
            'username': 'otp-api-user',
            'password': 'TestPassword123!',
            **extra,
        },
        format='json',
    )


@pytest.mark.parametrize('extra', [{}, {'otp': ''}, {'otp': 'invalid-code'}])
def test_missing_or_invalid_otp_never_creates_tokens(otp_device, extra):
    with patch('users.oauth2_views.RefreshToken.for_user') as issue_token:
        response = login(**extra)
    assert response.status_code == 401
    assert 'access' not in response.data
    assert 'refresh' not in response.data
    issue_token.assert_not_called()


def test_valid_otp_preserves_leading_zero_and_allows_refresh(otp_device, otp_code):
    assert otp_code.startswith('0')
    response = login(otp=otp_code)
    assert response.status_code == 200
    assert 'access' in response.data
    assert 'refresh' in response.data
    otp_device.refresh_from_db()
    assert otp_device.last_t > 0
    refreshed = APIClient().post('/api/token/refresh/', {'refresh': response.data['refresh']}, format='json')
    assert refreshed.status_code == 200
    assert 'access' in refreshed.data


def test_used_otp_is_rejected(otp_device, otp_code):
    assert login(otp=otp_code).status_code == 200
    assert login(otp=otp_code).status_code == 401


def test_otp_failure_commits_throttling_before_returning_error(otp_device, otp_code):
    assert login(otp='999999').status_code == 401
    otp_device.refresh_from_db()
    assert otp_device.throttling_failure_count == 1
    assert login(otp=otp_code).status_code == 401
    otp_device.refresh_from_db()
    assert otp_device.last_t == 0
    assert otp_device.throttling_failure_count == 1
    otp_device.throttling_failure_timestamp = timezone.now() - timedelta(seconds=2)
    otp_device.save(update_fields=['throttling_failure_timestamp'])
    assert login(otp=otp_code).status_code == 200
    otp_device.refresh_from_db()
    assert otp_device.throttling_failure_count == 0


@pytest.mark.parametrize('unconfirmed', [False, True])
def test_confirmed_authenticator_required(otp_device, otp_code, unconfirmed):
    if unconfirmed:
        otp_device.confirmed = False
        otp_device.save(update_fields=['confirmed'])
    else:
        otp_device.delete()
    response = login(otp=otp_code)
    assert response.status_code == 401
    assert 'web interface' in str(response.data['detail'])
    assert not UserOTPDevice.objects.filter(user__username='otp-api-user', confirmed=True).exists()


def test_recovery_code_is_accepted_once(otp_device):
    code = otp_device.generate_recovery_codes()[0]
    assert login(otp=code).status_code == 200
    assert otp_device.recovery_codes.filter(used_at__isnull=False).count() == 1
    assert login(otp=code).status_code == 401


def test_api_permission_denial_does_not_consume_otp(otp_device, otp_code):
    otp_device.user.role.permissions.clear()
    with patch('users.oauth2_views.RefreshToken.for_user') as issue_token:
        response = login(otp=otp_code)
    assert response.status_code == 403
    issue_token.assert_not_called()
    otp_device.refresh_from_db()
    assert otp_device.last_t == 0


def test_wrong_password_counts_once_without_consuming_otp(otp_device, otp_code):
    AccountSecurityConfig.objects.update_or_create(pk=1, defaults={'failed_login_attempts': 5})
    response = login(password='wrong-password', otp=otp_code)
    assert response.status_code == 401
    otp_device.user.refresh_from_db()
    assert otp_device.user.failed_login_attempts == 1
    otp_device.refresh_from_db()
    assert otp_device.last_t == 0


def test_disabled_otp_policy_allows_password_only(otp_device):
    PasswordPolicy.objects.filter(pk=1).update(require_otp=False)
    assert login().status_code == 200
    otp_device.refresh_from_db()
    assert otp_device.last_t == 0


def test_token_schema_documents_optional_write_only_otp():
    from django.urls import path
    from drf_spectacular.generators import SchemaGenerator
    from users.oauth2_views import ServiceAccountTokenObtainPairView

    schema = SchemaGenerator(
        patterns=[
            path('api/token/', ServiceAccountTokenObtainPairView.as_view()),
        ]
    ).get_schema(public=True)
    request = schema['components']['schemas']['TokenObtainRequest']
    assert request['properties']['otp']['type'] == 'string'
    assert request['properties']['otp']['writeOnly'] is True
    assert 'otp' not in request.get('required', [])
    assert 'otp' not in schema['components']['schemas']['TokenObtainResponse']['properties']
