# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Certificate lifecycle Behave steps."""

from __future__ import annotations

import json
from http import HTTPStatus

from behave import given, runner, then, when
from django.contrib.auth.models import Permission
from django.test import Client

from devices.tests.conftest import create_mock_models
from features.support.assertions import response_json
from features.support.auth import create_service_account
from management.models.security import SecurityConfig
from pki.models.certificate import CertificateModel, RevokedCertificateModel


@given('an active issued credential exists')
def step_active_credential(context: runner.Context) -> None:
    """Create an issued credential and a REST client authorized to revoke it."""
    security_config, _ = SecurityConfig.objects.get_or_create(pk=1)
    security_config.security_mode = SecurityConfig.SecurityModeChoices.LAB
    security_config.apply_security_settings()

    models = create_mock_models()
    context.issued_credential = models['issued_credential']
    context.certificate = context.issued_credential.credential.certificate
    assert context.certificate.certificate_status == CertificateModel.CertificateStatus.OK

    account, credential, secret = create_service_account(username=f'behave_revoke_{context.issued_credential.pk}')
    account.role.permissions.add(Permission.objects.get(codename='revoke_certificates'))
    token_response = Client().post(
        '/api/token/',
        {
            'grant_type': 'client_credentials',
            'client_id': credential.client_id,
            'client_secret': secret,
        },
    )
    assert token_response.status_code == HTTPStatus.OK, token_response.content.decode('utf-8', errors='replace')
    access_token = response_json(token_response)['access']
    context.api_client = Client(HTTP_AUTHORIZATION=f'Bearer {access_token}')


@when('the admin revokes the issued credential for key compromise')
def step_revoke_credential(context: runner.Context) -> None:
    """Submit certificate revocation through the authenticated REST PKI endpoint."""
    context.response = context.api_client.post(
        '/api/rest-pki/revoke/',
        data=json.dumps(
            {
                'issued_credential_id': context.issued_credential.pk,
                'revocation_reason': RevokedCertificateModel.ReasonCode.KEY_COMPROMISE,
            }
        ),
        content_type='application/json',
    )


@then('the certificate is marked as revoked')
def step_certificate_revoked(context: runner.Context) -> None:
    """Assert revocation persisted on the certificate and revocation record."""
    context.certificate.refresh_from_db()
    assert context.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED
    assert RevokedCertificateModel.objects.filter(certificate=context.certificate).exists()


@when('the admin revokes the same issued credential again')
def step_revoke_again(context: runner.Context) -> None:
    """Repeat the previous revocation request for the same credential."""
    step_revoke_credential(context)


@then('the lifecycle operation is rejected with status {status_code:d}')
def step_lifecycle_rejected(context: runner.Context, status_code: int) -> None:
    """Assert the repeated lifecycle operation is rejected with the expected status."""
    assert context.response.status_code == status_code
