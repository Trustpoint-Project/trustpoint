# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the REST PKI certificate revocation view."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import Mock, PropertyMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.urls import resolve
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from management.models.audit_log import AuditLog
from pki.models import IssuedCredentialModel
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from rest_pki.api_views import CertificateRevokeView
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser

HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_UNPROCESSABLE = 422
HTTP_UNAUTHORIZED = 401
HTTP_INTERNAL_SERVER_ERROR = 500


def _make_user(*, has_perm: bool = True, authenticated: bool = True) -> Mock:
    """Build a mock authenticated user with a controllable ``has_perm``."""
    user = Mock()
    user.is_authenticated = authenticated
    user.has_perm.return_value = has_perm
    return user


def _make_issued_credential(cert_status: str = CertificateModel.CertificateStatus.OK) -> Mock:
    """Build a mock issued credential exposing the fields the view reads."""
    issued_credential = Mock()
    issued_credential.credential.certificate_or_error.certificate_status = cert_status
    issued_credential.device.common_name = 'test-device'
    issued_credential.domain.unique_name = 'test-domain'
    issued_credential.common_name = 'test-credential'
    return issued_credential


def _post(user: Mock, data: dict[str, object]) -> object:
    """Issue an authenticated POST to the revoke endpoint."""
    request = APIRequestFactory().post('/api/rest-pki/revoke/', data=data, format='json')
    force_authenticate(request, user=user)
    return CertificateRevokeView.as_view()(request)


def test_revoke_happy_path() -> None:
    """A valid request revokes the certificate, writes the audit log, and returns 200."""
    user = _make_user()
    issued_credential = _make_issued_credential()

    with (
        patch('rest_pki.api_views._resolve_issued_credential', return_value=issued_credential),
        patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation,
        patch('rest_pki.api_views.AuditLog') as mock_audit,
    ):
        mock_revocation.revoke_certificate.return_value = (True, 'Certificate successfully revoked.')

        response = _post(
            user,
            {
                'issued_credential_id': 42,
                'revocation_reason': RevokedCertificateModel.ReasonCode.KEY_COMPROMISE,
            },
        )

    assert response.status_code == HTTP_OK
    assert response.data['issued_credential_id'] == 42
    mock_revocation.revoke_certificate.assert_called_once_with(42, RevokedCertificateModel.ReasonCode.KEY_COMPROMISE)
    mock_audit.create_entry.assert_called_once()
    assert mock_audit.create_entry.call_args.kwargs['actor'] is user


def test_revoke_unknown_credential_returns_404() -> None:
    """An unknown issued credential yields a 404 before any revocation attempt."""
    from rest_framework import status
    from rest_framework.response import Response

    user = _make_user()
    not_found = Response({'detail': 'not found'}, status=status.HTTP_404_NOT_FOUND)

    with (
        patch('rest_pki.api_views._resolve_issued_credential', return_value=not_found),
        patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation,
    ):
        response = _post(user, {'issued_credential_id': 999})

    assert response.status_code == HTTP_NOT_FOUND
    mock_revocation.revoke_certificate.assert_not_called()


def test_revoke_already_revoked_returns_422() -> None:
    """An already-revoked certificate is refused with 422 before calling the revocation logic."""
    user = _make_user()
    issued_credential = _make_issued_credential(cert_status=CertificateModel.CertificateStatus.REVOKED)

    with (
        patch('rest_pki.api_views._resolve_issued_credential', return_value=issued_credential),
        patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation,
    ):
        response = _post(user, {'issued_credential_id': 42})

    assert response.status_code == HTTP_UNPROCESSABLE
    mock_revocation.revoke_certificate.assert_not_called()


def test_revoke_expired_returns_422() -> None:
    """An expired certificate is refused with 422 before calling the revocation logic."""
    user = _make_user()
    issued_credential = _make_issued_credential(cert_status=CertificateModel.CertificateStatus.EXPIRED)

    with (
        patch('rest_pki.api_views._resolve_issued_credential', return_value=issued_credential),
        patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation,
    ):
        response = _post(user, {'issued_credential_id': 42})

    assert response.status_code == HTTP_UNPROCESSABLE
    mock_revocation.revoke_certificate.assert_not_called()


def test_revoke_default_reason_is_unspecified() -> None:
    """Omitting revocation_reason applies the UNSPECIFIED default when calling the revocation logic."""
    user = _make_user()
    issued_credential = _make_issued_credential()

    with (
        patch('rest_pki.api_views._resolve_issued_credential', return_value=issued_credential),
        patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation,
        patch('rest_pki.api_views.AuditLog'),
    ):
        mock_revocation.revoke_certificate.return_value = (True, 'Certificate successfully revoked.')

        response = _post(user, {'issued_credential_id': 42})

    assert response.status_code == HTTP_OK
    mock_revocation.revoke_certificate.assert_called_once_with(42, RevokedCertificateModel.ReasonCode.UNSPECIFIED)


def test_revoke_invalid_reason_returns_400() -> None:
    """An invalid revocation reason fails serializer validation with 400."""
    user = _make_user()

    response = _post(
        user,
        {'issued_credential_id': 42, 'revocation_reason': 'not-a-real-reason'},
    )

    assert response.status_code == HTTP_BAD_REQUEST


def test_revoke_without_permission_returns_403() -> None:
    """An authenticated user lacking REVOKE_CERTIFICATES is forbidden."""
    user = _make_user(has_perm=False)

    with patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation:
        response = _post(user, {'issued_credential_id': 42})

    assert response.status_code == HTTP_FORBIDDEN
    mock_revocation.revoke_certificate.assert_not_called()


def test_revoke_unexpected_failure_returns_500() -> None:
    """An unexpected revocation failure message maps to a 500 response."""
    user = _make_user()
    issued_credential = _make_issued_credential()

    with (
        patch('rest_pki.api_views._resolve_issued_credential', return_value=issued_credential),
        patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation,
        patch('rest_pki.api_views.AuditLog') as mock_audit,
    ):
        mock_revocation.revoke_certificate.return_value = (False, 'Unexpected database error.')

        response = _post(user, {'issued_credential_id': 42})

    assert response.status_code == HTTP_INTERNAL_SERVER_ERROR
    mock_audit.create_entry.assert_not_called()


def test_revoke_unauthenticated_is_rejected() -> None:
    """An unauthenticated request is rejected before reaching the revocation logic."""
    with patch('rest_pki.api_views.DeviceCredentialRevocation') as mock_revocation:
        request = APIRequestFactory().post('/api/rest-pki/revoke/', data={'issued_credential_id': 42}, format='json')
        response = CertificateRevokeView.as_view()(request)

    assert response.status_code in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN)
    mock_revocation.revoke_certificate.assert_not_called()


def _make_user_with_revoke_permission() -> AbstractUser:
    """Create a real user in the DB and grant it the revoke_certificates permission."""
    user_model = get_user_model()
    user = user_model.objects.create_user(username='revoker', password='revoker-pass')  # noqa: S106
    permission = Permission.objects.get(content_type__app_label='users', codename='revoke_certificates')
    user.user_permissions.add(permission)
    # Re-fetch to clear the cached permission set so has_perm sees the new grant.
    return user_model.objects.get(pk=user.pk)


@pytest.mark.django_db
def test_revoke_creates_revoked_certificate_row(tls_client_credential_instance: dict[str, Any]) -> None:
    """End-to-end revoke: a real user revokes a real credential and a RevokedCertificateModel row appears.

    This exercises the real ORM path, the real Django permission lookup and the
    real :class:`DeviceCredentialRevocation` logic (nothing is mocked), and
    asserts that a persisted :class:`RevokedCertificateModel` row is created and
    the certificate status flips to REVOKED.
    """
    issued_credential = tls_client_credential_instance['issued_credential']
    certificate = issued_credential.credential.certificate
    user = _make_user_with_revoke_permission()

    assert not RevokedCertificateModel.objects.filter(certificate=certificate).exists()

    response = _post(
        user,
        {
            'issued_credential_id': issued_credential.pk,
            'revocation_reason': RevokedCertificateModel.ReasonCode.KEY_COMPROMISE,
        },
    )

    assert response.status_code == HTTP_OK
    assert response.data['issued_credential_id'] == issued_credential.pk

    revoked = RevokedCertificateModel.objects.filter(certificate=certificate).first()
    assert revoked is not None
    assert revoked.revocation_reason == RevokedCertificateModel.ReasonCode.KEY_COMPROMISE

    certificate.refresh_from_db()
    assert certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED


URL = '/api/rest-pki/revoke/'


@pytest.fixture
def revoke_context():
    user = Mock(is_authenticated=True)
    user.has_perm.return_value = True
    issued = Mock(pk=7)
    issued.credential.certificate_or_error.certificate_status = CertificateModel.CertificateStatus.OK
    with (
        patch('rest_pki.api_views.IssuedCredentialModel.objects') as objects,
        patch('rest_pki.api_views.DeviceCredentialRevocation.revoke_certificate') as service,
        patch('rest_pki.api_views.AuditLog.create_entry') as audit,
    ):
        objects.select_related.return_value.get.return_value = issued
        service.return_value = (True, 'Certificate successfully revoked.')
        yield user, issued, objects, service, audit


def post(user, data):
    request = APIRequestFactory().post(URL, data, format='json')
    if user is not None:
        force_authenticate(request, user=user)
    return CertificateRevokeView.as_view()(request)


def test_route():
    assert resolve(URL).func.view_class is CertificateRevokeView


@pytest.mark.parametrize('reason', [None, *RevokedCertificateModel.ReasonCode.values])
def test_success_and_default_reason(revoke_context, reason):
    user, issued, _, service, audit = revoke_context
    data = {'issued_credential_id': 7}
    if reason is not None:
        data['revocation_reason'] = reason
    response = post(user, data)
    assert response.status_code == 200
    assert response.data == {'detail': 'Certificate successfully revoked.', 'issued_credential_id': 7}
    user.has_perm.assert_called_once_with(AppPermissions.REVOKE_CERTIFICATES)
    service.assert_called_once_with(7, reason or 'unspecified')
    audit.assert_called_once_with(
        operation_type=AuditLog.OperationType.CREDENTIAL_REVOKED,
        target=issued.device,
        target_display=(
            f'Device: {issued.device.common_name} | Domain: {issued.domain.unique_name}'
            f' | Credential: {issued.common_name}'
        ),
        actor=user,
    )


@pytest.mark.parametrize(
    'data',
    [
        {},
        {'issued_credential_id': 'bad'},
        {'issued_credential_id': 7, 'revocation_reason': 'invalid'},
        {'issued_credential_id': 7, 'revocation_reason': None},
    ],
)
def test_bad_request(revoke_context, data):
    user, _, objects, service, audit = revoke_context
    assert post(user, data).status_code == 400
    objects.select_related.assert_not_called()
    service.assert_not_called()
    audit.assert_not_called()


def test_permission_denied(revoke_context):
    user, _, objects, service, audit = revoke_context
    user.has_perm.return_value = False
    assert post(user, {'issued_credential_id': 7}).status_code == 403
    objects.select_related.assert_not_called()
    service.assert_not_called()
    audit.assert_not_called()


def test_unauthenticated(revoke_context):
    _, _, objects, service, _ = revoke_context
    assert post(None, {'issued_credential_id': 7}).status_code == 401
    objects.select_related.assert_not_called()
    service.assert_not_called()


def test_unknown_credential(revoke_context):
    user, _, objects, service, audit = revoke_context
    objects.select_related.return_value.get.side_effect = IssuedCredentialModel.DoesNotExist
    assert post(user, {'issued_credential_id': 7}).status_code == 404
    service.assert_not_called()
    audit.assert_not_called()


@pytest.mark.parametrize(
    'state',
    [
        CertificateModel.CertificateStatus.EXPIRED,
        CertificateModel.CertificateStatus.REVOKED,
    ],
)
def test_unprocessable_certificate(revoke_context, state):
    user, issued, _, service, audit = revoke_context
    issued.credential.certificate_or_error.certificate_status = state
    assert post(user, {'issued_credential_id': 7}).status_code == 422
    service.assert_not_called()
    audit.assert_not_called()


@pytest.mark.parametrize('raises', [False, True])
def test_service_failure(revoke_context, raises):
    user, _, _, service, audit = revoke_context
    if raises:
        service.side_effect = RuntimeError('private diagnostic')
    else:
        service.return_value = (False, 'Revocation failed.')
    response = post(user, {'issued_credential_id': 7})
    assert response.status_code == 500
    assert 'private diagnostic' not in str(response.data)
    audit.assert_not_called()


@pytest.mark.django_db
def test_revocation_integration(tls_client_credential_instance):
    issued = tls_client_credential_instance['issued_credential']
    user = get_user_model().objects.create_user(username='rest-revoker')
    user.user_permissions.add(
        Permission.objects.get(
            content_type__app_label='users',
            codename='revoke_certificates',
        )
    )
    client = APIClient()
    client.force_authenticate(user=user)
    response = client.post(
        URL,
        {
            'issued_credential_id': issued.pk,
            'revocation_reason': 'keyCompromise',
        },
        format='json',
    )
    assert response.status_code == 200
    certificate = issued.credential.certificate_or_error
    certificate.refresh_from_db()
    assert certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED
    revoked = RevokedCertificateModel.objects.get(certificate=certificate)
    assert revoked.revocation_reason == 'keyCompromise'
    assert revoked.ca == issued.domain.issuing_ca
    assert (
        AuditLog.objects.filter(
            operation_type=AuditLog.OperationType.CREDENTIAL_REVOKED,
            actor=user,
        ).count()
        == 1
    )
    assert client.post(URL, {'issued_credential_id': issued.pk}, format='json').status_code == 422
    assert RevokedCertificateModel.objects.filter(certificate=certificate).count() == 1


@pytest.mark.parametrize(
    ('message', 'expected'),
    [
        ('The certificate is already revoked.', 422),
        ('The associated certificate to revoke was not found.', 422),
        ('The credential to revoke does not exist.', 404),
    ],
)
def test_service_state_change(revoke_context, message, expected):
    user, _, _, service, audit = revoke_context
    service.return_value = (False, message)
    assert post(user, {'issued_credential_id': 7}).status_code == expected
    audit.assert_not_called()


def test_missing_certificate(revoke_context):
    user, issued, _, service, audit = revoke_context
    type(issued.credential).certificate_or_error = PropertyMock(side_effect=ValueError('missing'))
    assert post(user, {'issued_credential_id': 7}).status_code == 422
    service.assert_not_called()
    audit.assert_not_called()


def test_not_yet_valid_is_revocable(revoke_context):
    user, issued, _, service, _ = revoke_context
    issued.credential.certificate_or_error.certificate_status = CertificateModel.CertificateStatus.NOT_YET_VALID
    assert post(user, {'issued_credential_id': 7}).status_code == 200
    service.assert_called_once_with(7, 'unspecified')
