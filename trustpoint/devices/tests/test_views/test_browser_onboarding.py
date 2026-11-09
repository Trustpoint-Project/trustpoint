# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Permission checks for browser credential download grants."""

from typing import Any

import pytest
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from django.contrib.auth.models import Group, Permission
from django.test import Client
from django.urls import reverse
from trustpoint_core.serializer import CredentialFileFormat

from devices.models import RemoteDeviceCredentialDownloadModel
from users.models import TrustpointUser
from users.permissions import AppPermissions


@pytest.fixture
def download_client(client: Client) -> Client:
    """Sign in a non-superuser with credential download permission."""
    role = Group.objects.create(name='Credential downloader')
    role.permissions.add(Permission.objects.get(codename='download_credentials'))
    user = TrustpointUser.objects.create_user(username='downloader', password='TestPassword123!', role=role)
    client.force_login(user)
    return client


@pytest.mark.parametrize('view_name', ['devices_browser_otp_view', 'devices_browser_cancel'])
@pytest.mark.parametrize('existing_grant', [False, True])
def test_browser_grants_deny_users_without_download_permission(
    client: Client,
    remote_device_credential_download_instance: dict[str, Any],
    view_name: str,
    existing_grant: bool,
) -> None:
    """Unauthorized requests cannot create, replace, or cancel a download grant."""
    grant = remote_device_credential_download_instance['remote_credential']
    credential_id = grant.issued_credential_model_id
    if existing_grant:
        assert grant.check_otp(grant.otp)
    else:
        grant.delete()
    grants = RemoteDeviceCredentialDownloadModel.objects.filter(issued_credential_model_id=credential_id)
    before = list(grants.values())
    role = Group.objects.create(name='No credential access')
    user = TrustpointUser.objects.create_user(username='ordinary', password='TestPassword123!', role=role)
    assert not user.has_perm(AppPermissions.DOWNLOAD_CREDENTIALS)
    client.force_login(user)

    response = client.get(reverse(f'devices:{view_name}', args=[credential_id]))

    assert response.status_code == 403
    assert list(grants.values()) == before


def test_authorized_browser_grant_allows_remote_private_key_download(
    download_client: Client,
    tls_client_credential_instance: dict[str, Any],
) -> None:
    """An authorized user can delegate a credential download to a browser without a user session."""
    credential = tls_client_credential_instance['issued_credential']
    response = download_client.get(reverse('devices:devices_browser_otp_view', args=[credential.pk]))
    assert response.status_code == 200
    grant = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=credential)
    assert response.context['otp'] == grant.get_otp_display()

    remote_client = Client()
    response = remote_client.post(reverse('devices:browser_login'), {'otp': grant.get_otp_display()})
    assert response.status_code == 302
    response = remote_client.post(
        response.url,
        {
            'password': 'ExportPassword123!',
            'file_format': CredentialFileFormat.PKCS12.value,
        },
    )

    assert response.status_code == 200
    key, certificate, _chain = load_key_and_certificates(
        b''.join(response.streaming_content),
        b'ExportPassword123!',
    )
    assert key is not None
    assert certificate == credential.credential.certificate.get_certificate_serializer().as_crypto()


def test_authorized_browser_grant_cancellation_invalidates_download(
    download_client: Client,
    remote_device_credential_download_instance: dict[str, Any],
) -> None:
    """An authorized user can cancel a grant, including a previously issued download token."""
    grant = remote_device_credential_download_instance['remote_credential']
    assert grant.check_otp(grant.otp)
    credential_id = grant.issued_credential_model_id
    download_url = reverse('devices:browser_domain_credential_download', args=[credential_id])
    download_url = f'{download_url}?token={grant.download_token}'

    cancel_url = reverse('devices:devices_browser_cancel', args=[credential_id])
    assert download_client.get(cancel_url).status_code == 405
    assert RemoteDeviceCredentialDownloadModel.objects.filter(pk=grant.pk).exists()
    protected_client = Client(enforce_csrf_checks=True)
    user_id = download_client.session['_auth_user_id']
    protected_client.force_login(TrustpointUser.objects.get(pk=user_id))
    assert protected_client.post(cancel_url).status_code == 403
    assert RemoteDeviceCredentialDownloadModel.objects.filter(pk=grant.pk).exists()

    response = download_client.post(reverse('devices:devices_browser_cancel', args=[credential_id]))

    assert response.status_code == 302
    assert response.url == reverse('devices:devices_credential-download', args=[credential_id])
    assert not RemoteDeviceCredentialDownloadModel.objects.filter(pk=grant.pk).exists()
    response = Client().get(download_url)
    assert response.status_code == 302
    assert response.url == reverse('devices:browser_login')
