# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Remote certificate import through the GDS Push truststore association page."""

import base64
from http import HTTPStatus
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from django.contrib.auth.models import Permission
from django.contrib.messages import get_messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.urls import reverse

from devices.models import DeviceModel
from pki.models.truststore import TruststoreModel
from users.models import TrustpointUser


@pytest.fixture
def association(device_instance_onboarding: dict[str, Any]) -> tuple[DeviceModel, bytes, str]:
    """Provide a GDS device, DER certificate, and association URL."""
    device = device_instance_onboarding['device']
    device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
    device.save()
    certificate = device_instance_onboarding['cert'].public_bytes(Encoding.DER)
    url = reverse('devices:devices_truststore_association', kwargs={'pk': device.pk})
    return device, certificate, url


def test_retrieve_creates_selects_and_associates_truststore(
    admin_client: Client, association: tuple[DeviceModel, bytes, str]
) -> None:
    """Retrieve a fresh certificate and use the existing association step."""
    device, certificate, url = association
    server_info = {'server_certificate': base64.b64encode(certificate).decode('ascii')}
    discover = AsyncMock(return_value=(True, 'Discovered', server_info))
    with patch('devices.views.credential_issuance.GdsPushService') as service:
        service.return_value.discover_server = discover
        response = admin_client.post(url, {'action': 'retrieve_server_certificate'})
        service.assert_called_once_with(device=device, insecure=True)
        discover.assert_awaited_once()

    truststore = TruststoreModel.objects.get(intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH)
    assert response.url == f'{url}?truststore_id={truststore.pk}'
    entry = truststore.truststoreordermodel_set.get(order=0)
    assert entry.certificate.get_certificate_serializer().as_der() == certificate
    device.opc_ua_gds_push_config.refresh_from_db()
    assert device.opc_ua_gds_push_config.opc_trust_store_id is None

    page = admin_client.get(response.url)
    assert page.context['form'].initial['opc_trust_store'] == truststore
    assert b'Retrieve Server Certificate' in page.content
    assert b'Import new Truststore' in page.content
    assert b'discovery does not authenticate the server' in page.content
    response = admin_client.post(url, {'opc_trust_store': truststore.pk})
    assert response.status_code == HTTPStatus.FOUND
    device.opc_ua_gds_push_config.refresh_from_db()
    assert device.opc_ua_gds_push_config.opc_trust_store == truststore


@pytest.mark.parametrize(
    ('result', 'error'),
    [
        ((False, 'Connection refused', None), 'Connection refused'),
        ((True, 'Discovered', {}), 'did not provide a server certificate'),
        ((True, 'Discovered', {'server_certificate': 'invalid base64!'}), 'Failed to retrieve'),
        ((True, 'Discovered', {'server_certificate': 'bm90IGEgY2VydA=='}), 'Failed to retrieve'),
        (TimeoutError(), 'timed out'),
    ],
)
def test_retrieval_failure_preserves_association(
    admin_client: Client,
    association: tuple[DeviceModel, bytes, str],
    result: tuple[bool, str, dict[str, Any] | None] | Exception,
    error: str,
) -> None:
    """Failed discovery or invalid certificates leave existing trust unchanged."""
    device, _, url = association
    existing = TruststoreModel.objects.create(
        unique_name='existing-server', intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH
    )
    config = device.opc_ua_gds_push_config
    config.opc_trust_store = existing
    config.save()
    count = TruststoreModel.objects.count()
    discover = AsyncMock(side_effect=result) if isinstance(result, Exception) else AsyncMock(return_value=result)
    with patch('devices.views.credential_issuance.GdsPushService') as service:
        service.return_value.discover_server = discover
        response = admin_client.post(url, {'action': 'retrieve_server_certificate'})
    assert response.url == url
    assert any(error in str(message) for message in get_messages(response.wsgi_request))
    assert TruststoreModel.objects.count() == count
    config.refresh_from_db()
    assert config.opc_trust_store == existing


@pytest.mark.parametrize('permissions', [[], ['manage_devices'], ['manage_truststores']])
def test_retrieval_requires_device_and_truststore_permissions(
    client: Client,
    django_user_model: type[TrustpointUser],
    association: tuple[DeviceModel, bytes, str],
    permissions: list[str],
) -> None:
    """Deny retrieval before any network or database writes without both permissions."""
    _, _, url = association
    user = django_user_model.objects.create_user(username='truststore-reader')
    user.role.permissions.set(Permission.objects.filter(codename__in=permissions))
    client.force_login(user)
    count = TruststoreModel.objects.count()
    with patch('devices.views.credential_issuance.GdsPushService') as service:
        assert client.post(url, {'action': 'retrieve_server_certificate'}).status_code == HTTPStatus.FORBIDDEN
        service.assert_not_called()
    assert TruststoreModel.objects.count() == count


def test_manual_upload_still_selects_truststore(
    admin_client: Client, association: tuple[DeviceModel, bytes, str]
) -> None:
    """Preserve manual certificate upload alongside retrieval."""
    _, certificate, url = association
    response = admin_client.post(
        url,
        {
            'unique_name': 'uploaded-server',
            'intended_usage': TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH,
            'trust_store_file': SimpleUploadedFile('server.der', certificate),
        },
    )
    truststore = TruststoreModel.objects.get(unique_name='uploaded-server')
    assert response.url == f'{url}?truststore_id={truststore.pk}'
