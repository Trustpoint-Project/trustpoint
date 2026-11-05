# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Restrict AOKI demo setup and credential downloads to superusers."""

from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group
from django.test import Client
from django.urls import reverse

from users.models import GroupProfile, TrustpointUser


@pytest.fixture(params=[False, True])
def demo_user(request: pytest.FixtureRequest) -> TrustpointUser:
    """Provide staff users with and without superuser access."""
    role = Group.objects.create(name='Demo administrator')
    GroupProfile.objects.create(group=role, grants_staff=True, grants_superuser=request.param)
    return TrustpointUser.objects.create_user(username='demo-user', role=role)


def test_demo_setup_requires_superuser(client: Client, demo_user: TrustpointUser) -> None:
    """Denied requests must not run the command that creates trusted demo identities."""
    client.force_login(demo_user)
    with patch('help_pages.devices_help_views.call_command') as command:
        response = client.post(reverse('devices:zero_touch_credentials-aoki_setup_demo_env'))

    assert response.status_code == 302
    if demo_user.is_superuser:
        command.assert_called_once_with('aoki_setup_idevid_test_env')
        assert response.url == reverse('devices:zero_touch_credentials-aoki_cmp_help')
    else:
        command.assert_not_called()
        assert response.url == reverse('management:index')


@pytest.mark.parametrize(
    'filename',
    [
        'idevid.pem',
        'idevid_pk.pem',
        'owner_id_pk.pem',
        'domain_ca_owner_id_pk.pem',
    ],
)
def test_demo_download_requires_superuser(
    client: Client,
    demo_user: TrustpointUser,
    tmp_path: Path,
    filename: str,
) -> None:
    """Only superusers may download demo certificates and private keys."""
    (tmp_path / filename).write_bytes(b'demo credential')
    client.force_login(demo_user)
    url = reverse('devices:zero_touch_credentials-aoki_demo_download', kwargs={'filename': filename})
    with patch('help_pages.devices_help_views._AOKI_DEMO_CERTS_DIR', tmp_path):
        response = client.get(url)

    if demo_user.is_superuser:
        assert response.status_code == 200
        assert b''.join(response.streaming_content) == b'demo credential'
    else:
        assert response.status_code == 302
        assert response.url == reverse('management:index')
