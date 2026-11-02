# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Permission checks for agent setup profiles containing enrollment passwords."""

from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group, Permission
from django.http import HttpResponse
from django.test import Client
from django.urls import reverse

from help_pages.devices_help_views import AgentSetupProfileDownloadView
from users.models import TrustpointUser


@pytest.mark.parametrize('permission, expected_status', [
    (None, 403),
    ('view_help_pages', 403),
    ('download_credentials', 200),
])
def test_agent_profile_requires_download_permission(
    client: Client, permission: str | None, expected_status: int,
) -> None:
    """Only credential downloaders may reach the handler that exposes the password."""
    role = Group.objects.create(name='Agent profile access')
    if permission:
        role.permissions.add(Permission.objects.get(codename=permission))
    user = TrustpointUser.objects.create_user(username='agent-downloader', role=role)
    client.force_login(user)
    url = reverse('devices:devices_agent_setup_profile_download', kwargs={'pk': 1})

    with patch.object(AgentSetupProfileDownloadView, 'get', return_value=HttpResponse('profile')) as get_profile:
        response = client.get(url)

    assert response.status_code == expected_status
    if expected_status == 200:
        get_profile.assert_called_once()
    else:
        get_profile.assert_not_called()
