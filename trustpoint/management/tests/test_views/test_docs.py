# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Permission tests for the local documentation build trigger."""

from http import HTTPStatus
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse


@pytest.mark.django_db
def test_build_docs_requires_system_configuration_permission(client: Client) -> None:
    """A signed-in user without management permission cannot start a build."""
    user = get_user_model().objects.create_user(username='docs-viewer', password='testpass123')
    client.force_login(user)

    response = client.post(reverse('management:trigger_build_docs'))

    assert response.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.django_db
def test_build_docs_allowed_user_starts_build(client: Client, admin_user: Any, settings: Any, tmp_path: Path) -> None:
    """An authorized user can still trigger the build."""
    settings.MEDIA_ROOT = tmp_path
    client.force_login(admin_user)

    with patch('management.views.docs.call_command') as build:
        response = client.post(reverse('management:trigger_build_docs'))

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {'status': 'finished'}
    build.assert_called_once()
