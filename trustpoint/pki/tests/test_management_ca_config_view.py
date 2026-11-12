# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the certificate-authentication management CA selection page."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from management.models import CertificateAuthenticationConfig
from pki.models import CaModel
from pki.tests.managed_ca_helpers import create_managed_root_ca
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db


@pytest.fixture
def superuser_client() -> Client:
    """Return a logged-in superuser."""
    user = get_user_model().objects.create_superuser(
        username='ca-config-admin',
        password='test-password',  # noqa: S106
    )
    client = Client()
    client.force_login(user)
    return client


def _management_ca(name: str) -> CaModel:
    cert, key = create_managed_root_ca(name)
    return CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=cert,
        private_key=key,
        chain=[],
        unique_name=name,
        ca_role=CaModel.CaRole.MANAGEMENT,
    )


def test_page_has_no_lifecycle_actions_for_management_ca(superuser_client: Client) -> None:
    """Generating, replacing, and deleting CAs is no longer offered on the page."""
    response = superuser_client.get(reverse('management:certificate_authentication'))

    assert response.status_code == 200  # noqa: PLR2004
    assert b'No management CA is selected.' in response.content
    assert b'Generate management CA' not in response.content
    assert b'Replace management CA' not in response.content
    assert b'Delete management CA' not in response.content


def test_page_shows_and_saves_the_selected_management_ca(superuser_client: Client) -> None:
    """The explicit selection form stores the chosen management CA."""
    ca = _management_ca('Management Config CA')

    response = superuser_client.post(
        reverse('management:certificate_authentication'),
        {'selected_ca_id': ca.pk},
    )

    assert response.status_code == 302  # noqa: PLR2004
    assert CertificateAuthenticationConfig.objects.filter(issuing_ca=ca).exists()

    response = superuser_client.get(reverse('management:certificate_authentication'))
    assert ca.unique_name.encode() in response.content
    assert b'Save Management CA' in response.content
