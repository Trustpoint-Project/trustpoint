# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for creating a self-signed management CA from the add wizard."""

from __future__ import annotations

import pytest
from cryptography import x509
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client
from django.urls import reverse

from pki.models import CaModel
from pki.services.management_ca import create_self_signed_management_ca

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _profiles() -> None:
    call_command('create_default_cert_profiles')


@pytest.fixture
def manage_cas_client() -> Client:
    """Return an authenticated client allowed to manage CAs."""
    user = get_user_model().objects.create_user(
        username='self-signed-ca-admin',
        password='test-password',  # noqa: S106
    )
    user.role.permissions.add(Permission.objects.get(codename='manage_cas'))
    client = Client()
    client.force_login(user)
    return client


def test_service_creates_self_signed_management_ca_with_issuing_ca_profile() -> None:
    """The generated CA is self-signed, uses the management role, and takes validity/extensions from the profile."""
    ca = create_self_signed_management_ca(unique_name='Self-Signed Management CA', key_type='RSA-2048')

    certificate = ca.get_certificate()
    assert certificate is not None
    assert certificate.subject == certificate.issuer
    assert ca.ca_role == CaModel.CaRole.MANAGEMENT
    assert ca.is_root_ca()

    subject_ou = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert [attribute.value for attribute in subject_ou] == ['Self-Signed Management CA']

    basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert basic_constraints.ca
    assert basic_constraints.path_length == 0
    assert key_usage.key_cert_sign
    assert key_usage.crl_sign

    validity = certificate.not_valid_after_utc - certificate.not_valid_before_utc
    assert validity.days >= 3649  # noqa: PLR2004


def test_method_page_offers_self_signed_management_ca_and_creates_it(manage_cas_client: Client) -> None:
    """The management add flow links to the self-signed creation form and persists the CA."""
    session = manage_cas_client.session
    session['ca_add_role'] = CaModel.CaRole.MANAGEMENT
    session.save()

    response = manage_cas_client.get(reverse('pki:issuing_cas-add-method_select'))
    assert reverse('pki:issuing_cas-add-self_signed_management_ca') in response.content.decode()

    response = manage_cas_client.post(
        reverse('pki:issuing_cas-add-self_signed_management_ca'),
        {'unique_name': 'Self-Signed UI CA', 'key_type': 'RSA-2048'},
    )

    assert response.status_code == 302  # noqa: PLR2004
    ca = CaModel.objects.get(unique_name='Self-Signed UI CA')
    assert ca.ca_role == CaModel.CaRole.MANAGEMENT
    assert response.url == reverse('pki:issuing_cas-config', kwargs={'pk': ca.pk})
