# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for creating a self-signed management CA from the add wizard."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from cryptography import x509
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import Client
from django.urls import reverse

from management.models import SecurityConfig
from pki.forms.issuing_cas import SelfSignedCaForm
from pki.models import CaModel
from pki.services.management_ca import create_self_signed_ca, create_self_signed_management_ca

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _profiles() -> None:
    call_command('create_default_cert_profiles')
    SecurityConfig.objects.create(auto_gen_pki=True, allow_self_signed_ca_creation=True)


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

    assert ca.ca_type == CaModel.CaTypeChoice.SELF_SIGNED
    assert ca.get_ca_type_display() == 'Self-Signed'
    ca.full_clean()
    assert ca.unique_name == 'SelfSignedCA_Self-Signed Management CA'
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
    ca = CaModel.objects.get(unique_name='SelfSignedCA_Self-Signed UI CA')
    assert ca.ca_role == CaModel.CaRole.MANAGEMENT
    assert response.url == reverse('pki:issuing_cas-config', kwargs={'pk': ca.pk})


def test_management_ca_requires_security_config_opt_in() -> None:
    """Management CA callers cannot bypass the self-signed creation policy."""
    SecurityConfig.objects.update(auto_gen_pki=False)
    with pytest.raises(ValidationError, match='disabled'):
        create_self_signed_management_ca(unique_name='Blocked Management CA', key_type='RSA-2048')
    assert not CaModel.objects.exists()


@pytest.mark.parametrize('allowed', [False, True])
def test_management_ca_creation_obeys_policy(manage_cas_client: Client, *, allowed: bool) -> None:
    """The policy controls the link and is enforced on direct POSTs."""
    SecurityConfig.objects.update(allow_self_signed_ca_creation=allowed)
    session = manage_cas_client.session
    session['ca_add_role'] = CaModel.CaRole.MANAGEMENT
    session.save()
    url = reverse('pki:issuing_cas-add-self_signed_management_ca')

    response = manage_cas_client.get(reverse('pki:issuing_cas-add-method_select'))
    assert response.context['can_generate_auto_gen_pki'] is allowed
    assert (url in response.content.decode()) is allowed

    response = manage_cas_client.post(url, {'unique_name': 'Policy Management CA', 'key_type': 'RSA-2048'})
    assert response.status_code == (302 if allowed else 200)
    assert CaModel.objects.filter(unique_name='SelfSignedCA_Policy Management CA').exists() is allowed


def test_management_ca_service_rejects_disabled_creation_policy() -> None:
    """The shared service enforces the policy for non-UI callers too."""
    SecurityConfig.objects.update(allow_self_signed_ca_creation=False)
    with pytest.raises(ValidationError, match='Self-signed management CA creation is disabled'):
        create_self_signed_management_ca(unique_name='Blocked Management CA', key_type='RSA-2048')
    assert not CaModel.objects.exists()


@pytest.mark.parametrize('route', ['issuing_cas-add-self_signed_management_ca', 'issuing_cas-add-autogen'])
def test_creation_form_shows_prefix(manage_cas_client: Client, route: str) -> None:
    """Both creation pages show the mandatory name prefix."""
    response = manage_cas_client.get(reverse(f'pki:{route}'))
    assert b'value="SelfSignedCA_"' in response.content
    assert b'The SelfSignedCA_ prefix is required' in response.content


@pytest.mark.parametrize('name', ['Example', 'SelfSignedCA_Example'])
def test_form_normalizes_name_once(name: str) -> None:
    """Already-prefixed names are not prefixed a second time."""
    form = SelfSignedCaForm({'unique_name': name, 'key_type': 'RSA-2048'})
    assert form.is_valid(), form.errors
    assert form.cleaned_data['unique_name'] == 'SelfSignedCA_Example'


@pytest.mark.parametrize('name', ['SelfSignedCA_', 'x' * 100])
def test_form_rejects_invalid_prefixed_name(name: str) -> None:
    """Names need a suffix and must fit after the prefix is added."""
    form = SelfSignedCaForm({'unique_name': name, 'key_type': 'RSA-2048'})
    assert not form.is_valid()
    assert 'unique_name' in form.errors


@pytest.mark.parametrize('name', ['a' * 51, 'é' * 25 + 'a'])
def test_form_accepts_common_name_byte_limit(name: str) -> None:
    """The longest valid ASCII and multibyte names fit the certificate subject."""
    form = SelfSignedCaForm({'unique_name': name, 'key_type': 'RSA-2048'})
    assert form.is_valid(), form.errors
    full_name = form.cleaned_data['unique_name']
    assert len(full_name.encode('utf-8')) == 64  # noqa: PLR2004
    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, full_name)


@pytest.mark.parametrize('name', ['a' * 52, 'é' * 26])
@pytest.mark.parametrize('ca_role', [CaModel.CaRole.MANAGEMENT, CaModel.CaRole.ISSUING])
def test_rejects_long_common_names_before_key_generation(name: str, ca_role: int) -> None:
    """Both forms and service callers reject oversized subjects without generating a key."""
    form = SelfSignedCaForm({'unique_name': name, 'key_type': 'RSA-2048'})
    assert not form.is_valid()
    assert '64 UTF-8 bytes' in str(form.errors['unique_name'])
    with (
        patch('pki.services.management_ca.generate_managed_signing_private_key') as generate,
        pytest.raises(ValidationError, match='64 UTF-8 bytes'),
    ):
        create_self_signed_ca(unique_name=name, key_type='RSA-2048', ca_role=ca_role)
    generate.assert_not_called()
