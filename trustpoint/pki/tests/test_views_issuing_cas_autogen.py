# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Self-signed issuing CA creation and security policy regression tests."""

from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.test import Client
from django.urls import reverse

from management.models.audit_log import AuditLog
from management.models.security import SecurityConfig
from pki.forms.issuing_cas import SelfSignedCaForm
from pki.models import CaModel, DomainModel

# Test inputs and HTTP status codes are deliberately literal.
# ruff: noqa: S106, PLR2004

pytestmark = pytest.mark.django_db


@pytest.fixture
def manage_cas_client() -> Client:
    """Authenticate a CA manager and load certificate profiles."""
    call_command('create_default_cert_profiles')
    user = get_user_model().objects.create_user(username='autogen-admin', password='test-password')
    user.role.permissions.add(Permission.objects.get(codename='manage_cas'))
    client = Client()
    client.force_login(user)
    return client


def test_creation_disabled_by_security_config(manage_cas_client: Client) -> None:
    """Disabled settings hide the link and reject direct submissions."""
    SecurityConfig.objects.create(auto_gen_pki=False)
    response = manage_cas_client.get(reverse('pki:issuing_cas-add-method_select'))
    assert b'Self-signed Issuing CA' in response.content
    assert response.context['can_generate_auto_gen_pki'] is False
    response = manage_cas_client.post(
        reverse('pki:issuing_cas-add-autogen'), {'unique_name': 'Blocked CA', 'key_type': 'RSA-2048'}
    )
    assert response.status_code == 200
    assert b'Auto-generated PKI creation is disabled' in response.content
    assert not CaModel.objects.exists()


def test_form_uses_all_backend_choices() -> None:
    """Both roles use the same backend-supported algorithms."""
    choices = [('ECC-SECP384R1', 'ECC SECP384R1'), ('MLDSA-44', 'ML-DSA-44')]
    with patch('pki.forms.issuing_cas.supported_key_type_choices', return_value=choices):
        form = SelfSignedCaForm()
    assert list(form.fields['key_type'].choices) == choices


@pytest.mark.parametrize('key_type', ['RSA-2048', 'ECC-SECP384R1', 'MLDSA-44'])
def test_creates_multiple_named_cas_without_domains(manage_cas_client: Client, key_type: str) -> None:
    """Repeated creation produces independent self-signed CAs with audits."""
    SecurityConfig.objects.create(auto_gen_pki=True)
    for name in ['First CA', 'Second CA']:
        response = manage_cas_client.post(
            reverse('pki:issuing_cas-add-autogen'), {'unique_name': name, 'key_type': key_type}
        )
        assert response.status_code == 302
        ca = CaModel.objects.get(unique_name=f'SelfSignedCA_{name}')
        assert ca.ca_role == CaModel.CaRole.ISSUING
        assert ca.ca_type == CaModel.CaTypeChoice.SELF_SIGNED
        ca.full_clean()
        assert ca.parent_ca is None
        certificate = ca.get_certificate()
        assert certificate.subject == certificate.issuer
        certificate.verify_directly_issued_by(certificate)
        assert AuditLog.objects.filter(
            operation_type=AuditLog.OperationType.CA_CREATED, target_object_id=str(ca.pk)
        ).exists()
    assert CaModel.objects.count() == 2
    assert not DomainModel.objects.exists()


@pytest.mark.parametrize(
    'values',
    [
        {'unique_name': 'Bad CA', 'key_type': 'unsupported'},
        {'key_type': 'RSA-2048'},
    ],
)
def test_rejects_invalid_input(manage_cas_client: Client, values: dict) -> None:
    """A name and a supported algorithm are required."""
    SecurityConfig.objects.create(auto_gen_pki=True)
    response = manage_cas_client.post(reverse('pki:issuing_cas-add-autogen'), values)
    assert response.status_code == 200
    assert not CaModel.objects.exists()


def test_rejects_user_without_permission(manage_cas_client: Client) -> None:
    """The creation endpoint requires CA management permission."""
    user = get_user_model().objects.create_user(username='reader')
    user.role.permissions.remove(Permission.objects.get(codename='manage_cas'))
    manage_cas_client.force_login(user)
    response = manage_cas_client.post(reverse('pki:issuing_cas-add-autogen'), {})
    assert response.status_code == 403


def test_rejects_duplicate_name(manage_cas_client: Client) -> None:
    """A duplicate submission cannot overwrite an existing CA or key."""
    SecurityConfig.objects.create(auto_gen_pki=True)
    values = {'unique_name': 'Existing CA', 'key_type': 'RSA-2048'}
    url = reverse('pki:issuing_cas-add-autogen')
    assert manage_cas_client.post(url, values).status_code == 302
    response = manage_cas_client.post(url, values)
    assert response.status_code == 200
    assert b'A CA with this unique name already exists.' in response.content
    assert CaModel.objects.count() == 1
