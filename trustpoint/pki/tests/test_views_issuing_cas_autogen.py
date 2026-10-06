# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for AutoGenPKI generation from the Add Issuing CA page."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.messages import get_messages
from django.test import Client
from django.urls import reverse

from management.models.audit_log import AuditLog
from management.models.security import SecurityConfig
from pki.auto_gen_pki import AutoGenPki
from pki.forms.issuing_cas import IssuingCaAddAutoGenForm
from pki.models import CaModel, DomainModel


@pytest.fixture
def manage_cas_client(db: None) -> Client:
    """Return an authenticated client allowed to manage CAs."""
    user = get_user_model().objects.create_user(username='autogen-admin', password='test-password')
    permission = Permission.objects.get(codename='manage_cas')
    user.role.permissions.add(permission)
    client = Client()
    client.force_login(user)
    return client


def _security_config(*, allowed: bool) -> SecurityConfig:
    return SecurityConfig.objects.create(
        security_mode=SecurityConfig.SecurityModeChoices.LAB,
        auto_gen_pki=allowed,
        allow_auto_gen_pki=True,
    )


@pytest.mark.django_db
def test_add_issuing_ca_page_keeps_autogen_section_visible_when_disabled(manage_cas_client: Client) -> None:
    """The separate section remains visible but its action is disabled by settings."""
    _security_config(allowed=False)

    response = manage_cas_client.get(reverse('pki:issuing_cas-add-method_select'))

    assert response.status_code == 200
    assert b'Auto-generated PKI' in response.content
    assert b'Auto-generated PKI creation is disabled in the Security Settings.' in response.content
    assert response.context['auto_gen_pki_form'].fields['key_type'].widget.attrs['disabled'] == 'disabled'
    assert response.context['can_generate_auto_gen_pki'] is False


@pytest.mark.django_db
def test_add_issuing_ca_page_disables_action_when_an_autogen_pki_is_active(manage_cas_client: Client) -> None:
    """The active PKI is linked and cannot be generated again from the page."""
    _security_config(allowed=True)
    active_ca = Mock(pk=42)

    with patch.object(AutoGenPki, 'get_auto_gen_pki', return_value=active_ca):
        response = manage_cas_client.get(reverse('pki:issuing_cas-add-method_select'))

    assert response.status_code == 200
    assert b'An auto-generated PKI is already active.' in response.content
    assert b'/pki/issuing-cas/detail/42/' in response.content
    assert response.context['can_generate_auto_gen_pki'] is False


def test_autogen_form_uses_central_key_generation_choices() -> None:
    """The AutoGen form takes its backend-filtered choices from key_generation."""
    choices = [('ECC-SECP384R1', 'ECC SECP384R1')]
    with patch('pki.forms.issuing_cas.supported_key_type_choices', return_value=choices):
        form = IssuingCaAddAutoGenForm()

    assert list(form.fields['key_type'].choices) == choices


@pytest.mark.django_db
def test_autogen_endpoint_rejects_user_without_manage_cas(db: None) -> None:
    """Only users with MANAGE_CAS can submit the generation endpoint."""
    user = get_user_model().objects.create_user(username='autogen-reader', password='test-password')
    client = Client()
    client.force_login(user)
    _security_config(allowed=True)
    client.raise_request_exception = False

    response = client.post(reverse('pki:issuing_cas-add-autogen'), {'key_type': 'RSA-2048'})

    assert response.status_code == 403
    assert not CaModel.objects.filter(ca_type=CaModel.CaTypeChoice.AUTOGEN).exists()


@pytest.mark.django_db
def test_autogen_endpoint_rejects_when_security_settings_disallow_creation(manage_cas_client: Client) -> None:
    """The server rejects a forged POST even when the page's control is disabled."""
    _security_config(allowed=False)

    with patch.object(AutoGenPki, 'enable_auto_gen_pki') as generate:
        response = manage_cas_client.post(reverse('pki:issuing_cas-add-autogen'), {'key_type': 'RSA-2048'})

    assert response.status_code == 302
    generate.assert_not_called()


@pytest.mark.django_db
def test_autogen_endpoint_rejects_duplicate_active_pki(manage_cas_client: Client) -> None:
    """The server blocks duplicate generation even for a direct POST."""
    _security_config(allowed=True)

    with (
        patch.object(AutoGenPki, 'get_auto_gen_pki', return_value=Mock()),
        patch.object(AutoGenPki, 'enable_auto_gen_pki') as generate,
    ):
        response = manage_cas_client.post(reverse('pki:issuing_cas-add-autogen'), {'key_type': 'RSA-2048'})

    assert response.status_code == 302
    generate.assert_not_called()


@pytest.mark.django_db
def test_autogen_endpoint_rejects_unsupported_key_type(manage_cas_client: Client) -> None:
    """A key type absent from the backend-filtered form choices cannot be submitted."""
    _security_config(allowed=True)

    with patch.object(AutoGenPki, 'enable_auto_gen_pki') as generate:
        response = manage_cas_client.post(reverse('pki:issuing_cas-add-autogen'), {'key_type': 'not-a-key-type'})

    assert response.status_code == 302
    generate.assert_not_called()


@pytest.mark.django_db
def test_autogen_endpoint_generates_cas_domain_audit_and_success_message(manage_cas_client: Client) -> None:
    """A valid POST generates the lifecycle and redirects with an audit entry."""
    _security_config(allowed=True)

    response = manage_cas_client.post(reverse('pki:issuing_cas-add-autogen'), {'key_type': 'RSA-2048'})

    assert response.status_code == 302
    assert response.url == reverse('pki:issuing_cas')
    issuing_ca = AutoGenPki.get_auto_gen_pki()
    assert issuing_ca is not None
    assert issuing_ca.parent_ca is not None
    assert CaModel.objects.filter(ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT).count() == 1
    domain = DomainModel.objects.get(issuing_ca=issuing_ca)
    assert domain.is_active
    audit_entry = AuditLog.objects.get(operation_type=AuditLog.OperationType.CA_CREATED)
    assert audit_entry.target == issuing_ca
    assert any('Successfully generated auto-generated PKI.' in str(message) for message in get_messages(response.wsgi_request))