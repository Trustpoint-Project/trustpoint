# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for choosing the CA role before the add wizard."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import Client
from django.urls import reverse

from pki.forms.issuing_cas import (
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddRequestExternalCsrForm,
    IssuingCaRequestCmpForm,
    IssuingCaRequestEstForm,
)
from pki.models import CaModel


@pytest.fixture
def manage_cas_client() -> Client:
    """Return an authenticated client allowed to manage CAs."""
    user = get_user_model().objects.create_user(
        username='ca-role-admin', password='test-password',  # noqa: S106
    )
    user.role.permissions.add(Permission.objects.get(codename='manage_cas'))
    client = Client()
    client.force_login(user)
    return client


@pytest.mark.django_db
def test_role_selection_precedes_the_method_page(manage_cas_client: Client) -> None:
    """Choosing Management CA stores the role and swaps the wizard heading."""
    response = manage_cas_client.post(
        reverse('pki:issuing_cas-add-role_select'),
        {'ca_role': CaModel.CaRole.MANAGEMENT},
    )

    assert response.status_code == 302  # noqa: PLR2004
    assert response.url == reverse('pki:issuing_cas-add-method_select')
    assert manage_cas_client.session['ca_add_role'] == CaModel.CaRole.MANAGEMENT

    response = manage_cas_client.get(reverse('pki:issuing_cas-add-method_select'))
    assert response.context['management_ca'] is True
    assert b'Add new Management CA' in response.content
    assert b'Auto-generated PKI' not in response.content


@pytest.mark.django_db
def test_role_selection_defaults_to_issuing(manage_cas_client: Client) -> None:
    """The legacy method page remains usable and defaults to an issuing CA."""
    response = manage_cas_client.get(reverse('pki:issuing_cas-add-method_select'))

    assert response.status_code == 200  # noqa: PLR2004
    assert response.context['management_ca'] is False
    assert b'Add new Issuing CA' in response.content


def test_import_form_receives_the_selected_role() -> None:
    """The import form only needs the role to stamp it on the created CA."""
    form = IssuingCaAddFileImportPkcs12Form(ca_role=CaModel.CaRole.MANAGEMENT)

    assert form.ca_role == CaModel.CaRole.MANAGEMENT


def test_request_wizards_carry_the_selected_role() -> None:
    """EST and CMP wizard forms must submit the role chosen before the wizard."""
    for form_class in (IssuingCaRequestEstForm, IssuingCaRequestCmpForm):
        form = form_class(initial={'ca_role': CaModel.CaRole.MANAGEMENT})

        assert form['ca_role'].value() == CaModel.CaRole.MANAGEMENT


@pytest.mark.django_db
def test_external_csr_form_stamps_selected_role() -> None:
    """The pre-wizard role reaches the created CA, not just the form attribute."""
    form = IssuingCaAddRequestExternalCsrForm(
        {
            'unique_name': 'management-csr-ca',
            'ca_type': CaModel.CaTypeChoice.REMOTE_ISSUING_CSR,
            'key_type': 'RSA-2048',
        },
        ca_role=CaModel.CaRole.MANAGEMENT,
    )
    assert form.is_valid(), form.errors

    with (
        patch('pki.forms.issuing_cas.PermittedProtocolsAuthorization.check'),
        patch('pki.forms.issuing_cas.PkiSecurityAuthorization.check'),
    ):
        ca = form.save()

    assert ca.ca_role == CaModel.CaRole.MANAGEMENT
