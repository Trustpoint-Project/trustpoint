# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for managed-key ownership in issuing-CA request forms."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from django import forms

from pki.forms.issuing_cas import IssuingCaAddRequestCmpForm, IssuingCaAddRequestEstForm
from pki.models import CaModel


def _form(form_type: type[IssuingCaAddRequestEstForm] | type[IssuingCaAddRequestCmpForm]):
    with patch.object(form_type, '_supported_key_type_choices', return_value=[('RSA-2048', 'RSA 2048')]):
        return form_type()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('form_type', 'secret_values'),
    [
        (IssuingCaAddRequestEstForm, {'est_username': 'operator', 'est_password': 'secret'}),
        (IssuingCaAddRequestCmpForm, {'cmp_shared_secret': 'secret'}),
    ],
)
def test_remote_issuing_ca_generates_exactly_one_managed_key(form_type, secret_values) -> None:
    """Subclass save flows must not generate once in the mixin and again in the subclass."""
    form = _form(form_type)
    form.cleaned_data = {'key_type': 'RSA-2048', 'unique_name': 'remote-ca', **secret_values}
    instance = Mock(spec=CaModel)
    credential = Mock()

    with (
        patch.object(forms.ModelForm, 'save', return_value=instance),
        patch.object(form, '_create_credential', return_value=credential) as create_credential,
        patch('pki.forms.issuing_cas.NoOnboardingConfigModel.objects.create', return_value=Mock()),
        patch('pki.forms.issuing_cas.PermittedProtocolsAuthorization.check'),
        patch('pki.forms.issuing_cas.PkiSecurityAuthorization.check'),
    ):
        result = form.save(is_ra_mode=False)

    assert result is instance
    create_credential.assert_called_once_with()
    assert instance.credential is credential
    instance.save.assert_called_once_with()


@pytest.mark.django_db
def test_remote_ra_does_not_generate_managed_key() -> None:
    """Registration-authority mode has no signing credential and must not create a key."""
    form = _form(IssuingCaAddRequestEstForm)
    form.cleaned_data = {'key_type': 'RSA-2048', 'est_username': 'operator', 'est_password': 'secret'}
    instance = Mock(spec=CaModel)

    with (
        patch.object(forms.ModelForm, 'save', return_value=instance),
        patch.object(form, '_create_credential') as create_credential,
        patch('pki.forms.issuing_cas.NoOnboardingConfigModel.objects.create', return_value=Mock()),
        patch('pki.forms.issuing_cas.PermittedProtocolsAuthorization.check'),
        patch('pki.forms.issuing_cas.PkiSecurityAuthorization.check'),
    ):
        form.save(is_ra_mode=True)

    create_credential.assert_not_called()
    assert instance.credential is None


@pytest.mark.django_db
def test_remote_ca_failure_cleans_up_generated_credential() -> None:
    """A provider key is compensated when later CA persistence fails."""
    form = _form(IssuingCaAddRequestCmpForm)
    form.cleaned_data = {'key_type': 'RSA-2048', 'unique_name': 'remote-ca', 'cmp_shared_secret': 'secret'}
    instance = Mock(spec=CaModel)
    instance.save.side_effect = RuntimeError('database failure')
    credential = Mock()

    with (
        patch.object(forms.ModelForm, 'save', return_value=instance),
        patch.object(form, '_create_credential', return_value=credential),
        patch.object(form, '_cleanup_generated_credential') as cleanup,
        patch('pki.forms.issuing_cas.NoOnboardingConfigModel.objects.create', return_value=Mock()),
        patch('pki.forms.issuing_cas.PermittedProtocolsAuthorization.check'),
        patch('pki.forms.issuing_cas.PkiSecurityAuthorization.check'),
        pytest.raises(RuntimeError, match='database failure'),
    ):
        form.save(is_ra_mode=False)

    cleanup.assert_called_once_with(credential)
