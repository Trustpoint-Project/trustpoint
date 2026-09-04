# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for certificate profile view behavior."""

from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from pki.models import CertificateProfileModel
from pki.serializer.cert_profile import CertProfileDetailSerializer, CertProfileSerializer
from pki.views.cert_profiles import (
    CertProfileBulkDeleteConfirmView,
    CertProfileConfigView,
    CertProfileIssuanceView,
    CertProfileViewSet,
)


def profile_form(raw_json: object, unique_name: str = '') -> MagicMock:
    """Build a form mock exposing the fields read by profile configuration."""
    form = MagicMock()
    form.__getitem__.side_effect = lambda field: SimpleNamespace(
        value=lambda: raw_json if field == 'profile_json' else unique_name
    )
    return form


@pytest.mark.parametrize(
    ('raw_json', 'expected', 'state'),
    [
        (
            '',
            {
                'type': 'cert_profile',
                'credential_type': CertificateProfileModel.ProfileCredentialType.APPLICATION,
                'subj': {},
                'ext': {},
            },
            'valid',
        ),
        ('{"type": "cert_profile", "subj": {}}', {'type': 'cert_profile', 'subj': {}}, 'valid'),
        ('not-json', 'not-json', 'invalid'),
    ],
)
def test_profile_config_context_parses_json_states(raw_json: str, expected: object, state: str) -> None:
    """Profile configuration exposes defaults, parsed JSON, and invalid text states."""
    view = CertProfileConfigView()
    view.request = RequestFactory().get('/profiles/config/')
    view.object = None
    with patch('pki.views.cert_profiles.UpdateView.get_context_data', return_value={'form': profile_form(raw_json)}):
        context = CertProfileConfigView.get_context_data(view)

    assert context['profile_json'] == expected
    assert context['json_valid'] is (state == 'valid')


def test_profile_config_initial_uses_existing_name() -> None:
    """Editing a profile seeds the form with its persistent name."""
    view = CertProfileConfigView()
    view.object = SimpleNamespace(unique_name='existing')
    with patch('pki.views.cert_profiles.UpdateView.get_initial', return_value={}) as initial:
        result = view.get_initial()

    initial.assert_called_once()
    assert result == {'unique_name': 'existing'}


def test_profile_issuance_form_kwargs_and_context_include_profile() -> None:
    """Issuance views pass parsed profile content to the form and template."""
    view = CertProfileIssuanceView()
    view.profile = SimpleNamespace(profile_json='{"type": "cert_profile"}')
    with patch('pki.views.cert_profiles.FormView.get_form_kwargs', return_value={'data': {}}):
        kwargs = view.get_form_kwargs()
    assert kwargs['profile'] == {'type': 'cert_profile'}

    with patch.object(view, 'get_form_kwargs', return_value={'profile': kwargs['profile']}):
        context = view.get_context_data()
    assert context['profile'] is view.profile
    assert context['profile_dict'] == kwargs['profile']


def test_profile_issuance_invalid_form_reports_field_error() -> None:
    """Invalid issuance forms report field errors and render the form again."""
    view = CertProfileIssuanceView()
    view.request = RequestFactory().post('/profiles/issue/')
    invalid_form = Mock(errors={'subject': ['invalid']})
    with (
        patch('pki.views.cert_profiles.messages.error') as error,
        patch('pki.views.cert_profiles.FormView.form_invalid', return_value=HttpResponse(status=400)) as invalid,
    ):
        response = view.form_invalid(invalid_form)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    error.assert_called_once()
    invalid.assert_called_once_with(invalid_form)


def test_profile_issuance_valid_form_redirects() -> None:
    """A valid issuance form that builds successfully redirects to profiles."""
    view = CertProfileIssuanceView()
    view.request = RequestFactory().post('/profiles/issue/')
    form = Mock()
    with patch('pki.views.cert_profiles.messages.success') as success:
        response = view.form_valid(form)

    form.get_certificate_builder.assert_called_once()
    success.assert_called_once()
    assert response.status_code == HTTPStatus.FOUND


def test_profile_issuance_builder_error_uses_invalid_path() -> None:
    """Builder errors are surfaced and routed through invalid-form handling."""
    view = CertProfileIssuanceView()
    view.request = RequestFactory().post('/profiles/issue/')
    form = Mock()
    form.get_certificate_builder.side_effect = ValueError('bad profile')
    with (
        patch('pki.views.cert_profiles.messages.error') as error,
        patch.object(view, 'form_invalid', return_value=HttpResponse(status=400)) as invalid,
    ):
        response = view.form_valid(form)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    error.assert_called_once()
    invalid.assert_called_once_with(form)


def test_profile_viewset_uses_detail_serializer_only_for_retrieve() -> None:
    """The API uses the detailed serializer for retrieve and basic serializer otherwise."""
    view = CertProfileViewSet()
    view.action = 'retrieve'
    assert view.get_serializer_class() is CertProfileDetailSerializer
    view.action = 'list'
    assert view.get_serializer_class() is CertProfileSerializer


@pytest.mark.django_db
def test_profile_bulk_delete_get_redirects_without_selection() -> None:
    """Empty profile deletion selections redirect without rendering confirmation."""
    request = RequestFactory().get('/profiles/delete/')
    view = CertProfileBulkDeleteConfirmView()
    view.request = request
    view.get_queryset = Mock(return_value=Mock(exists=Mock(return_value=False)))
    with (
        patch('pki.views.cert_profiles.messages.error') as error,
        patch('pki.views.cert_profiles.HttpResponseRedirect', return_value=HttpResponse(status=302)) as redirect,
    ):
        response = view.get(request)

    assert response.status_code == HTTPStatus.FOUND
    error.assert_called_once()
    redirect.assert_called_once()
