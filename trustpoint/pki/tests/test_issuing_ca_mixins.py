# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for reusable issuing-CA certificate-request view mixins."""

from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.test import RequestFactory

from pki.models import CertificateProfileModel
from pki.views.issuing_cas import (
    IssuingCaDefineCertContentCmpView,
    IssuingCaDefineCertContentEstView,
    IssuingCaDefineCertContentMixin,
    IssuingCaRequestCertCmpView,
    IssuingCaRequestCertEstView,
    IssuingCaRequestCertMixin,
)


def test_certificate_content_summary_formats_subject_sans_and_validity() -> None:
    """Content summaries label all supplied subject, SAN, and validity fields."""
    view = IssuingCaRequestCertEstView()
    summary = IssuingCaRequestCertMixin.__dict__['_build_cert_content_summary'](view, {
        'common_name': 'ca.example',
        'organization_name': 'Trustpoint',
        'dns_names': ['ca.example'],
        'uris': ['urn:ca'],
        'days': 10,
        'minutes': 5,
    })

    assert summary['subject'] == {'Common Name (CN)': 'ca.example', 'Organization (O)': 'Trustpoint'}
    assert summary['san'] == {'DNS Names': ['ca.example'], 'URIs': ['urn:ca']}
    assert summary['validity'] == '10 days, 5 minutes'
    assert IssuingCaRequestCertMixin.__dict__['_build_cert_content_summary'](view, {})['validity'] == 'Not specified'


def test_est_and_cmp_request_data_convert_form_values() -> None:
    """EST and CMP request views produce the same nested request contract."""
    content = {
        'common_name': 'ca.example',
        'country_name': 'DE',
        'dns_names': ['ca.example'],
        'ip_addresses': '192.0.2.1',
        'days': '30',
    }
    est_view = IssuingCaRequestCertEstView()
    cmp_view = IssuingCaRequestCertCmpView()
    est = IssuingCaRequestCertEstView.__dict__['_build_request_data_from_form'](est_view, content)
    cmp = IssuingCaRequestCertCmpView.__dict__['_build_request_data_from_form'](cmp_view, content)

    assert est == cmp
    assert est['subj'] == {'common_name': 'ca.example', 'country_name': 'DE'}
    assert est['ext']['subject_alternative_name']['ip_addresses'] == '192.0.2.1'
    assert est['validity'] == {'days': 30}


@pytest.mark.django_db
def test_define_content_profile_selection_prefers_requested_then_issuing_default() -> None:
    """Certificate-content views resolve an explicit profile, then issuing_ca, then first."""
    selected = CertificateProfileModel.objects.create(
        unique_name='selected', display_name='Selected', profile_json={'type': 'cert_profile'}
    )
    default = CertificateProfileModel.objects.create(
        unique_name='issuing_ca', display_name='Default', profile_json={'type': 'cert_profile'}
    )
    view = IssuingCaDefineCertContentEstView()
    requested = RequestFactory().get('/', {'cert_profile_pk': selected.pk})

    resolve_profile = IssuingCaDefineCertContentMixin.__dict__['_resolve_cert_profile']
    assert resolve_profile(view, requested) == selected
    assert resolve_profile(view, RequestFactory().get('/')) == default

    default.delete()
    assert resolve_profile(view, RequestFactory().get('/')) == selected


@pytest.mark.django_db
def test_request_cert_views_redirect_when_content_is_missing() -> None:
    """EST and CMP requests require certificate content in the session first."""
    ca = SimpleNamespace(pk=7, unique_name='remote-ca')
    for view_class, route in [
        (IssuingCaRequestCertEstView, 'pki:issuing_cas-define-cert-content-est'),
        (IssuingCaRequestCertCmpView, 'pki:issuing_cas-define-cert-content-cmp'),
    ]:
        request = RequestFactory().post('/')
        request.session = {}
        view = view_class()
        view.get_object = Mock(return_value=ca)
        with patch('pki.views.issuing_cas.messages.error') as error, patch(
            'pki.views.issuing_cas.redirect', return_value=SimpleNamespace(status_code=HTTPStatus.FOUND)
        ) as redirect:
            response = view.post(request)

        assert response.status_code == HTTPStatus.FOUND
        error.assert_called_once()
        redirect.assert_called_once_with(route, pk=7)


def test_define_content_views_have_protocol_specific_messages() -> None:
    """EST and CMP content views expose protocol-specific success messages."""
    est_message = IssuingCaDefineCertContentEstView().get_success_message()
    cmp_message = IssuingCaDefineCertContentCmpView().get_success_message()

    assert 'EST' in est_message
    assert 'CMP' in cmp_message
