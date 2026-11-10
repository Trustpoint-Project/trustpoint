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
from pki.util.certificate_request import build_cert_content_summary
from pki.views.issuing_cas import (
    IssuingCaDefineCertContentEstView,
    IssuingCaExternalCsrView,
    IssuingCaRequestCertCmpView,
    IssuingCaRequestCertEstView,
)


def test_certificate_content_summary_formats_subject_sans_and_validity() -> None:
    """Content summaries label all supplied subject, SAN, and validity fields."""
    summary = build_cert_content_summary(
        {
            'common_name': 'ca.example',
            'organization_name': 'Trustpoint',
            'dns_names': ['ca.example'],
            'uris': ['urn:ca'],
            'days': 10,
            'minutes': 5,
        },
    )

    assert summary['subject'] == {'Common Name (CN)': 'ca.example', 'Organization (O)': 'Trustpoint'}
    assert summary['san'] == {'DNS Names': ['ca.example'], 'URIs': ['urn:ca']}
    assert summary['validity'] == '10 days, 5 minutes'
    assert build_cert_content_summary({})['validity'] == 'Not specified'


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
    est = est_view.build_request_data_for_enrollment(content)
    cmp = cmp_view.build_request_data_for_enrollment(content)

    assert est == cmp
    assert IssuingCaExternalCsrView()._build_request_data_from_form(content) == est
    assert est['subj'] == {'common_name': 'ca.example', 'country_name': 'DE'}
    assert est['ext']['subject_alternative_name'] == {
        'dns_names': ['ca.example'],
        'ip_addresses': ['192.0.2.1'],
    }
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

    assert view._resolve_cert_profile(requested) == selected
    assert view._resolve_cert_profile(RequestFactory().get('/')) == default

    default.delete()
    assert view._resolve_cert_profile(RequestFactory().get('/')) == selected


@pytest.mark.django_db
def test_request_cert_views_redirect_when_content_is_missing() -> None:
    """Certificate requests require certificate content in the session first."""
    ca = SimpleNamespace(pk=7, unique_name='remote-ca')
    view = IssuingCaRequestCertCmpView()
    view.state = {}
    view.edit_url_name = 'pki:issuing_cas-define-cert-content-cmp'
    request = RequestFactory().post('/')
    request.user = Mock(has_perm=Mock(return_value=True))
    request.session = {}
    view.get_object = Mock(return_value=ca)
    with patch(
        'pki.views.est_request.redirect', return_value=SimpleNamespace(status_code=HTTPStatus.FOUND)
    ) as redirect:
        response = view.post(request)

    assert response.status_code == HTTPStatus.FOUND
    redirect.assert_called_once_with('pki:issuing_cas-define-cert-content-cmp', pk=7)
