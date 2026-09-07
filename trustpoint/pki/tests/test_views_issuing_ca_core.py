# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for core issuing-CA table and CRL views."""

from __future__ import annotations

from http import HTTPStatus
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import HttpResponse
from django.test import RequestFactory
from rest_framework.test import APIRequestFactory

from pki.util.crl import generate_empty_crl
from pki.util.x509 import CertificateGenerator
from pki.views.issuing_cas import (
    CrlDownloadView,
    IssuingCaCrlGenerationView,
    IssuingCaTableView,
    IssuingCaViewSet,
)


def test_issuing_ca_table_maps_common_name_sort() -> None:
    """The table maps display-name sorting to the related certificate field."""
    queryset = Mock()
    queryset.exclude.return_value = queryset
    queryset.order_by.return_value = queryset
    request = RequestFactory().get('/cas/', {'sort': 'common_name'})
    view = IssuingCaTableView()
    view.request = request
    view.model = Mock()
    view.model.objects.all.return_value = queryset
    view.model.CaTypeChoice.KEYLESS = -1
    view.model.CaTypeChoice.AUTOGEN_ROOT = 0
    view.model.is_active = True

    result = view.get_queryset()

    assert result is queryset
    queryset.order_by.assert_called_once_with('-is_active', 'credential__certificate__common_name')


def test_crl_generation_rejects_inactive_ca() -> None:
    """Inactive CAs cannot generate CRLs and are redirected to configuration."""
    ca = Mock(is_active=False, unique_name='inactive', pk=7)
    request = RequestFactory().get('/crl/')
    with (
        patch.object(IssuingCaCrlGenerationView, 'get_object', return_value=ca),
        patch('pki.views.issuing_cas.messages.error') as error,
        patch('pki.views.issuing_cas.redirect', return_value=HttpResponse(status=302)) as redirect,
    ):
        view = IssuingCaCrlGenerationView()
        view.request = request
        response = view.get(request)

    assert response.status_code == HTTPStatus.FOUND
    error.assert_called_once()
    redirect.assert_called_once_with('pki:issuing_cas-config', pk=7)


def test_crl_generation_reports_failure_and_rejects_external_next() -> None:
    """Failed generation reports an error and does not follow an external URL."""
    ca = Mock(is_active=True, unique_name='active', pk=7, crl_validity_hours=24)
    ca.issue_crl.return_value = False
    request = RequestFactory().get('/crl/', {'next': 'https://evil.example/'})
    with (
        patch.object(IssuingCaCrlGenerationView, 'get_object', return_value=ca),
        patch('pki.views.issuing_cas.messages.error') as error,
        patch('pki.views.issuing_cas.redirect', return_value=HttpResponse(status=302)) as redirect,
    ):
        view = IssuingCaCrlGenerationView()
        view.request = request
        response = view.get(request)

    assert response.status_code == HTTPStatus.FOUND
    ca.issue_crl.assert_called_once_with(crl_validity_hours=24)
    error.assert_called_once()
    redirect.assert_called_once_with('pki:issuing_cas-config', pk=7)


def test_crl_download_returns_pem() -> None:
    """CRL downloads return PEM bytes with an attachment filename."""
    ca = Mock(crl_pem='-----BEGIN X509 CRL-----\nabc\n-----END X509 CRL-----', unique_name='ca')
    request = RequestFactory().get('/crl/')
    with patch.object(CrlDownloadView, 'get_object', return_value=ca):
        response = CrlDownloadView().get(request)

    assert response.status_code == HTTPStatus.OK
    assert response['Content-Type'] == 'application/x-pem-file'
    assert response['Content-Disposition'] == 'attachment; filename="ca.crl"'


def test_crl_download_returns_der_and_handles_missing_crl() -> None:
    """DER downloads decode PEM bodies, while missing CRLs redirect."""
    pem = '-----BEGIN X509 CRL-----\nYWJj\n-----END X509 CRL-----'
    ca = Mock(crl_pem=pem, unique_name='ca')
    request = RequestFactory().get('/crl/', {'encoding': 'der'})
    with patch.object(CrlDownloadView, 'get_object', return_value=ca):
        response = CrlDownloadView().get(request)
    assert response.content == b'abc'
    assert response['Content-Type'] == 'application/pkix-crl'

    missing = Mock(crl_pem='', unique_name='missing')
    with (
        patch.object(CrlDownloadView, 'get_object', return_value=missing),
        patch('pki.views.issuing_cas.messages.warning') as warning,
        patch('pki.views.issuing_cas.redirect', return_value=HttpResponse(status=302)),
    ):
        response = CrlDownloadView().get(RequestFactory().get('/crl/'))
    assert response.status_code == HTTPStatus.FOUND
    warning.assert_called_once()


def test_issuing_ca_api_generate_crl_reports_success_and_failure() -> None:
    """The API CRL action returns structured success and failure responses."""
    ca = Mock(unique_name='api-ca', crl_validity_hours=48, last_crl_issued_at='timestamp')
    ca.issue_crl.side_effect = [True, False]
    view = IssuingCaViewSet()
    view.get_object = Mock(return_value=ca)

    success = view.generate_crl(Mock())
    failure = view.generate_crl(Mock())

    assert success.status_code == HTTPStatus.OK
    assert success.data['message'] == 'CRL generated successfully for Issuing CA "api-ca".'
    assert success.data['last_crl_issued_at'] == 'timestamp'
    assert failure.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert 'Failed to generate CRL' in failure.data['error']


def test_issuing_ca_api_crl_validates_format_and_downloads_der() -> None:
    """The API CRL action handles missing, invalid, PEM, and DER responses."""
    view = IssuingCaViewSet()
    ca = Mock(unique_name='api-ca', pk=3, crl_pem='')
    view.get_object = Mock(return_value=ca)
    missing = view.crl(APIRequestFactory().get('/'))
    assert missing.status_code == HTTPStatus.NOT_FOUND

    certificate, private_key = CertificateGenerator.create_root_ca('API Root')
    ca.crl_pem = generate_empty_crl(certificate, private_key)
    invalid = view.crl(APIRequestFactory().get('/', {'encoding': 'xml'}))
    assert invalid.status_code == HTTPStatus.BAD_REQUEST

    pem = view.crl(APIRequestFactory().get('/', {'encoding': 'pem'}))
    assert pem.status_code == HTTPStatus.OK
    assert pem['Content-Type'] == 'application/x-pem-file'

    der = view.crl(APIRequestFactory().get('/', {'encoding': 'der'}))
    assert der.status_code == HTTPStatus.OK
    assert der.content.startswith(b'0')
    assert der['Content-Type'] == 'application/pkix-crl'


def test_issuing_ca_import_rejects_malformed_key_and_certificate() -> None:
    """Import parsing returns field-specific errors for malformed PEM input."""
    view = IssuingCaViewSet()
    build_credential = IssuingCaViewSet.__dict__['_build_credential_from_import_data']
    key_error, *_ = build_credential(view, {
        'private_key_pem': 'bad',
        'ca_certificate_pem': 'bad',
    })
    assert key_error.status_code == HTTPStatus.BAD_REQUEST
    assert 'private_key_pem' in key_error.data

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_error, *_ = build_credential(view, {
        'private_key_pem': key_pem,
        'ca_certificate_pem': 'bad',
    })
    assert cert_error.status_code == HTTPStatus.BAD_REQUEST
    assert 'ca_certificate_pem' in cert_error.data
