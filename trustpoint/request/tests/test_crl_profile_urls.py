# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""CRL profile URL validation, resolution, and manual issuance regression tests."""

import ipaddress
from typing import Any
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.models.ca_rollover import CaRolloverState
from pki.util.cert_profile import JSONProfileVerifier
from pki.util.cert_req_converter import JSONCertRequestConverter
from request.profile_validator import ProfileValidator
from request.request_context import BaseRequestContext, ManualCredentialRequestContext
from request.template_vars import resolve_crl_urls


def profile(uris: Any) -> dict[str, Any]:
    """Build a minimal CRL profile."""
    return {'type': 'cert_profile', 'validity': {'days': 10},
            'ext': {'crl_distribution_points': {'uris': uris}}}


@pytest.mark.parametrize('url', [
    'http://2.2.2.2/crl/{issuing_ca.id}',
    'http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}',
    'https://{{ tls_certificate.ip_address.2 }}/crl/{{ issuing_ca.id }}',
    'http://[2001:db8::1]/crl/4',
])
def test_profile_accepts_crl_templates(url: str) -> None:
    """Accept fixed URLs and supported placeholders."""
    assert JSONProfileVerifier(profile({'value': [url]})).get_profile()


@pytest.mark.parametrize('url', [
    'http:2.2.2.2/crl/4', 'http://{unknown}/crl/4',
    'http://{tls_certificate.ip_address.0}/crl/4', 'http://host/crl/{issuing_ca.id',
    'http://host with spaces/crl/4', 'http://host:bad/crl/4',
])
def test_profile_rejects_invalid_crl_urls(url: str) -> None:
    """Reject malformed URLs and unsupported placeholders."""
    with pytest.raises(ValidationError):
        JSONProfileVerifier(profile({'default': [url]}))


def test_crl_templates_use_active_tls_ip_sans_and_ca_rollover() -> None:
    """Use the signing CA ID and ordered IP SANs, including IPv6."""
    context = BaseRequestContext(domain=Mock())
    ca = context.domain.get_issuing_ca_or_value_error.return_value
    ca.pk = 4
    rollover = Mock()
    rollover.new_issuing_ca.pk = 9
    rollover.state = CaRolloverState.TRANSITION
    data = {'extensions': {'crl_distribution_points': {'uris': [
        'http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}',
        'http://{{ tls_certificate.ip_address.2 }}/crl/{{ issuing_ca.id }}',
    ]}}}
    cert = Mock()
    cert.extensions.get_extension_for_class.return_value.value = x509.SubjectAlternativeName([
        x509.DNSName('example.test'), x509.IPAddress(ipaddress.ip_address('192.0.2.3')),
        x509.IPAddress(ipaddress.ip_address('2001:db8::1')),
    ])
    with patch('request.template_vars.ActiveTrustpointTlsServerCredentialModel.objects') as objects, patch(
        'request.template_vars.CaRolloverService.get_active_rollover', return_value=rollover,
    ):
        objects.select_related.return_value.first.return_value.credential.get_certificate.return_value = cert
        resolve_crl_urls(data, context)
    assert data['extensions']['crl_distribution_points']['uris'] == [
        'http://192.0.2.3/crl/9', 'http://[2001:db8::1]/crl/9',
    ]


def test_unavailable_tls_ip_fails() -> None:
    """Reject unavailable IP SAN indices without a localhost fallback."""
    data = {'extensions': {'crl_distribution_points': {'uris': ['http://{tls_certificate.ip_address.1}/crl/4']}}}
    with patch('request.template_vars.ActiveTrustpointTlsServerCredentialModel.objects') as objects:
        objects.select_related.return_value.first.return_value = None
        with pytest.raises(ValueError, match='Cannot resolve CRL URL placeholder'):
            resolve_crl_urls(data, BaseRequestContext())


@pytest.mark.parametrize('mutable', [True, False])
def test_manual_form_retains_profile_constraints_and_converter_roundtrip(*, mutable: bool) -> None:
    """Preserve fixed and mutable CRL URLs through manual form conversion."""
    url = 'http://192.0.2.3/crl/4'
    form = CertificateIssuanceForm(
        profile({'value': [url], 'mutable': mutable}),
        data={'crl_distribution_point_uris': 'http://192.0.2.99/crl/4'},
    )
    assert form.fields['crl_distribution_point_uris'].disabled is (not mutable)
    with patch('pki.forms.cert_profiles.check_validity_days_against_security_config'):
        assert form.is_valid(), form.errors
    builder = form.get_certificate_builder()
    request = JSONCertRequestConverter.to_json(builder)
    expected = 'http://192.0.2.99/crl/4' if mutable else url
    assert request['ext']['crl_distribution_points']['uris'] == [expected]


def test_manual_crl_url_survives_pipeline_and_signing() -> None:
    """Retain a mutable manual URL through revalidation and certificate signing."""
    cert_profile = profile({'value': ['http://192.0.2.1/crl/4'], 'mutable': True})
    url = 'https://crl.example.test/crl/4'
    form = CertificateIssuanceForm(cert_profile, data={'crl_distribution_point_uris': url})
    with patch('pki.forms.cert_profiles.check_validity_days_against_security_config'):
        assert form.is_valid(), form.errors
    context = ManualCredentialRequestContext(
        cert_requested=form.get_certificate_builder(),
        certificate_profile_model=Mock(profile=cert_profile),
    )
    ProfileValidator.validate(context)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'CRL test')])
    builder = context.cert_requested_profile_validated
    assert builder is not None
    certificate = (builder.subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(1).sign(key, hashes.SHA256()))
    points = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert points[0].full_name == [x509.UniformResourceIdentifier(url)]


@pytest.mark.parametrize('mutable', [True, False])
def test_form_displays_resolved_crl_url_without_changing_profile(*, mutable: bool) -> None:
    """Show concrete initial URLs and preserve template rules through submission."""
    template = 'http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}'
    cert_profile = profile({'value': [template], 'mutable': mutable})
    cert_profile['reject_mods'] = True
    domain = Mock(organization=None)
    domain.get_issuing_ca_or_value_error.return_value.pk = 4
    variables = {'tls_certificate.ip_address.1': '127.0.0.1'}
    with patch('request.template_vars._tls_ip_variables', return_value=variables), patch(
        'request.template_vars.CaRolloverService.get_active_rollover', return_value=None,
    ), patch('pki.forms.cert_profiles.check_validity_days_against_security_config'):
        form = CertificateIssuanceForm(cert_profile, domain=domain)
        assert form['crl_distribution_point_uris'].value() == 'http://127.0.0.1/crl/4'
        assert cert_profile['ext']['crl_distribution_points']['uris']['value'] == [template]
        bound = CertificateIssuanceForm(
            cert_profile, domain=domain, data={'crl_distribution_point_uris': 'http://127.0.0.1/crl/4'},
        )
        assert bound.is_valid(), bound.errors
        builder = bound.get_certificate_builder(ManualCredentialRequestContext(domain=domain))
        result = JSONCertRequestConverter.to_json(builder)
        assert result['ext']['crl_distribution_points']['uris'] == ['http://127.0.0.1/crl/4']


def test_form_keeps_crl_url_editable_when_tls_ip_is_missing() -> None:
    """Allow entering a fixed URL when the configured TLS IP cannot be resolved."""
    template = 'http://{tls_certificate.ip_address.1}/crl/4'
    with patch('request.template_vars._tls_ip_variables', return_value={}):
        form = CertificateIssuanceForm(profile({'value': [template], 'mutable': True}))
    assert form['crl_distribution_point_uris'].value() == template
    assert 'Cannot resolve CRL URL placeholder' in form.fields['crl_distribution_point_uris'].help_text
    assert not form.fields['crl_distribution_point_uris'].disabled


@pytest.mark.parametrize('placeholder', ['{issuing_ca.id}', '{{ issuing_ca.id }}'])
def test_ca_id_placeholder(placeholder: str) -> None:
    """Resolve the CA ID placeholder with either brace syntax."""
    url = f'http://127.0.0.1/crl/{placeholder}'
    JSONProfileVerifier(profile({'value': [url]}))
    domain = Mock()
    domain.get_issuing_ca_or_value_error.return_value.pk = 7
    data = {'extensions': {'crl_distribution_points': {'uris': [url]}}}
    with patch('request.template_vars.CaRolloverService.get_active_rollover', return_value=None):
        resolve_crl_urls(data, BaseRequestContext(domain=domain))
    assert data['extensions']['crl_distribution_points']['uris'] == ['http://127.0.0.1/crl/7']


@pytest.mark.parametrize('placeholder', ['{crlnumber}', '{{ crlnumber }}'])
def test_removed_crl_number_placeholder_is_rejected(placeholder: str) -> None:
    """Reject the removed placeholder in profiles and during URL resolution."""
    url = f'http://127.0.0.1/crl/{placeholder}'
    with pytest.raises(ValidationError):
        JSONProfileVerifier(profile({'value': [url]}))
    data = {'extensions': {'crl_distribution_points': {'uris': [url]}}}
    with pytest.raises(ValueError, match='Supported placeholders'):
        resolve_crl_urls(data, BaseRequestContext())
