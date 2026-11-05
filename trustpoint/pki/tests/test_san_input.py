# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for shared SAN normalization and validation boundaries."""

import ipaddress
from unittest.mock import Mock

import pytest
from cryptography import x509

from devices.forms import BaseServerCredentialForm
from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.serializer.owner_credential import CertificateIssuanceContentSerializer
from pki.util.certificate_request import build_ca_request_data, build_request_data
from pki.util.cert_req_converter import JSONCertRequestConverter
from pki.util.san import SanValidationError, normalize_san_values, parse_ip_addresses, split_san_values
from request.operation_processor.csr_build import CsrBuilder
from setup_wizard.forms import FreshInstallTlsConfigForm, StartupWizardTlsCertificateForm
from util.validation import ValidationError as ApplicationUriError
from util.validation import validate_application_uri

NORMALIZATIONS = [
    (
        'dns_names',
        ' BüCHER.Example., localhost, *.Example.COM, localhost, ',
        ['xn--bcher-kva.example', 'localhost', '*.example.com', 'localhost'],
    ),
    (
        'ip_addresses',
        ' 192.0.2.1, 2001:0DB8:0:0::1, ::ffff:192.0.2.1, ',
        ['192.0.2.1', '2001:db8::1', str(ipaddress.IPv6Address('::ffff:192.0.2.1'))],
    ),
    ('rfc822_names', ' User@BÜCHER.Example, other@EXAMPLE.COM, ', ['User@xn--bcher-kva.example', 'other@example.com']),
    (
        'uris',
        ' urn:EXAMPLE:Device, https://EXAMPLE.com/CaseSensitive%2FPath, ',
        ['urn:EXAMPLE:Device', 'https://EXAMPLE.com/CaseSensitive%2FPath'],
    ),
]
INVALID = (
    [
        ('dns_names', name)
        for name in [
            '',
            '-host.example',
            'host-.example',
            'host..example',
            'host.example..',
            'host_name.example',
            'https://example.com',
            'foo.*.example',
            '*foo.example',
            'a' * 64 + '.example',
            '.example',
            'host\nname.example',
        ]
        if name
    ]
    + [('ip_addresses', name) for name in ['999.1.1.1', '192.0.2.0/24', '2001:db8::/32', 'fe80::1%eth0', 'hostname']]
    + [
        ('rfc822_names', name)
        for name in ['no-at-sign', 'user@', '@example.com', '用户@example.com', 'user@bad_domain.com']
    ]
    + [
        ('uris', name)
        for name in [
            'relative/path',
            'urn:',
            'https:///path',
            'https://example.com:bad/',
            'urn:test\nother',
            'https://example.com/%xx',
            'urn:bad<value>',
            'https://bücher.example',
        ]
    ]
)


@pytest.mark.parametrize(('field', 'raw', 'expected'), NORMALIZATIONS)
def test_csv_and_list_input_normalize_identically(field, raw, expected):
    """Whitespace, empty entries, DNS IDNA, IP notation and mailbox domains share one policy."""
    assert normalize_san_values(field, raw) == expected
    assert normalize_san_values(field, raw.split(',')) == expected
    assert normalize_san_values(field, None) == []


@pytest.mark.parametrize(('field', 'raw'), INVALID)
def test_invalid_identities_fail_before_x509_construction(field, raw):
    """Reject malformed identities instead of letting crypto libraries encode invalid SANs."""
    with pytest.raises(SanValidationError):
        normalize_san_values(field, raw)


@pytest.mark.parametrize('value', [123, {'dns': 'example.com'}, ['example.com', None], ['example.com', 123]])
def test_unsupported_san_input_shapes_are_controlled(value):
    """Unknown shapes never turn into accidental identities through str() coercion."""
    with pytest.raises(SanValidationError):
        split_san_values(value)


def test_list_entries_can_contain_commas():
    """A URI or quoted mailbox supplied as a list item is not split into multiple SANs."""
    uri = 'https://example.com/path,a?b=c,d'
    assert normalize_san_values('uris', [uri]) == [uri]
    assert normalize_san_values('rfc822_names', ['"Last,First"@EXAMPLE.COM']) == ['"Last,First"@example.com']


def test_ip_families_and_native_objects():
    """Version-specific forms retain address objects while generic inputs accept both families."""
    ipv4, ipv6 = ipaddress.IPv4Address('192.0.2.1'), ipaddress.IPv6Address('2001:db8::1')
    assert parse_ip_addresses([ipv4], version=4) == [ipv4]
    assert parse_ip_addresses([ipv6], version=6) == [ipv6]
    for value, version in [('::1', 4), ('192.0.2.1', 6)]:
        with pytest.raises(SanValidationError):
            parse_ip_addresses(value, version=version)


@pytest.mark.parametrize(
    'form_type', [FreshInstallTlsConfigForm, StartupWizardTlsCertificateForm, BaseServerCredentialForm]
)
def test_legacy_and_setup_form_adapters_preserve_output_types(form_type):
    """Shared parsing preserves string outputs for fresh setup and address objects for existing forms."""
    form = form_type(device=Mock()) if form_type is BaseServerCredentialForm else form_type()
    form.cleaned_data = {
        'ipv4_addresses': ' 192.0.2.1, ',
        'ipv6_addresses': '2001:0DB8::1, ',
        'domain_names': ' BüCHER.Example., localhost, ',
    }
    ipv4, ipv6 = form.clean_ipv4_addresses(), form.clean_ipv6_addresses()
    assert [str(value) for value in ipv4] == ['192.0.2.1']
    assert [str(value) for value in ipv6] == ['2001:db8::1']
    assert isinstance(ipv4[0], str if form_type is FreshInstallTlsConfigForm else ipaddress.IPv4Address)
    assert form.clean_domain_names() == ['xn--bcher-kva.example', 'localhost']


def test_setup_keeps_hostname_only_policy_while_device_certificates_allow_wildcards():
    """Setup's existing wildcard restriction must not become a general certificate restriction."""
    from django.core.exceptions import ValidationError

    for form_type in (FreshInstallTlsConfigForm, StartupWizardTlsCertificateForm):
        form = form_type()
        form.cleaned_data = {'domain_names': '*.example.com'}
        with pytest.raises(ValidationError):
            form.clean_domain_names()
    form = BaseServerCredentialForm(device=Mock())
    form.cleaned_data = {'domain_names': '*.EXAMPLE.com'}
    assert form.clean_domain_names() == ['*.example.com']


def _profile():
    return {'type': 'cert_profile', 'subj': {'cn': {'default': 'device.example'}}, 'ext': {'san': {'allow': '*'}}}


@pytest.mark.django_db
@pytest.mark.parametrize(('field', 'raw', 'expected'), NORMALIZATIONS)
def test_profile_forms_api_and_request_builders_agree(field, raw, expected):
    """Editable UI fields and API content normalize before profile and CSR processing."""
    form = CertificateIssuanceForm(_profile(), data={field: raw})
    serializer = CertificateIssuanceContentSerializer(data={field: raw})
    assert form.is_valid(), form.errors
    assert serializer.is_valid(), serializer.errors
    assert form.cleaned_data[field] == serializer.validated_data[field] == ', '.join(expected)
    assert form._form_data_to_json_request()['extensions']['subject_alternative_name'][field] == expected
    assert build_request_data(serializer.validated_data)['ext']['subject_alternative_name'][field] == expected
    assert build_ca_request_data({field: expected})['ext']['subject_alternative_name'][field] == expected


@pytest.mark.django_db
@pytest.mark.parametrize(('field', 'raw'), INVALID)
def test_ui_and_api_validation_errors_remain_on_the_field(field, raw):
    """Malformed entries become field errors in both interfaces."""
    form = CertificateIssuanceForm(_profile(), data={field: raw})
    serializer = CertificateIssuanceContentSerializer(data={field: raw})
    assert not form.is_valid()
    assert field in form.errors
    assert not serializer.is_valid()
    assert field in serializer.errors


@pytest.mark.django_db
def test_required_san_rejects_comma_only_input():
    """Required SANs remain required after empty CSV entries have been removed."""
    profile = _profile()
    profile['ext']['san']['dns_names'] = {'required': True, 'mutable': True}
    form = CertificateIssuanceForm(profile, data={'dns_names': ', , '})
    assert not form.is_valid()
    assert 'dns_names' in form.errors


@pytest.mark.django_db
def test_immutable_profile_templates_are_not_validated_as_user_input():
    """Trusted immutable templates survive form cleaning until context-based resolution."""
    template = '{device.common_name}.EXAMPLE.com'
    profile = _profile()
    profile['ext']['san']['dns_names'] = {'value': [template], 'mutable': False}
    form = CertificateIssuanceForm(profile, data={'dns_names': 'attacker.example'})
    assert form.fields['dns_names'].disabled
    assert form.is_valid(), form.errors
    assert form.cleaned_data['dns_names'] == template
    assert build_request_data(form.cleaned_data)['ext']['subject_alternative_name']['dns_names'] == [template]


def test_csr_builder_preserves_ipv4_mapped_ipv6_and_rejects_partial_invalid_input():
    """Dotted IPv6 notation is not mistaken for IPv4, and invalid IPs are never silently dropped."""
    builder = CsrBuilder()
    sans = builder._build_san_names({'ip_addresses': '192.0.2.1, ::ffff:192.0.2.1'})
    assert sans == [
        x509.IPAddress(ipaddress.ip_address('192.0.2.1')),
        x509.IPAddress(ipaddress.ip_address('::ffff:192.0.2.1')),
    ]
    assert JSONCertRequestConverter._general_name_from_json(
        {'ip_addresses': ['192.0.2.1', '::ffff:192.0.2.1']},
    ) == sans
    with pytest.raises(SanValidationError):
        builder._build_san_names({'ip_addresses': '192.0.2.1, invalid'})
    with pytest.raises(SanValidationError):
        JSONCertRequestConverter._general_name_from_json({'ip_addresses': ['192.0.2.1', 'invalid']})


@pytest.mark.parametrize('uri', ['http://example.com/resource', 'https://example.com/resource'])
def test_generic_uri_support_does_not_bypass_opcua_restrictions(uri):
    """HTTP SAN URIs are valid generally but remain disallowed as OPC UA application URIs."""
    assert normalize_san_values('uris', uri) == [uri]
    with pytest.raises(ApplicationUriError, match='HTTP and HTTPS'):
        validate_application_uri(uri)
