# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Wire-format and endpoint tests for EST CSR attributes."""

import base64

import pytest
from django.urls import resolve
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5280

from est.csrattrs import CsrAttrs, EXTENSION_REQUEST_OID, build_csrattrs
from est.views import EstCsrAttrsView
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainAllowedCertificateProfileModel


def decode_attributes(data):
    attributes, remainder = decoder.decode(data, asn1Spec=CsrAttrs())
    assert not remainder
    return attributes


def test_required_subject_aliases_and_server_defaults():
    profile = {
        'type': 'cert_profile',
        'subj': {
            'CN': {'required': True},
            '2.5.4.5': {'required': True},
            'o': {'required': True, 'default': 'Server default'},
            'ou': {'value': '{{ domain.organization_unit }}'},
        },
    }
    attributes = decode_attributes(build_csrattrs(profile))
    assert {str(item['oid']) for item in attributes} == {'2.5.4.3', '2.5.4.5'}


def test_extension_values_use_one_extensions_sequence():
    profile = {
        'type': 'cert_profile',
        'ext': {
            'san': {'critical': True, 'dns_names': {'value': ['device.example.com']}},
            'basic_constraints': {'ca': False},
            'crl_distribution_points': {'uris': {'value': ['http://{issuing_ca.id}/crl']}},
        },
    }
    attributes = decode_attributes(build_csrattrs(profile))
    assert len(attributes) == 1
    attribute = attributes[0]['attribute']
    assert str(attribute['type']) == EXTENSION_REQUEST_OID
    assert len(attribute['values']) == 1
    extensions, remainder = decoder.decode(attribute['values'][0].asOctets(), asn1Spec=rfc5280.Extensions())
    assert not remainder
    assert {str(ext['extnID']) for ext in extensions} == {'2.5.29.17', '2.5.29.19'}
    san = next(ext for ext in extensions if str(ext['extnID']) == '2.5.29.17')
    names, remainder = decoder.decode(san['extnValue'].asOctets(), asn1Spec=rfc5280.SubjectAltName())
    assert not remainder
    assert bool(san['critical'])
    assert str(names[0]['dNSName']) == 'device.example.com'


def test_client_supplied_extensions_request_oid_without_placeholder_values():
    profile = {'type': 'cert_profile', 'ext': {'san': {'ip_addresses': {'required': True}}}}
    attributes = decode_attributes(build_csrattrs(profile))
    assert len(attributes) == 1
    assert str(attributes[0]['oid']) == EXTENSION_REQUEST_OID


@pytest.mark.parametrize('profile', [None, {'type': 'cert_profile'}])
def test_no_requirements_encode_empty_sequence(profile):
    assert build_csrattrs(profile) == b'\x30\x00'


@pytest.mark.parametrize('path', ['csrattrs', '~tls_server/csrattrs'])
def test_required_channel_binding_is_advertised(client, settings, path):
    """The policy is discoverable even without a selected profile."""
    settings.TRUSTPOINT_EST_REQUIRE_CHANNEL_BINDING = True
    if path.startswith('~'):
        CertificateProfileModel.objects.create(unique_name='tls_server', profile_json={'type': 'cert_profile'})
    response = client.get('/.well-known/est/' + path)
    assert response.status_code == 200
    attributes = decode_attributes(base64.b64decode(response.content))
    assert len(attributes) == 1
    assert str(attributes[0]['oid']) == '1.2.840.113549.1.9.7'


@pytest.fixture
def csrattrs_profile(domain_instance):
    profile = CertificateProfileModel.objects.create(
        unique_name='csrattrs-test',
        profile_json={'type': 'cert_profile', 'subj': {'serial_number': {'required': True}}},
    )
    domain = domain_instance['domain']
    DomainAllowedCertificateProfileModel.objects.create(domain=domain, certificate_profile=profile, alias='attrs-alias')
    domain.domain_credential_profile = profile
    domain.save()
    return domain, profile


@pytest.mark.parametrize('trailing_slash', ['', '/'])
@pytest.mark.parametrize('selection', ['default', 'profile', 'domain', 'domain-profile', 'alias'])
def test_csrattrs_routes_and_profile_selection(client, csrattrs_profile, selection, trailing_slash):
    domain, profile = csrattrs_profile
    prefixes = {
        'default': '',
        'profile': f'~{profile.unique_name}/',
        'domain': f'{domain.unique_name}/',
        'domain-profile': f'{domain.unique_name}/{profile.unique_name}/',
        'alias': f'{domain.unique_name}/attrs-alias/',
    }
    path = f'/.well-known/est/{prefixes[selection]}csrattrs{trailing_slash}'
    assert resolve(path).func.view_class is EstCsrAttrsView
    response = client.get(path)
    assert response.status_code == 200
    assert response['Content-Type'] == 'application/csrattrs'
    assert 'Location' not in response
    assert 'Content-Transfer-Encoding' not in response
    attributes = decode_attributes(base64.b64decode(response.content, validate=True))
    assert {str(item['oid']) for item in attributes} == (set() if selection == 'default' else {'2.5.4.5'})


def test_unavailable_profiles_and_domains_return_404(client, csrattrs_profile):
    domain, profile = csrattrs_profile
    assert client.get('/.well-known/est/missing/csrattrs').status_code == 404
    assert client.get('/.well-known/est/~missing/csrattrs').status_code == 404
    assert client.get(f'/.well-known/est/{domain.unique_name}/missing/csrattrs').status_code == 404
    domain.certificate_profiles.all().delete()
    assert client.get(f'/.well-known/est/{domain.unique_name}/{profile.unique_name}/csrattrs').status_code == 404
    domain.is_active = False
    domain.save()
    assert client.get(f'/.well-known/est/{domain.unique_name}/csrattrs').status_code == 404


def test_csrattrs_rejects_post(client):
    assert client.post('/.well-known/est/csrattrs').status_code == 405


def test_malformed_profile_is_server_error(client, csrattrs_profile):
    domain, profile = csrattrs_profile
    profile.profile_json = {'type': 'invalid'}
    profile.save()
    response = client.get(f'/.well-known/est/{domain.unique_name}/csrattrs')
    assert response.status_code == 500
    assert response.content == b'Error retrieving CSR attributes.'
