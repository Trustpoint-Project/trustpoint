# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Live HTTPS checks for the enrollment-endpoints workflow's EST discovery APIs.

Set EST_DISCOVERY_BASE_URL, ENV_FILE and TLS_CERT to run against the server created
by that workflow. These tests do not access Django's database directly.
"""

import base64
import json
import os
from pathlib import Path
from urllib.parse import quote

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1_modules import rfc2986, rfc5280


@pytest.fixture(scope='module')
def est_environment():
    base_url = os.environ.get('EST_DISCOVERY_BASE_URL')
    if not base_url:
        pytest.skip('Set EST_DISCOVERY_BASE_URL to test a running HTTPS server.')
    assert base_url.startswith('https://')
    est = json.loads(Path(os.environ['ENV_FILE']).read_text())['protocols']['est']
    return {
        'base_url': base_url.rstrip('/') + '/.well-known/est/',
        'tls_cert': str(Path(os.environ['TLS_CERT']).resolve()),
        'domain': quote(est['domain'], safe=''),
        'ca': est['ca'],
        'domain_profile': quote(est['domain_credential_profile'], safe=''),
    }


@pytest.fixture(scope='module')
def est_get(est_environment):
    reports = Path(os.environ.get('EST_DISCOVERY_REPORT_DIR', 'reports/est-discovery'))
    reports.mkdir(parents=True, exist_ok=True)
    with requests.Session() as session:
        # Discovery is public; prevent local netrc credentials from masking failures.
        session.trust_env = False

        def get(path, expected_status=200, content_type=None):
            response = session.get(
                est_environment['base_url'] + path,
                verify=est_environment['tls_cert'],
                allow_redirects=False,
                timeout=30,
            )
            artifact = path.replace('/', '_') + ('slash' if path.endswith('/') else '')
            (reports / f'{artifact}.body').write_bytes(response.content)
            (reports / f'{artifact}.json').write_text(
                json.dumps(
                    {
                        'url': response.url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type'),
                        'location': response.headers.get('Location'),
                    },
                    indent=2,
                )
            )
            assert response.status_code == expected_status, f'{path}: {response.status_code}: {response.text[:200]}'
            assert 'Location' not in response.headers
            if content_type:
                assert response.headers['Content-Type'].split(';', 1)[0] == content_type
            return response

        yield get


def decode_base64(response):
    # Both wrapped and unwrapped Base64 are valid EST responses.
    return base64.b64decode(b''.join(response.content.split()), validate=True)


def get_ca_certificates(est_get, path):
    response = est_get(path, content_type='application/pkcs7-mime')
    certificates = load_der_pkcs7_certificates(decode_base64(response))
    assert certificates
    fingerprints = [certificate.fingerprint(hashes.SHA256()) for certificate in certificates]
    assert len(fingerprints) == len(set(fingerprints)), 'Duplicate certificates in CA response'
    for certificate in certificates:
        assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    return certificates


@pytest.mark.parametrize('suffix', ['', '/'])
def test_default_cacerts_contains_domain_chain(est_get, est_environment, suffix):
    default = get_ca_certificates(est_get, 'cacerts' + suffix)
    scoped = get_ca_certificates(est_get, est_environment['domain'] + '/cacerts' + suffix)
    assert set(scoped).issubset(set(default))
    common_names = {
        name.value
        for certificate in scoped
        for name in certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    }
    assert est_environment['ca'] in common_names
    assert est_environment['ca'] + '-root' in common_names


@pytest.mark.parametrize('suffix', ['', '/'])
def test_default_csrattrs_is_empty_sequence(est_get, suffix):
    response = est_get('csrattrs' + suffix, content_type='application/csrattrs')
    assert decode_base64(response) == b'\x30\x00'
    assert 'Content-Transfer-Encoding' not in response.headers


@pytest.mark.parametrize('suffix', ['', '/'])
@pytest.mark.parametrize('selection', ['profile', 'domain', 'domain-profile'])
def test_profile_csrattrs_extension_values(est_get, est_environment, selection, suffix):
    domain = est_environment['domain']
    prefixes = {'profile': '~tls_server/', 'domain': domain + '/', 'domain-profile': domain + '/tls_server/'}
    response = est_get(prefixes[selection] + 'csrattrs' + suffix, content_type='application/csrattrs')
    if selection == 'domain':
        explicit_default = est_get(
            domain + '/' + est_environment['domain_profile'] + '/csrattrs' + suffix,
            content_type='application/csrattrs',
        )
        assert decode_base64(response) == decode_base64(explicit_default)
    # Decode using the RFC schemas, independently of the server's CsrAttrs class.
    attributes, remainder = decoder.decode(decode_base64(response), asn1Spec=univ.SequenceOf(componentType=univ.Any()))
    assert not remainder
    extension_requests = []
    for encoded in attributes:
        value, remainder = decoder.decode(encoded.asOctets())
        assert not remainder
        if isinstance(value, univ.ObjectIdentifier):
            continue
        attribute, remainder = decoder.decode(encoded.asOctets(), asn1Spec=rfc2986.Attribute())
        assert not remainder
        if str(attribute['type']) == '1.2.840.113549.1.9.14':
            assert len(attribute['values']) == 1
            extensions, remainder = decoder.decode(attribute['values'][0].asOctets(), asn1Spec=rfc5280.Extensions())
            assert not remainder
            extension_requests.append({str(ext['extnID']): ext for ext in extensions})
    assert len(extension_requests) == 1
    extensions = extension_requests[0]
    constraints, remainder = decoder.decode(extensions['2.5.29.19']['extnValue'], asn1Spec=rfc5280.BasicConstraints())
    assert not remainder
    assert not bool(constraints['cA'])
    if selection != 'domain':
        usages, remainder = decoder.decode(extensions['2.5.29.37']['extnValue'], asn1Spec=rfc5280.ExtKeyUsageSyntax())
        assert not remainder
        assert '1.3.6.1.5.5.7.3.1' in {str(oid) for oid in usages}
        names, remainder = decoder.decode(extensions['2.5.29.17']['extnValue'], asn1Spec=rfc5280.SubjectAltName())
        assert not remainder
        assert any(name.getName() == 'dNSName' and str(name['dNSName']) == 'localhost' for name in names)


@pytest.mark.parametrize('path', ['does-not-exist/csrattrs', '~does-not-exist/csrattrs'])
def test_unknown_csrattrs_selection_returns_404(est_get, path):
    est_get(path, expected_status=404)


def test_profile_not_available_in_domain_returns_404(est_get, est_environment):
    est_get(est_environment['domain'] + '/does-not-exist/csrattrs', expected_status=404)
