# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Live EST channel-binding checks for the enrollment-endpoints HTTPS server."""

import base64
import http.client
import ipaddress
import json
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from cryptography.x509.oid import AttributeOID


@dataclass
class EstResult:
    status: int
    body: bytes
    content_type: str
    csr: x509.CertificateSigningRequest
    binding: bytes


def build_bound_csr(binding):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'tls_server.local')])
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                x509.IPAddress(ipaddress.ip_address('::1')),
            ]
        ),
        critical=True,
    )
    return builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, base64.b64encode(binding)).sign(key, hashes.SHA256())


@pytest.fixture(scope='module')
def est_bound_request():
    base_url = os.environ.get('EST_DISCOVERY_BASE_URL')
    if not base_url:
        pytest.skip('Set EST_DISCOVERY_BASE_URL to test a running HTTPS server.')
    target = urlsplit(base_url)
    assert target.scheme == 'https'
    environment = json.loads(Path(os.environ['ENV_FILE']).read_text())['protocols']['est']
    domain = quote(environment['domain'], safe='')
    device = 'est-no-onboarding-device'
    password = environment['devices'][device]['est_password']
    authorization = 'Basic ' + base64.b64encode(f'{device}:{password}'.encode()).decode('ascii')
    reports = Path(os.environ.get('EST_BINDING_REPORT_DIR', 'reports/est-channel-binding'))
    reports.mkdir(parents=True, exist_ok=True)

    def send(label, *, transform=None, previous_csr=None, forged_headers=False, version=ssl.TLSVersion.TLSv1_2):
        context = ssl.create_default_context(cafile=os.environ['TLS_CERT'])
        context.minimum_version = version
        context.maximum_version = version
        connection = http.client.HTTPSConnection(target.hostname, target.port or 443, context=context, timeout=30)
        try:
            # The CSR must be generated after the handshake and sent over this
            # exact connection; a requests.post call could create another TLS session.
            connection.connect()
            assert connection.sock.version() == ('TLSv1.2' if version == ssl.TLSVersion.TLSv1_2 else 'TLSv1.3')
            actual_binding = connection.sock.get_channel_binding('tls-unique')
            binding = transform(actual_binding) if transform else actual_binding
            csr = previous_csr or build_bound_csr(binding)
            headers = {'Content-Type': 'application/pkcs10', 'Authorization': authorization}
            if forged_headers:
                headers.update(
                    {
                        'X-EST-TLS-Unique': base64.b64encode(binding).decode('ascii'),
                        'X-EST-TLS-Unique-Supported': '1',
                        'X-EST-TLS-Protocol': 'TLSv1.2',
                    }
                )
            connection.request(
                'POST',
                f'/.well-known/est/{domain}/tls_server/simpleenroll',
                body=base64.b64encode(csr.public_bytes(serialization.Encoding.DER)),
                headers=headers,
            )
            response = connection.getresponse()
            body = response.read()
            content_type = response.getheader('Content-Type', '')
            (reports / f'{label}.body').write_bytes(body)
            (reports / f'{label}.json').write_text(
                json.dumps(
                    {
                        'status': response.status,
                        'content_type': content_type,
                        'tls_version': connection.sock.version() if connection.sock else str(version),
                    },
                    indent=2,
                )
            )
            return EstResult(response.status, body, content_type, csr, actual_binding)
        finally:
            connection.close()

    return send


def assert_rejected(result):
    assert result.status == 400, f'Expected binding rejection, got {result.status}: {result.body[:200]!r}'
    assert result.content_type.split(';', 1)[0] == 'text/plain'
    assert b'channel-binding verification failed' in result.body


def test_matching_tls12_binding_enrolls_certificate(est_bound_request):
    result = est_bound_request('matching-tls12')
    assert result.status == 200, result.body[:200]
    assert result.content_type.split(';', 1)[0] == 'application/pkcs7-mime'
    certificates = load_der_pkcs7_certificates(base64.b64decode(b''.join(result.body.split()), validate=True))
    certificate = next(
        cert
        for cert in certificates
        if any(
            name.value == 'tls_server.local' for name in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        )
    )
    assert certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == result.csr.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_mismatched_tls12_binding_is_rejected(est_bound_request):
    result = est_bound_request('mismatched-tls12', transform=lambda binding: bytes([binding[0] ^ 1]) + binding[1:])
    assert_rejected(result)


def test_csr_bound_to_previous_connection_is_rejected(est_bound_request):
    original = est_bound_request('original-connection')
    assert original.status == 200, original.body[:200]
    replay = est_bound_request('replayed-connection', previous_csr=original.csr)
    assert replay.binding != original.binding
    assert_rejected(replay)


def test_forged_proxy_headers_cannot_override_direct_tls_socket(est_bound_request):
    result = est_bound_request(
        'forged-proxy-headers',
        transform=lambda binding: bytes([binding[0] ^ 1]) + binding[1:],
        forged_headers=True,
    )
    assert_rejected(result)


def test_tls13_does_not_accept_tls_unique_binding(est_bound_request):
    result = est_bound_request('unsupported-tls13', version=ssl.TLSVersion.TLSv1_3, transform=lambda _: b'0' * 12)
    assert_rejected(result)
