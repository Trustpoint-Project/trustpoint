"""Tests for X.509 generation, extraction, and verification helpers."""

from __future__ import annotations

import datetime
from typing import cast
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import VerificationError
from django.test import RequestFactory
from management.models import SecurityConfig

from pki.util.crl import generate_empty_crl
from pki.util.x509 import (
    CertificateGenerator,
    CertificateVerifier,
    ClientCertificateAuthenticationError,
    NginxTLSClientCertExtractor,
)


def test_create_root_and_issuing_ca_have_expected_hierarchy() -> None:
    """Generated roots and intermediates expose the expected hierarchy."""
    root, root_key = CertificateGenerator.create_root_ca('Test Root', validity_days=30)
    issuing, issuing_key = CertificateGenerator.create_issuing_ca(
        root_key, 'Test Root', 'Test Issuing', validity_days=15, path_length=0
    )

    assert root.subject == root.issuer
    assert issuing.issuer == root.subject
    assert issuing.subject != root.subject
    assert issuing.public_key().public_numbers() != root.public_key().public_numbers()
    assert issuing.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(
        ca=True, path_length=0
    )
    assert isinstance(issuing_key, rsa.RSAPrivateKey)


def test_create_ee_accepts_full_name_and_extensions() -> None:
    """End-entity generation preserves a full subject and supplied extensions."""
    root, root_key = CertificateGenerator.create_root_ca('Root')
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device.example')])
    san = x509.SubjectAlternativeName([x509.DNSName('device.example')])

    certificate, private_key = CertificateGenerator.create_ee(
        root_key, root.subject, subject, extensions=[(san, False)], validity_days=2
    )

    assert certificate.subject == subject
    assert certificate.issuer == root.subject
    assert certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == san
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert isinstance(private_key, rsa.RSAPrivateKey)


def test_create_test_pki_builds_requested_chain() -> None:
    """The test-PKI helper creates a root, intermediate, and leaf chain."""
    certificates, keys = CertificateGenerator.create_test_pki(chain_depth=2)

    assert len(certificates) == len(keys) == 3
    assert certificates[0].subject == certificates[0].issuer
    assert certificates[1].issuer == certificates[0].subject
    assert certificates[2].issuer == certificates[1].subject
    assert certificates[2].extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_create_ee_rejects_invalid_subject_type() -> None:
    """End-entity generation rejects subject values outside its public API."""
    root, root_key = CertificateGenerator.create_root_ca('Root')

    with pytest.raises(TypeError, match='subject_name'):
        CertificateGenerator.create_ee(root_key, root.subject, cast(str, 123))


def test_certificate_extractor_decodes_client_and_chain_certificates() -> None:
    """NGINX URL decoding returns the client certificate and chain."""
    root, root_key = CertificateGenerator.create_root_ca('Root')
    client_cert, _ = CertificateGenerator.create_ee(root_key, root.subject, 'client')
    request = RequestFactory().get(
        '/',
        HTTP_SSL_CLIENT_CERT=quote(client_cert.public_bytes(serialization.Encoding.PEM).decode()),
    )
    request.META['SSL_CLIENT_CERT_CHAIN_0'] = root.public_bytes(serialization.Encoding.PEM).decode()

    certificate, intermediates = NginxTLSClientCertExtractor.get_client_cert_as_x509(request)

    assert certificate.fingerprint(hashes.SHA256()) == client_cert.fingerprint(hashes.SHA256())
    assert [item.subject for item in intermediates] == [root.subject]


@pytest.mark.parametrize(
    ('meta', 'message'),
    [({}, 'Missing'), ({'HTTP_SSL_CLIENT_CERT': 'not-a-certificate'}, 'Invalid')],
)
def test_certificate_extractor_rejects_missing_or_invalid_client_certificate(
    meta: dict[str, str], message: str
) -> None:
    """Missing and malformed client headers raise the public extractor error."""
    request = RequestFactory().get('/')
    request.META.update(meta)

    with pytest.raises(ClientCertificateAuthenticationError, match=message):
        NginxTLSClientCertExtractor.get_client_cert_as_x509(request)


def test_certificate_extractor_rejects_invalid_intermediate() -> None:
    """Malformed NGINX chain entries are rejected."""
    root, root_key = CertificateGenerator.create_root_ca('Root')
    client_cert, _ = CertificateGenerator.create_ee(root_key, root.subject, 'client')
    request = RequestFactory().get(
        '/', HTTP_SSL_CLIENT_CERT=client_cert.public_bytes(serialization.Encoding.PEM).decode()
    )
    request.META['SSL_CLIENT_CERT_CHAIN_0'] = 'bad-chain'

    with pytest.raises(ClientCertificateAuthenticationError, match='CHAIN_0'):
        NginxTLSClientCertExtractor.get_client_cert_as_x509(request)


def test_verify_ca_cert_builds_and_validates_chain(settings) -> None:
    """CA verification builds a leaf-to-root chain under the active policy."""
    settings.TRUSTPOINT_SECURITY_MODE = 'permissive'
    root, root_key = CertificateGenerator.create_root_ca('Root')
    intermediate, _ = CertificateGenerator.create_issuing_ca(root_key, 'Root', 'Intermediate')

    SecurityConfig.objects.create(security_mode=True, rsa_minimum_key_size=2048)
    chain = CertificateVerifier.verify_ca_cert(intermediate, [root])

    assert [certificate.subject for certificate in chain] == [intermediate.subject, root.subject]


def test_verify_ca_cert_rejects_end_entity() -> None:
    """CA verification rejects certificates with BasicConstraints.ca false."""
    root, root_key = CertificateGenerator.create_root_ca('Root')
    leaf, _ = CertificateGenerator.create_ee(root_key, root.subject, 'leaf')

    with pytest.raises(ValueError, match='not a CA'):
        CertificateVerifier._check_ca_basic_constraints(leaf)


def test_verify_ca_cert_rejects_untrusted_chain(settings) -> None:
    """CA verification rejects a chain without a trusted root."""
    settings.TRUSTPOINT_SECURITY_MODE = 'permissive'
    root, root_key = CertificateGenerator.create_root_ca('Root')
    intermediate, _ = CertificateGenerator.create_issuing_ca(root_key, 'Root', 'Intermediate')

    SecurityConfig.objects.create(security_mode=True, rsa_minimum_key_size=2048)

    with pytest.raises(ValueError, match='valid certificate chain'):
        CertificateVerifier.verify_ca_cert(intermediate, trusted_roots=[])


def test_verify_signature_rejects_wrong_issuer() -> None:
    """Signature verification rejects a certificate signed by another issuer."""
    first, first_key = CertificateGenerator.create_root_ca('First')
    second, _ = CertificateGenerator.create_root_ca('Second')
    certificate, _ = CertificateGenerator.create_ee(first_key, first.subject, 'leaf')

    with pytest.raises(ValueError, match='signature verification failed'):
        CertificateVerifier._verify_cert_signature(certificate, second)


def test_generator_accepts_ec_key() -> None:
    """Certificate generation preserves a supplied EC private key."""
    key = ec.generate_private_key(ec.SECP256R1())
    certificate, generated_key = CertificateGenerator.create_root_ca('EC Root', private_key=key)

    assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
    assert generated_key is key


def test_generate_empty_crl_has_expected_metadata() -> None:
    """Empty CRLs contain issuer, number, and requested validity metadata."""
    root, root_key = CertificateGenerator.create_root_ca('Root')

    crl = x509.load_pem_x509_crl(
        generate_empty_crl(root, root_key, crl_validity_hours=12, crl_number=7).encode()
    )

    assert crl.issuer == root.subject
    assert len(crl) == 0
    assert crl.next_update_utc > crl.last_update_utc
    assert crl.next_update_utc - crl.last_update_utc == datetime.timedelta(hours=12)
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 7


def test_generate_empty_crl_rejects_invalid_hash_algorithm() -> None:
    """CRL generation rejects unsupported signing hash objects."""
    root, root_key = CertificateGenerator.create_root_ca('Root')

    with pytest.raises(TypeError, match='Hash algo'):
        generate_empty_crl(root, root_key, hash_algorithm=cast('hashes.HashAlgorithm', object()))


def test_verify_server_cert_validates_hostname_and_chain(settings) -> None:
    """Server verification validates both the hostname and trusted chain."""
    settings.TRUSTPOINT_SECURITY_MODE = 'permissive'
    root, root_key = CertificateGenerator.create_root_ca('Root')
    leaf, _ = CertificateGenerator.create_ee(
        root_key,
        root.subject,
        'server',
        extensions=[(x509.SubjectAlternativeName([x509.DNSName('server.example')]), False)],
    )

    SecurityConfig.objects.create(security_mode=True, rsa_minimum_key_size=2048)
    chain = CertificateVerifier.verify_server_cert(leaf, 'server.example', [root])

    assert [certificate.subject for certificate in chain] == [leaf.subject, root.subject]
    with pytest.raises(VerificationError):
        CertificateVerifier.verify_server_cert(leaf, 'other.example', [root])
