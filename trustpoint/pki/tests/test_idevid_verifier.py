"""Tests for the IDevID verifier."""

from unittest.mock import MagicMock

import pytest
from cryptography import x509

from pki.util.idevid import IDevIDVerifier
from pki.util.x509 import CertificateGenerator


def get_mock_truststore(certificates: list[x509.Certificate]) -> MagicMock:
    """Get a mock truststore for testing."""
    ts = MagicMock()
    ts.unique_name = 'test_mock_truststore'
    ts.get_certificate_collection_serializer.return_value.as_crypto.return_value = certificates
    return ts

def test_tls_client_cert_verification() -> None:
    """Tests the TLS client certificate verification with the direct Issuing CA in the Truststore."""
    certs, _keys = CertificateGenerator.create_test_pki(1)
    truststore = get_mock_truststore([certs[0]])
    assert IDevIDVerifier.verify_idevid_against_truststore(certs[1], [], truststore)

def test_tls_client_cert_verification_self_signed() -> None:
    """Tests the TLS client certificate verification with a self-signed client certificate."""
    certs, _keys = CertificateGenerator.create_test_pki(0)
    truststore = get_mock_truststore([certs[0]])
    assert IDevIDVerifier.verify_idevid_against_truststore(certs[0], [], truststore)

def test_tls_client_cert_verification_not_in_truststore() -> None:
    """Tests the TLS client certificate verification fails if no matching certificate in the Truststore."""
    different_pki_root, _key = CertificateGenerator.create_root_ca('Different Root CA')
    truststore = get_mock_truststore([different_pki_root])
    certs, _keys = CertificateGenerator.create_test_pki(1)
    assert not IDevIDVerifier.verify_idevid_against_truststore(certs[1], [], truststore)

@pytest.mark.parametrize('client_includes_root_ca', [True, False])
def test_tls_client_cert_verification_chain(client_includes_root_ca: bool) -> None:  # noqa: FBT001
    """Tests the TLS client certificate verification with an intermediate CA."""
    certs, _keys = CertificateGenerator.create_test_pki(2)
    truststore = get_mock_truststore([certs[0]])
    intermediates = [certs[1], certs[0]] if client_includes_root_ca else [certs[1]]
    assert IDevIDVerifier.verify_idevid_against_truststore(certs[2], intermediates, truststore)

def test_tls_client_cert_chain_too_long() -> None:
    """Tests the TLS client certificate verification fails with a too long chain."""
    certs, _keys = CertificateGenerator.create_test_pki(4)
    truststore = get_mock_truststore([certs[0]])
    intermediates = [certs[3], certs[2], certs[1]]
    assert not IDevIDVerifier.verify_idevid_against_truststore(certs[4], intermediates, truststore)

def test_tls_client_cert_idevid_in_truststore() -> None:
    """Tests that verification works with just the IDevID directly in the Truststore (not the CA)."""
    certs, _keys = CertificateGenerator.create_test_pki(1)
    truststore = get_mock_truststore([certs[1]])
    assert IDevIDVerifier.verify_idevid_against_truststore(certs[1], [], truststore)

def test_tls_client_cert_idevid_expired() -> None:
    """Tests that verification fails if the IDevID certificate is expired."""

def test_tls_client_cert_ca_expired() -> None:
    """Tests that verification fails if the CA certificate is expired."""

def test_tls_client_cert_attributes() -> None:
    """Tests that verification fails if the client cert has no subject serial number."""
