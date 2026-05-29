"""Tests for TlsServerCredentialFileParser in setup_wizard.tls_credential."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from trustpoint_core.serializer import PrivateKeySerializer

from setup_wizard.tls_credential import TlsServerCredentialFileParser


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------


def _make_ca(common_name: str = 'Test CA') -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Return a self-signed CA key+cert pair."""
    key = ec.generate_private_key(curve=ec.SECP256R1())
    now = datetime.datetime.now(tz=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_tls_server(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    common_name: str = 'Test TLS Server',
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Return an end-entity TLS server key+cert pair signed by the given CA."""
    server_key = ec.generate_private_key(curve=ec.SECP256R1())
    now = datetime.datetime.now(tz=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return server_key, cert


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _key_pem_encrypted(key: ec.EllipticCurvePrivateKey, password: str) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(password.encode()),
    )


def _build_pkcs12(
    server_key: ec.EllipticCurvePrivateKey,
    server_cert: x509.Certificate,
    ca_certs: list[x509.Certificate],
    password: bytes | None = None,
) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        name=b'test',
        key=server_key,
        cert=server_cert,
        cas=ca_certs,
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# _encode_password
# ---------------------------------------------------------------------------


class TestEncodePassword:
    """Tests for TlsServerCredentialFileParser._encode_password."""

    def test_none_returns_none(self) -> None:
        """None input yields None output."""
        assert TlsServerCredentialFileParser._encode_password(None, 'field') is None

    def test_empty_string_returns_none(self) -> None:
        """Empty string is treated as no password."""
        assert TlsServerCredentialFileParser._encode_password('', 'field') is None

    def test_valid_string_returns_utf8_bytes(self) -> None:
        """Non-empty string returns its UTF-8 encoding."""
        result = TlsServerCredentialFileParser._encode_password('secret', 'field')
        assert result == b'secret'

    def test_unicode_string_is_encoded(self) -> None:
        """Unicode characters are encoded correctly."""
        result = TlsServerCredentialFileParser._encode_password('pässwort', 'field')
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# _parse_certificates
# ---------------------------------------------------------------------------


class TestParseCertificates:
    """Tests for TlsServerCredentialFileParser._parse_certificates."""

    def test_single_pem_certificate(self) -> None:
        """Parses a single PEM certificate into a one-element list."""
        _, ca_cert = _make_ca()
        result = TlsServerCredentialFileParser._parse_certificates(_cert_pem(ca_cert))
        assert len(result) == 1
        assert isinstance(result[0], x509.Certificate)

    def test_single_der_certificate(self) -> None:
        """Parses a single DER certificate into a one-element list."""
        _, ca_cert = _make_ca()
        result = TlsServerCredentialFileParser._parse_certificates(_cert_der(ca_cert))
        assert len(result) == 1

    def test_multiple_pem_certificates(self) -> None:
        """Parses a concatenated PEM bundle into multiple certificates."""
        _, ca_cert = _make_ca()
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        bundle = _cert_pem(server_cert) + _cert_pem(ca_cert)
        result = TlsServerCredentialFileParser._parse_certificates(bundle)
        assert len(result) == 2

    def test_invalid_bytes_raises_value_error(self) -> None:
        """Garbage bytes raise ValueError."""
        with pytest.raises(ValueError, match='Failed to parse the certificate file'):
            TlsServerCredentialFileParser._parse_certificates(b'not a certificate')


# ---------------------------------------------------------------------------
# _is_ca_certificate
# ---------------------------------------------------------------------------


class TestIsCaCertificate:
    """Tests for TlsServerCredentialFileParser._is_ca_certificate."""

    def test_ca_certificate_returns_true(self) -> None:
        """CA certificate (BasicConstraints ca=True) returns True."""
        _, ca_cert = _make_ca()
        assert TlsServerCredentialFileParser._is_ca_certificate(ca_cert) is True

    def test_end_entity_certificate_returns_false(self) -> None:
        """End-entity certificate (BasicConstraints ca=False) returns False."""
        ca_key, ca_cert = _make_ca()
        _, server_cert = _make_tls_server(ca_key, ca_cert)
        assert TlsServerCredentialFileParser._is_ca_certificate(server_cert) is False

    def test_certificate_without_basic_constraints_returns_false(self) -> None:
        """Certificate with no BasicConstraints extension returns False."""
        key = ec.generate_private_key(curve=ec.SECP256R1())
        now = datetime.datetime.now(tz=datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'No BC')]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'No BC')]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        assert TlsServerCredentialFileParser._is_ca_certificate(cert) is False


# ---------------------------------------------------------------------------
# _is_tls_server_certificate
# ---------------------------------------------------------------------------


class TestIsTlsServerCertificate:
    """Tests for TlsServerCredentialFileParser._is_tls_server_certificate."""

    def test_valid_tls_server_cert_returns_true(self) -> None:
        """End-entity cert with SERVER_AUTH EKU returns True."""
        ca_key, ca_cert = _make_ca()
        _, server_cert = _make_tls_server(ca_key, ca_cert)
        assert TlsServerCredentialFileParser._is_tls_server_certificate(server_cert) is True

    def test_ca_certificate_returns_false(self) -> None:
        """CA cert is never a valid TLS server cert."""
        _, ca_cert = _make_ca()
        assert TlsServerCredentialFileParser._is_tls_server_certificate(ca_cert) is False

    def test_end_entity_without_eku_returns_false(self) -> None:
        """End-entity cert without ExtendedKeyUsage returns False."""
        ca_key, ca_cert = _make_ca()
        key = ec.generate_private_key(curve=ec.SECP256R1())
        now = datetime.datetime.now(tz=datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'No EKU')]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        assert TlsServerCredentialFileParser._is_tls_server_certificate(cert) is False


# ---------------------------------------------------------------------------
# _get_single_end_entity_certificate
# ---------------------------------------------------------------------------


class TestGetSingleEndEntityCertificate:
    """Tests for TlsServerCredentialFileParser._get_single_end_entity_certificate."""

    def test_returns_single_ee_cert(self) -> None:
        """Returns the single end-entity certificate when exactly one is present."""
        ca_key, ca_cert = _make_ca()
        _, server_cert = _make_tls_server(ca_key, ca_cert)
        result = TlsServerCredentialFileParser._get_single_end_entity_certificate([ca_cert, server_cert])
        assert result == server_cert

    def test_raises_when_no_end_entity_certificate(self) -> None:
        """Raises ValueError when only CA certs are supplied."""
        _, ca_cert = _make_ca()
        with pytest.raises(ValueError, match='Expected exactly one end-entity'):
            TlsServerCredentialFileParser._get_single_end_entity_certificate([ca_cert])

    def test_raises_when_multiple_end_entity_certificates(self) -> None:
        """Raises ValueError when more than one end-entity cert is supplied."""
        ca_key, ca_cert = _make_ca()
        _, server_cert1 = _make_tls_server(ca_key, ca_cert)
        _, server_cert2 = _make_tls_server(ca_key, ca_cert)
        with pytest.raises(ValueError, match='Expected exactly one end-entity'):
            TlsServerCredentialFileParser._get_single_end_entity_certificate([server_cert1, server_cert2])

    def test_raises_when_ee_cert_is_not_tls_server(self) -> None:
        """Raises ValueError when the only EE cert lacks SERVER_AUTH EKU."""
        ca_key, ca_cert = _make_ca()
        key = ec.generate_private_key(curve=ec.SECP256R1())
        now = datetime.datetime.now(tz=datetime.UTC)
        non_tls_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Non TLS')]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        with pytest.raises(ValueError, match='not a valid TLS server certificate'):
            TlsServerCredentialFileParser._get_single_end_entity_certificate([non_tls_cert])


# ---------------------------------------------------------------------------
# _match_private_key
# ---------------------------------------------------------------------------


class TestMatchPrivateKey:
    """Tests for TlsServerCredentialFileParser._match_private_key."""

    def test_matching_key_does_not_raise(self) -> None:
        """Matching private key and certificate passes without error."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        private_key_serializer = PrivateKeySerializer(server_key)
        TlsServerCredentialFileParser._match_private_key(private_key_serializer, server_cert)  # must not raise

    def test_mismatching_key_raises_value_error(self) -> None:
        """Mismatching private key raises ValueError."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        other_key = ec.generate_private_key(curve=ec.SECP256R1())
        private_key_serializer = PrivateKeySerializer(other_key)
        with pytest.raises(ValueError, match='does not match'):
            TlsServerCredentialFileParser._match_private_key(private_key_serializer, server_cert)


# ---------------------------------------------------------------------------
# _build_certificate_chain
# ---------------------------------------------------------------------------


class TestBuildCertificateChain:
    """Tests for TlsServerCredentialFileParser._build_certificate_chain."""

    def test_valid_chain_ee_plus_root(self) -> None:
        """Returns chain [ee_cert, ca_cert] when a direct trust chain exists."""
        ca_key, ca_cert = _make_ca()
        _, server_cert = _make_tls_server(ca_key, ca_cert)
        chain = TlsServerCredentialFileParser._build_certificate_chain(server_cert, [ca_cert])
        assert chain[0] == server_cert
        assert chain[-1] == ca_cert

    def test_raises_when_non_ca_in_additional_certs(self) -> None:
        """Raises ValueError when a non-CA cert is included in additional_certificates."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        _, another_server_cert = _make_tls_server(ca_key, ca_cert)
        with pytest.raises(ValueError, match='Only CA certificates'):
            TlsServerCredentialFileParser._build_certificate_chain(server_cert, [another_server_cert])

    def test_raises_when_chain_cannot_be_built(self) -> None:
        """Raises ValueError when no valid chain path exists."""
        ca_key, ca_cert = _make_ca()
        _, server_cert = _make_tls_server(ca_key, ca_cert)
        _, unrelated_ca_cert = _make_ca('Unrelated CA')
        with pytest.raises(ValueError, match='full chain'):
            TlsServerCredentialFileParser._build_certificate_chain(server_cert, [unrelated_ca_cert])


# ---------------------------------------------------------------------------
# build_from_pkcs12_bytes
# ---------------------------------------------------------------------------


class TestBuildFromPkcs12Bytes:
    """Tests for TlsServerCredentialFileParser.build_from_pkcs12_bytes."""

    def test_valid_pkcs12_without_password(self) -> None:
        """Parses a valid unencrypted PKCS#12 file and returns a CredentialSerializer."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        pkcs12_bytes = _build_pkcs12(server_key, server_cert, [ca_cert])

        result = TlsServerCredentialFileParser.build_from_pkcs12_bytes(pkcs12_bytes)

        assert result is not None
        assert result.certificate is not None

    def test_valid_pkcs12_with_password(self) -> None:
        """Parses a valid password-protected PKCS#12 file."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        password = 'test-password'
        pkcs12_bytes = _build_pkcs12(server_key, server_cert, [ca_cert], password=password.encode())

        result = TlsServerCredentialFileParser.build_from_pkcs12_bytes(pkcs12_bytes, pkcs12_password=password)

        assert result is not None
        assert result.certificate is not None

    def test_wrong_password_raises_value_error(self) -> None:
        """Wrong PKCS#12 password raises ValueError."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        pkcs12_bytes = _build_pkcs12(server_key, server_cert, [ca_cert], password=b'correct-password')

        with pytest.raises(ValueError, match='Failed to parse and load'):
            TlsServerCredentialFileParser.build_from_pkcs12_bytes(pkcs12_bytes, pkcs12_password='wrong-password')

    def test_invalid_bytes_raises_value_error(self) -> None:
        """Garbage bytes raise ValueError."""
        with pytest.raises(ValueError, match='Failed to parse and load'):
            TlsServerCredentialFileParser.build_from_pkcs12_bytes(b'not a pkcs12 file')


# ---------------------------------------------------------------------------
# build_from_separate_files
# ---------------------------------------------------------------------------


class TestBuildFromSeparateFiles:
    """Tests for TlsServerCredentialFileParser.build_from_separate_files."""

    def test_valid_separate_files(self) -> None:
        """Parses valid separate certificate, chain, and key files."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)

        result = TlsServerCredentialFileParser.build_from_separate_files(
            tls_server_certificate_raw=_cert_pem(server_cert),
            further_certificates_raw=[_cert_pem(ca_cert)],
            key_file_raw=_key_pem(server_key),
        )

        assert result is not None
        assert result.certificate is not None

    def test_encrypted_key_with_correct_password(self) -> None:
        """Correctly decrypts an encrypted private key file."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)
        password = 'secret123'

        result = TlsServerCredentialFileParser.build_from_separate_files(
            tls_server_certificate_raw=_cert_pem(server_cert),
            further_certificates_raw=[_cert_pem(ca_cert)],
            key_file_raw=_key_pem_encrypted(server_key, password),
            key_password=password,
        )

        assert result is not None

    def test_encrypted_key_with_wrong_password_raises(self) -> None:
        """Wrong key password raises ValueError."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)

        with pytest.raises(ValueError, match='Failed to parse the private key file'):
            TlsServerCredentialFileParser.build_from_separate_files(
                tls_server_certificate_raw=_cert_pem(server_cert),
                further_certificates_raw=[_cert_pem(ca_cert)],
                key_file_raw=_key_pem_encrypted(server_key, 'correct'),
                key_password='wrong',
            )

    def test_invalid_key_bytes_raises(self) -> None:
        """Garbage key bytes raise ValueError."""
        ca_key, ca_cert = _make_ca()
        _, server_cert = _make_tls_server(ca_key, ca_cert)

        with pytest.raises(ValueError, match='Failed to parse the private key file'):
            TlsServerCredentialFileParser.build_from_separate_files(
                tls_server_certificate_raw=_cert_pem(server_cert),
                further_certificates_raw=[_cert_pem(ca_cert)],
                key_file_raw=b'not a key',
            )

    def test_mismatched_key_raises(self) -> None:
        """A key that does not match the certificate raises ValueError."""
        ca_key, ca_cert = _make_ca()
        _, server_cert = _make_tls_server(ca_key, ca_cert)
        unrelated_key = ec.generate_private_key(curve=ec.SECP256R1())

        with pytest.raises(ValueError, match='does not match'):
            TlsServerCredentialFileParser.build_from_separate_files(
                tls_server_certificate_raw=_cert_pem(server_cert),
                further_certificates_raw=[_cert_pem(ca_cert)],
                key_file_raw=_key_pem(unrelated_key),
            )

    def test_no_further_certificates_without_chain_raises(self) -> None:
        """Raises ValueError when no CA cert is provided and the chain cannot be built."""
        ca_key, ca_cert = _make_ca()
        server_key, server_cert = _make_tls_server(ca_key, ca_cert)

        with pytest.raises(ValueError, match='full chain'):
            TlsServerCredentialFileParser.build_from_separate_files(
                tls_server_certificate_raw=_cert_pem(server_cert),
                further_certificates_raw=[],
                key_file_raw=_key_pem(server_key),
            )
