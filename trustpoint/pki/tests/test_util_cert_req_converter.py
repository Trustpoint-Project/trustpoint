"""Tests for pki.util.cert_req_converter module."""

from __future__ import annotations

import datetime
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pki.util.cert_req_converter import (
    JSONCertRequestCommandExtractor,
    JSONCertRequestConverter,
)


@pytest.fixture
def private_key() -> rsa.RSAPrivateKey:
    """Generate a test RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def basic_csr(private_key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
    """Create a basic CSR for testing."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
        ]
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr


class TestJSONCertRequestConverterSANValueToJson:
    """Test _san_value_to_json method."""

    def test_san_with_dns_names(self) -> None:
        """Test SAN conversion with DNS names."""
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName('example.com'),
                x509.DNSName('www.example.com'),
            ]
        )

        result = JSONCertRequestConverter._san_value_to_json(san)

        assert 'dns_names' in result
        assert result['dns_names'] == ['example.com', 'www.example.com']

    def test_san_with_rfc822_names(self) -> None:
        """Test SAN conversion with email addresses."""
        san = x509.SubjectAlternativeName(
            [
                x509.RFC822Name('test@example.com'),
                x509.RFC822Name('admin@example.com'),
            ]
        )

        result = JSONCertRequestConverter._san_value_to_json(san)

        assert 'rfc822_names' in result
        assert result['rfc822_names'] == ['test@example.com', 'admin@example.com']

    def test_san_with_uris(self) -> None:
        """Test SAN conversion with URIs."""
        san = x509.SubjectAlternativeName(
            [
                x509.UniformResourceIdentifier('https://example.com'),
                x509.UniformResourceIdentifier('https://www.example.com'),
            ]
        )

        result = JSONCertRequestConverter._san_value_to_json(san)

        assert 'uris' in result
        assert result['uris'] == ['https://example.com', 'https://www.example.com']

    def test_san_with_ip_addresses(self) -> None:
        """Test SAN conversion with IP addresses."""
        san = x509.SubjectAlternativeName(
            [
                x509.IPAddress(ipaddress.IPv4Address('192.168.1.1')),
                x509.IPAddress(ipaddress.IPv6Address('2001:db8::1')),
            ]
        )

        result = JSONCertRequestConverter._san_value_to_json(san)

        assert 'ip_addresses' in result
        assert '192.168.1.1' in result['ip_addresses']
        assert '2001:db8::1' in result['ip_addresses']

    def test_san_with_mixed_types(self) -> None:
        """Test SAN conversion with multiple types."""
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName('example.com'),
                x509.RFC822Name('test@example.com'),
                x509.IPAddress(ipaddress.IPv4Address('192.168.1.1')),
            ]
        )

        result = JSONCertRequestConverter._san_value_to_json(san)

        assert 'dns_names' in result
        assert 'rfc822_names' in result
        assert 'ip_addresses' in result


class TestJSONCertRequestConverterKUValueToJson:
    """Test _ku_value_to_json method."""

    def test_ku_digital_signature(self) -> None:
        """Test KeyUsage with digital_signature."""
        ku = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )

        result = JSONCertRequestConverter._ku_value_to_json(ku)

        assert result['digital_signature'] is True
        assert 'content_commitment' not in result

    def test_ku_key_agreement_with_encipher_only(self) -> None:
        """Test KeyUsage with key_agreement and encipher_only."""
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=True,
            decipher_only=False,
        )

        result = JSONCertRequestConverter._ku_value_to_json(ku)

        assert result['key_agreement'] is True
        assert result['encipher_only'] is True

    def test_ku_key_agreement_with_decipher_only(self) -> None:
        """Test KeyUsage with key_agreement and decipher_only."""
        ku = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True,
        )

        result = JSONCertRequestConverter._ku_value_to_json(ku)

        assert result['key_agreement'] is True
        assert result['decipher_only'] is True

    def test_ku_all_flags(self) -> None:
        """Test KeyUsage with all flags enabled."""
        ku = x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=True,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=True,
            decipher_only=True,
        )

        result = JSONCertRequestConverter._ku_value_to_json(ku)

        assert result['digital_signature'] is True
        assert result['content_commitment'] is True
        assert result['key_encipherment'] is True
        assert result['data_encipherment'] is True
        assert result['key_agreement'] is True
        assert result['key_cert_sign'] is True
        assert result['crl_sign'] is True


class TestJSONCertRequestConverterToJson:
    """Test to_json method."""

    def test_to_json_with_none_raises_error(self) -> None:
        """Test that to_json raises ValueError when CSR is None."""
        with pytest.raises(ValueError, match='CSR is None'):
            JSONCertRequestConverter.to_json(None)

    def test_to_json_basic_csr(self, basic_csr: x509.CertificateSigningRequest) -> None:
        """Test to_json with a basic CSR."""
        result = JSONCertRequestConverter.to_json(basic_csr)

        assert result['type'] == 'cert_request'
        assert 'subj' in result
        assert 'ext' in result
        assert NameOID.COMMON_NAME.dotted_string in result['subj']

    def test_to_json_csr_with_san(self, private_key: rsa.RSAPrivateKey) -> None:
        """Test to_json with CSR containing SAN extension."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com')])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName('example.com')]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        result = JSONCertRequestConverter.to_json(csr)

        assert 'san' in result['ext']
        assert 'dns_names' in result['ext']['san']

    def test_to_json_csr_with_key_usage(self, private_key: rsa.RSAPrivateKey) -> None:
        """Test to_json with CSR containing KeyUsage extension."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com')])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        result = JSONCertRequestConverter.to_json(csr)

        assert 'key_usage' in result['ext']
        assert result['ext']['key_usage']['digital_signature'] is True
        assert result['ext']['key_usage']['critical'] is True

    def test_to_json_csr_with_extended_key_usage(self, private_key: rsa.RSAPrivateKey) -> None:
        """Test to_json with CSR containing ExtendedKeyUsage extension."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com')])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        result = JSONCertRequestConverter.to_json(csr)

        assert 'extended_key_usage' in result['ext']
        assert 'server_auth' in result['ext']['extended_key_usage']['usages']
        assert 'client_auth' in result['ext']['extended_key_usage']['usages']

    def test_to_json_csr_with_basic_constraints_ca_raises_error(self, private_key: rsa.RSAPrivateKey) -> None:
        """Test to_json with CSR requesting CA certificate raises error."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com')])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        with pytest.raises(ValueError, match='Requesting CA certificates is not allowed'):
            JSONCertRequestConverter.to_json(csr)

    def test_to_json_with_certificate_builder(self, private_key: rsa.RSAPrivateKey) -> None:
        """Test to_json with CertificateBuilder instead of CSR."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com')])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        )

        result = JSONCertRequestConverter.to_json(builder)

        assert result['type'] == 'cert_request'
        assert 'subj' in result


class TestJSONCertRequestConverterValidityPeriodFromJson:
    """Test validity_period_from_json method."""

    def test_validity_with_duration(self) -> None:
        """Test parsing validity with duration in seconds."""
        validity = {'duration': 86400}  # 1 day

        result = JSONCertRequestConverter.validity_period_from_json(validity)

        assert result == datetime.timedelta(days=1)

    def test_validity_with_days(self) -> None:
        """Test parsing validity with days."""
        validity = {'days': 30}

        result = JSONCertRequestConverter.validity_period_from_json(validity)

        assert result == datetime.timedelta(days=30)

    def test_validity_with_hours(self) -> None:
        """Test parsing validity with hours."""
        validity = {'hours': 24}

        result = JSONCertRequestConverter.validity_period_from_json(validity)

        assert result == datetime.timedelta(hours=24)

    def test_validity_with_minutes(self) -> None:
        """Test parsing validity with minutes."""
        validity = {'minutes': 60}

        result = JSONCertRequestConverter.validity_period_from_json(validity)

        assert result == datetime.timedelta(minutes=60)

    def test_validity_with_seconds(self) -> None:
        """Test parsing validity with seconds."""
        validity = {'seconds': 3600}

        result = JSONCertRequestConverter.validity_period_from_json(validity)

        assert result == datetime.timedelta(seconds=3600)

    def test_validity_with_mixed_units(self) -> None:
        """Test parsing validity with multiple units."""
        validity = {'days': 1, 'hours': 2, 'minutes': 30, 'seconds': 45}

        result = JSONCertRequestConverter.validity_period_from_json(validity)

        expected = datetime.timedelta(days=1, hours=2, minutes=30, seconds=45)
        assert result == expected

    def test_validity_zero_raises_error(self) -> None:
        """Test that zero validity raises ValueError."""
        validity = {'days': 0}

        with pytest.raises(ValueError, match='Validity period must be specified'):
            JSONCertRequestConverter.validity_period_from_json(validity)


class TestJSONCertRequestConverterFromJson:
    """Test from_json method."""

    def test_from_json_basic(self) -> None:
        """Test from_json with basic subject."""
        json_data = {
            'type': 'cert_request',
            'subject': {'common_name': 'test.example.com'},
            'extensions': {},
            'validity': {'days': 30},
        }

        builder = JSONCertRequestConverter.from_json(json_data)

        assert isinstance(builder, x509.CertificateBuilder)

    def test_from_json_with_san(self) -> None:
        """Test from_json with SAN extension."""
        json_data = {
            'type': 'cert_request',
            'subject': {'common_name': 'test.example.com'},
            'extensions': {
                'subject_alternative_name': {
                    'dns_names': ['example.com', 'www.example.com'],
                    'critical': False,
                }
            },
            'validity': {'days': 30},
        }

        builder = JSONCertRequestConverter.from_json(json_data)

        assert isinstance(builder, x509.CertificateBuilder)

    def test_from_json_with_key_usage(self) -> None:
        """Test from_json with KeyUsage extension."""
        json_data = {
            'type': 'cert_request',
            'subject': {'common_name': 'test.example.com'},
            'extensions': {
                'key_usage': {
                    'digital_signature': True,
                    'key_encipherment': True,
                    'critical': True,
                }
            },
            'validity': {'days': 30},
        }

        builder = JSONCertRequestConverter.from_json(json_data)

        assert isinstance(builder, x509.CertificateBuilder)

    def test_from_json_with_extended_key_usage(self) -> None:
        """Test from_json with ExtendedKeyUsage extension."""
        json_data = {
            'type': 'cert_request',
            'subject': {'common_name': 'test.example.com'},
            'extensions': {
                'extended_key_usage': {
                    'usages': ['server_auth', 'client_auth'],
                    'critical': False,
                }
            },
            'validity': {'days': 30},
        }

        builder = JSONCertRequestConverter.from_json(json_data)

        assert isinstance(builder, x509.CertificateBuilder)

    def test_from_json_with_basic_constraints_ca_raises_error(self) -> None:
        """Test from_json with CA BasicConstraints raises error."""
        json_data = {
            'type': 'cert_request',
            'subject': {'common_name': 'test.example.com'},
            'extensions': {
                'basic_constraints': {
                    'ca': True,
                    'critical': True,
                }
            },
            'validity': {'days': 30},
        }

        with pytest.raises(ValueError, match='Requesting CA certificates is not allowed'):
            JSONCertRequestConverter.from_json(json_data)

    def test_from_json_with_crl_distribution_points(self) -> None:
        """Test from_json with CRL Distribution Points."""
        json_data = {
            'type': 'cert_request',
            'subject': {'common_name': 'test.example.com'},
            'extensions': {
                'crl_distribution_points': {
                    'uris': ['http://crl.example.com/ca.crl'],
                    'critical': False,
                }
            },
            'validity': {'days': 30},
        }

        builder = JSONCertRequestConverter.from_json(json_data)

        assert isinstance(builder, x509.CertificateBuilder)


class TestJSONCertRequestCommandExtractor:
    """Test JSONCertRequestCommandExtractor methods."""

    def test_sample_request_to_openssl_subj_basic(self) -> None:
        """Test converting subject to OpenSSL format."""
        sample_req = {
            'subject': {
                'common_name': 'test.example.com',
                'organization': 'Test Org',
                'country': 'US',
            }
        }

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_subj(sample_req)

        assert '/commonName=test.example.com' in result
        assert '/organization=Test Org' in result
        assert '/country=US' in result

    def test_sample_request_to_openssl_subj_empty(self) -> None:
        """Test converting empty subject to OpenSSL format."""
        sample_req = {'subject': {}}

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_subj(sample_req)

        assert result == '/'

    def test_sample_request_to_openssl_cmp_sans(self) -> None:
        """Test converting SANs to OpenSSL CMP format."""
        sample_req = {
            'extensions': {
                'subject_alternative_name': {
                    'dns_names': ['example.com', 'www.example.com'],
                    'uris': ['https://example.com'],
                    'critical': False,
                }
            }
        }

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_cmp_sans(sample_req)

        assert 'example.com' in result
        assert 'www.example.com' in result
        assert 'https://example.com' in result

    def test_sample_request_to_openssl_cmp_sans_critical(self) -> None:
        """Test converting critical SANs to OpenSSL CMP format."""
        sample_req = {
            'extensions': {
                'subject_alternative_name': {
                    'dns_names': ['example.com'],
                    'critical': True,
                }
            }
        }

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_cmp_sans(sample_req)

        assert result.startswith('critical,')

    def test_sample_request_to_openssl_req_sans(self) -> None:
        """Test converting SANs to OpenSSL req format."""
        sample_req = {
            'extensions': {
                'subject_alternative_name': {
                    'dns_names': ['example.com', 'www.example.com'],
                    'uris': ['https://example.com'],
                    'ip_addresses': ['192.168.1.1'],
                    'critical': False,
                }
            }
        }

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_req_sans(sample_req)

        assert 'DNS:example.com' in result
        assert 'DNS:www.example.com' in result
        assert 'URI:https://example.com' in result
        assert 'IP:192.168.1.1' in result

    def test_sample_request_to_openssl_req_sans_critical(self) -> None:
        """Test converting critical SANs to OpenSSL req format."""
        sample_req = {
            'extensions': {
                'subject_alternative_name': {
                    'dns_names': ['example.com'],
                    'critical': True,
                }
            }
        }

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_req_sans(sample_req)

        assert result.startswith('critical,')

    def test_sample_request_to_openssl_days(self) -> None:
        """Test extracting validity days."""
        sample_req = {'validity': {'days': 365}}

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_days(sample_req)

        assert result == 365

    def test_sample_request_to_openssl_days_from_duration(self) -> None:
        """Test extracting validity days from duration."""
        sample_req = {
            'validity': {'duration': 86400 * 30}  # 30 days
        }

        result = JSONCertRequestCommandExtractor.sample_request_to_openssl_days(sample_req)

        assert result == 30
