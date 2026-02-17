"""Tests for setup_wizard.tls_credential module."""

import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from setup_wizard.tls_credential import TlsServerCredentialGenerator


class TestTlsServerCredentialGenerator:
    """Test cases for TlsServerCredentialGenerator class."""

    def test_init_with_all_san_types(self):
        """Test initialization with IPv4, IPv6, and domain names."""
        ipv4_addresses = [ipaddress.IPv4Address('192.168.1.1'), ipaddress.IPv4Address('10.0.0.1')]
        ipv6_addresses = [ipaddress.IPv6Address('2001:db8::1'), ipaddress.IPv6Address('fe80::1')]
        domain_names = ['example.com', 'test.example.com']

        generator = TlsServerCredentialGenerator(
            ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses, domain_names=domain_names
        )

        assert generator._ipv4_addresses == ipv4_addresses
        assert generator._ipv6_addresses == ipv6_addresses
        assert generator._domain_names == domain_names

    def test_init_with_empty_lists(self):
        """Test initialization with empty SAN lists."""
        generator = TlsServerCredentialGenerator(ipv4_addresses=[], ipv6_addresses=[], domain_names=[])

        assert generator._ipv4_addresses == []
        assert generator._ipv6_addresses == []
        assert generator._domain_names == []

    def test_generate_key_pair(self):
        """Test static method _generate_key_pair generates EC key."""
        private_key_serializer = TlsServerCredentialGenerator._generate_key_pair()

        assert private_key_serializer is not None
        # Check it's an EC private key with SECP256R1 curve
        private_key = private_key_serializer._private_key
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert private_key.curve.name == 'secp256r1'

    def test_generate_tls_server_credential_basic(self):
        """Test generating TLS server credential with basic configuration."""
        ipv4_addresses = [ipaddress.IPv4Address('192.168.1.1')]
        domain_names = ['trustpoint.local']

        generator = TlsServerCredentialGenerator(
            ipv4_addresses=ipv4_addresses, ipv6_addresses=[], domain_names=domain_names
        )

        credential = generator.generate_tls_server_credential()

        assert credential is not None
        assert credential.private_key is not None
        assert credential.certificate is not None
        assert credential.additional_certificates is not None
        assert len(credential.additional_certificates) == 1

    def test_generate_tls_server_credential_certificate_properties(self):
        """Test the generated certificate has correct properties."""
        ipv4_addresses = [ipaddress.IPv4Address('10.0.0.1')]
        ipv6_addresses = [ipaddress.IPv6Address('2001:db8::1')]
        domain_names = ['example.com']

        generator = TlsServerCredentialGenerator(
            ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses, domain_names=domain_names
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        # Check subject and issuer
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert subject_cn == 'Trustpoint Self-Signed TLS Server Credential'
        assert issuer_cn == 'Trustpoint Self-Signed TLS Server Credential'

        # Check it's self-signed (subject == issuer)
        assert cert.subject == cert.issuer

    def test_generate_tls_server_credential_validity_period(self):
        """Test the certificate validity period is approximately 1 year."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')], ipv6_addresses=[], domain_names=['localhost']
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        # Check not_valid_before is approximately now (with 2 day tolerance for clock skew in cert)
        now = datetime.datetime.now(tz=datetime.UTC)
        not_before_diff = abs((cert.not_valid_before_utc - now).days)
        assert not_before_diff <= 2  # Certificate is backdated by 1 day for clock skew

        # Check not_valid_after is approximately 1 year from now
        expected_not_after = now + datetime.timedelta(days=365)
        not_after_diff = abs((cert.not_valid_after_utc - expected_not_after).days)
        assert not_after_diff <= 2  # Allow 2 days tolerance

    def test_generate_tls_server_credential_basic_constraints(self):
        """Test BasicConstraints extension is set correctly."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('192.168.1.1')], ipv6_addresses=[], domain_names=['test.com']
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints is not None
        assert basic_constraints.critical is False
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None

    def test_generate_tls_server_credential_key_usage(self):
        """Test KeyUsage extension has correct flags."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('10.0.0.1')], ipv6_addresses=[], domain_names=['example.com']
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage is not None
        assert key_usage.critical is True
        assert key_usage.value.digital_signature is True
        assert key_usage.value.key_agreement is True
        assert key_usage.value.content_commitment is False
        assert key_usage.value.key_encipherment is False
        assert key_usage.value.data_encipherment is False
        assert key_usage.value.key_cert_sign is False
        assert key_usage.value.crl_sign is False

    def test_generate_tls_server_credential_extended_key_usage(self):
        """Test ExtendedKeyUsage extension has SERVER_AUTH."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('172.16.0.1')], ipv6_addresses=[], domain_names=['server.local']
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        ext_key_usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ext_key_usage is not None
        assert ext_key_usage.critical is False
        assert ExtendedKeyUsageOID.SERVER_AUTH in ext_key_usage.value

    def test_generate_tls_server_credential_subject_alternative_name_ipv4_only(self):
        """Test SAN extension with IPv4 addresses only."""
        ipv4_addresses = [
            ipaddress.IPv4Address('192.168.1.1'),
            ipaddress.IPv4Address('192.168.1.2'),
            ipaddress.IPv4Address('10.0.0.1'),
        ]

        generator = TlsServerCredentialGenerator(ipv4_addresses=ipv4_addresses, ipv6_addresses=[], domain_names=[])

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san is not None
        assert san.critical is True

        # Check all IPv4 addresses are in SAN
        san_ips = [str(ip.value) for ip in san.value if isinstance(ip, x509.IPAddress)]
        assert len(san_ips) == 3
        assert '192.168.1.1' in san_ips
        assert '192.168.1.2' in san_ips
        assert '10.0.0.1' in san_ips

    def test_generate_tls_server_credential_subject_alternative_name_ipv6_only(self):
        """Test SAN extension with IPv6 addresses only."""
        ipv6_addresses = [
            ipaddress.IPv6Address('2001:db8::1'),
            ipaddress.IPv6Address('fe80::1'),
        ]

        generator = TlsServerCredentialGenerator(ipv4_addresses=[], ipv6_addresses=ipv6_addresses, domain_names=[])

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san is not None
        assert san.critical is True

        # Check all IPv6 addresses are in SAN
        san_ips = [str(ip.value) for ip in san.value if isinstance(ip, x509.IPAddress)]
        assert len(san_ips) == 2
        assert '2001:db8::1' in san_ips
        assert 'fe80::1' in san_ips

    def test_generate_tls_server_credential_subject_alternative_name_dns_only(self):
        """Test SAN extension with DNS names only."""
        domain_names = ['example.com', 'www.example.com', 'api.example.com']

        generator = TlsServerCredentialGenerator(ipv4_addresses=[], ipv6_addresses=[], domain_names=domain_names)

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san is not None
        assert san.critical is True

        # Check all DNS names are in SAN
        san_dns = [dns.value for dns in san.value if isinstance(dns, x509.DNSName)]
        assert len(san_dns) == 3
        assert 'example.com' in san_dns
        assert 'www.example.com' in san_dns
        assert 'api.example.com' in san_dns

    def test_generate_tls_server_credential_subject_alternative_name_mixed(self):
        """Test SAN extension with mixed IPv4, IPv6, and DNS names."""
        ipv4_addresses = [ipaddress.IPv4Address('192.168.1.1'), ipaddress.IPv4Address('10.0.0.1')]
        ipv6_addresses = [ipaddress.IPv6Address('2001:db8::1')]
        domain_names = ['trustpoint.local', 'www.trustpoint.local']

        generator = TlsServerCredentialGenerator(
            ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses, domain_names=domain_names
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san is not None
        assert san.critical is True

        # Check all entries are in SAN
        san_ips = [str(ip.value) for ip in san.value if isinstance(ip, x509.IPAddress)]
        san_dns = [dns.value for dns in san.value if isinstance(dns, x509.DNSName)]

        assert len(san_ips) == 3
        assert '192.168.1.1' in san_ips
        assert '10.0.0.1' in san_ips
        assert '2001:db8::1' in san_ips

        assert len(san_dns) == 2
        assert 'trustpoint.local' in san_dns
        assert 'www.trustpoint.local' in san_dns

    def test_generate_tls_server_credential_subject_key_identifier(self):
        """Test SubjectKeyIdentifier extension is present."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')], ipv6_addresses=[], domain_names=['localhost']
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski is not None
        assert ski.critical is False
        assert ski.value.digest is not None
        assert len(ski.value.digest) == 20  # SHA-1 hash is 160 bits = 20 bytes

    def test_generate_tls_server_credential_authority_key_identifier(self):
        """Test AuthorityKeyIdentifier extension is present."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')], ipv6_addresses=[], domain_names=['localhost']
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki is not None
        assert aki.critical is False
        assert aki.value.key_identifier is not None

    def test_generate_tls_server_credential_private_key_type(self):
        """Test the generated private key is EC P-256."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('192.168.1.1')], ipv6_addresses=[], domain_names=['example.com']
        )

        credential = generator.generate_tls_server_credential()
        private_key = credential.private_key

        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert private_key.curve.name == 'secp256r1'
        assert private_key.key_size == 256

    def test_generate_tls_server_credential_public_key_matches(self):
        """Test certificate public key matches private key."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('10.0.0.1')], ipv6_addresses=[], domain_names=['test.com']
        )

        credential = generator.generate_tls_server_credential()

        # Get public key from private key
        private_key_public = credential.private_key.public_key()
        cert_public = credential.certificate.public_key()

        # Compare public key numbers
        private_pub_numbers = private_key_public.public_numbers()
        cert_pub_numbers = cert_public.public_numbers()

        assert private_pub_numbers.x == cert_pub_numbers.x
        assert private_pub_numbers.y == cert_pub_numbers.y

    def test_generate_tls_server_credential_serial_number_unique(self):
        """Test each generated certificate has unique serial number."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('192.168.1.1')], ipv6_addresses=[], domain_names=['test.com']
        )

        credential1 = generator.generate_tls_server_credential()
        credential2 = generator.generate_tls_server_credential()

        # Serial numbers should be different (random)
        assert credential1.certificate.serial_number != credential2.certificate.serial_number

    def test_generate_tls_server_credential_additional_certificates(self):
        """Test additional_certificates contains the certificate itself."""
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')], ipv6_addresses=[], domain_names=['localhost']
        )

        credential = generator.generate_tls_server_credential()

        assert len(credential.additional_certificates) == 1
        # The additional certificate should be the same as the main certificate (self-signed)
        assert credential.additional_certificates[0] == credential.certificate

    def test_generate_tls_server_credential_with_many_sans(self):
        """Test generating credential with many SAN entries."""
        ipv4_addresses = [ipaddress.IPv4Address(f'192.168.1.{i}') for i in range(1, 11)]
        ipv6_addresses = [ipaddress.IPv6Address(f'2001:db8::{i}') for i in range(1, 6)]
        domain_names = [f'server{i}.example.com' for i in range(1, 8)]

        generator = TlsServerCredentialGenerator(
            ipv4_addresses=ipv4_addresses, ipv6_addresses=ipv6_addresses, domain_names=domain_names
        )

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

        # Should have 10 IPv4 + 5 IPv6 + 7 DNS = 22 total SAN entries
        assert len(list(san.value)) == 22

    def test_generate_tls_server_credential_empty_sans(self):
        """Test generating credential with no SAN entries (edge case)."""
        generator = TlsServerCredentialGenerator(ipv4_addresses=[], ipv6_addresses=[], domain_names=[])

        credential = generator.generate_tls_server_credential()
        cert = credential.certificate

        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san is not None
        # SAN should be empty but present
        assert len(list(san.value)) == 0
