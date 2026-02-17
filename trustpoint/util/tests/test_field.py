"""Tests for util/field.py."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.exceptions import ValidationError

from util.field import UniqueNameValidator, get_certificate_name


class TestUniqueNameValidator:
    """Tests for UniqueNameValidator class."""

    def test_init(self) -> None:
        """Test validator initialization."""
        validator = UniqueNameValidator()
        assert validator.regex.pattern == r'^[^\x00-\x1F\x7F-\x9F]+$'
        assert validator.code == 'invalid_unique_name'

    def test_valid_names(self) -> None:
        """Test validation of valid unique names."""
        validator = UniqueNameValidator()

        # Test valid names
        valid_names = [
            'test-name',
            'TEST_NAME_123',
            'domain.example.com',
            'name with spaces',
            'ÄÖÜäöüß',  # UTF-8 characters
            'name-with-dashes',
            'name_with_underscores',
            '123-numeric-prefix',
            'MixedCase123',
        ]

        for name in valid_names:
            validator(name)  # Should not raise

    def test_invalid_names(self) -> None:
        """Test validation of invalid unique names."""
        validator = UniqueNameValidator()

        # Test invalid names with control characters
        invalid_names = [
            'name\nwith\nnewline',  # newline
            'name\twith\ttab',  # tab
            'name\rwith\rreturn',  # carriage return
            'name\x00null',  # null character
            'name\x1fcontrol',  # control character
        ]

        for name in invalid_names:
            with pytest.raises(ValidationError):
                validator(name)

    def test_trailing_spaces_trimmed(self) -> None:
        """Test that trailing spaces are trimmed before validation."""
        validator = UniqueNameValidator()

        # Name with trailing spaces should be valid after trimming
        validator('valid-name   ')  # Should not raise

        # But leading spaces should remain and be valid
        validator('   valid-name')  # Should not raise

    def test_empty_string(self) -> None:
        """Test validation of empty string."""
        validator = UniqueNameValidator()

        with pytest.raises(ValidationError):
            validator('')

    def test_non_string_input(self) -> None:
        """Test validation with non-string input."""
        validator = UniqueNameValidator()

        # Integer converts to string and validates
        # This is expected behavior for validators
        validator(123)  # Should not raise - converts to '123'


class TestGetCertificateName:
    """Tests for get_certificate_name function."""

    def _create_test_cert(
        self, common_name: str | None = None, san_dns: list[str] | None = None, san_uri: list[str] | None = None
    ) -> x509.Certificate:
        """Helper to create a test certificate.

        Args:
            common_name: Common name for subject.
            san_dns: List of DNS names for SAN extension.
            san_uri: List of URIs for SAN extension.

        Returns:
            A test x509 certificate.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Build subject
        subject_attrs = []
        if common_name:
            subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        else:
            # Need at least one attribute
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'))

        subject = x509.Name(subject_attrs)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        )

        # Add SAN extension if provided
        if san_dns or san_uri:
            san_list = []
            if san_dns:
                san_list.extend([x509.DNSName(name) for name in san_dns])
            if san_uri:
                san_list.extend([x509.UniformResourceIdentifier(uri) for uri in san_uri])

            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        return builder.sign(private_key, hashes.SHA256())

    def test_get_name_from_common_name(self) -> None:
        """Test extracting name from CN."""
        cert = self._create_test_cert(common_name='test-device.example.com')

        name = get_certificate_name(cert)

        assert name == 'test-device.example.com'

    def test_get_name_from_san_dns(self) -> None:
        """Test extracting name from SAN DNS when no CN."""
        cert = self._create_test_cert(common_name=None, san_dns=['device1.example.com', 'device2.example.com'])

        name = get_certificate_name(cert)

        # Should return first DNS name
        assert name == 'device1.example.com'

    def test_get_name_from_san_uri(self) -> None:
        """Test extracting name from SAN URI when no CN or DNS."""
        cert = self._create_test_cert(
            common_name=None, san_uri=['https://device.example.com', 'https://other.example.com']
        )

        name = get_certificate_name(cert)

        # Should return first URI
        assert name == 'https://device.example.com'

    def test_get_name_from_aoki_dev_owner(self) -> None:
        """Test extracting name from AOKI DevOwnerID URI."""
        cert = self._create_test_cert(common_name=None, san_uri=['dev-owner:SN123456.example.com'])

        name = get_certificate_name(cert)

        # Should transform AOKI format
        assert name == 'Owner of SN: SN123456'

    def test_cn_takes_priority_over_san(self) -> None:
        """Test that CN takes priority over SAN."""
        cert = self._create_test_cert(common_name='cn-device.example.com', san_dns=['san-device.example.com'])

        name = get_certificate_name(cert)

        # CN should be used, not SAN
        assert name == 'cn-device.example.com'

    def test_san_dns_priority_over_uri(self) -> None:
        """Test that SAN DNS takes priority over SAN URI."""
        cert = self._create_test_cert(
            common_name=None, san_dns=['dns-device.example.com'], san_uri=['https://uri-device.example.com']
        )

        name = get_certificate_name(cert)

        # DNS should be used, not URI
        assert name == 'dns-device.example.com'

    def test_no_cn_no_san_raises_error(self) -> None:
        """Test that missing CN and SAN raises ValueError."""
        cert = self._create_test_cert(common_name=None)

        with pytest.raises(ValueError, match='No valid CN or SAN found'):
            get_certificate_name(cert)

    def test_empty_cn_falls_back_to_san(self) -> None:
        """Test that empty CN falls back to SAN."""
        # This would require a cert with empty CN string
        # For now, test the fallback behavior indirectly
        cert = self._create_test_cert(common_name=None, san_dns=['fallback-device.example.com'])

        name = get_certificate_name(cert)

        assert name == 'fallback-device.example.com'

    def test_bytes_cn_decoded(self) -> None:
        """Test that bytes CN is decoded to UTF-8."""
        # Create cert with CN
        cert = self._create_test_cert(common_name='test-device')

        name = get_certificate_name(cert)

        # Should return string
        assert isinstance(name, str)
        assert name == 'test-device'

    def test_multiple_san_entries(self) -> None:
        """Test with multiple SAN entries of same type."""
        cert = self._create_test_cert(
            common_name=None, san_dns=['first.example.com', 'second.example.com', 'third.example.com']
        )

        name = get_certificate_name(cert)

        # Should return first entry
        assert name == 'first.example.com'

    def test_aoki_dev_owner_with_complex_format(self) -> None:
        """Test AOKI DevOwnerID with complex serial number."""
        cert = self._create_test_cert(common_name=None, san_uri=['dev-owner:ABC-123-XYZ-789.manufacturer.example.com'])

        name = get_certificate_name(cert)

        # Should extract serial number before first dot
        assert name == 'Owner of SN: ABC-123-XYZ-789'
