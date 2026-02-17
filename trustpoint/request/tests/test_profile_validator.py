"""Tests for request/profile_validator.py."""

import json
from typing import Any
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from pki.util.cert_profile import ProfileValidationError
from pydantic_core import ValidationError

from pki.models import CertificateProfileModel
from request.profile_validator import ProfileValidator
from request.request_context import EstCertificateRequestContext


@pytest.mark.django_db
class TestProfileValidator:
    """Tests for ProfileValidator class."""

    def test_validate_success(self, domain_instance: dict[str, Any]) -> None:
        """Test successful profile validation."""
        domain = domain_instance['domain']

        # Create a simple certificate profile (using proper format from conftest)
        profile_json = {'type': 'cert_profile', 'subj': {'allow': '*'}, 'ext': {}, 'validity': {'days': 30}}

        cert_profile = CertificateProfileModel.objects.create(
            unique_name='test-profile', profile_json=json.dumps(profile_json)
        )

        # Create a CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
                ]
            )
        )

        from pki.util.keys import KeyGenerator

        private_key = KeyGenerator.generate_private_key(domain=domain)
        csr = builder.sign(private_key.as_crypto(), hashes.SHA256())

        # Create context
        context = EstCertificateRequestContext()
        context.cert_requested = csr
        context.certificate_profile_model = cert_profile

        # Validate
        ProfileValidator.validate(context)

        # Check that validated request was set
        assert hasattr(context, 'cert_requested_profile_validated')
        assert context.cert_requested_profile_validated is not None

    def test_validate_no_profile_model(self) -> None:
        """Test validation fails when no profile model is set."""
        # Create a simple CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
                ]
            )
        )

        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = builder.sign(private_key, hashes.SHA256())

        context = EstCertificateRequestContext()
        context.cert_requested = csr
        context.certificate_profile_model = None

        with pytest.raises(ValueError, match='Certificate profile model is not set in the context'):
            ProfileValidator.validate(context)

        assert context.http_response_content == 'Corresponding certificate profile is missing.'
        assert context.http_response_status == 422

    def test_validate_invalid_profile_json(self, domain_instance: dict[str, Any]) -> None:
        """Test validation fails with invalid profile JSON."""
        domain = domain_instance['domain']

        # Create a profile with invalid JSON
        cert_profile = CertificateProfileModel.objects.create(
            unique_name='test-profile-invalid',
            profile_json='{"invalid": json}',  # Invalid JSON
        )

        # Create a CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
                ]
            )
        )

        from pki.util.keys import KeyGenerator

        private_key = KeyGenerator.generate_private_key(domain=domain)
        csr = builder.sign(private_key.as_crypto(), hashes.SHA256())

        context = EstCertificateRequestContext()
        context.cert_requested = csr
        context.certificate_profile_model = cert_profile

        with pytest.raises(ValueError, match='Error decoding certificate profile JSON'):
            ProfileValidator.validate(context)

        assert context.http_response_content == 'Certificate profile data is corrupted.'
        assert context.http_response_status == 500

    def test_validate_profile_validation_error(self, domain_instance: dict[str, Any]) -> None:
        """Test validation fails when CSR doesn't match profile."""
        domain = domain_instance['domain']

        # Create a strict profile requiring organizationName
        profile_json = {
            'subject': {
                'commonName': {'required': True},
                'organizationName': {'required': True},  # Required but not in CSR
            },
            'extensions': {},
        }

        cert_profile = CertificateProfileModel.objects.create(
            unique_name='test-profile-strict', profile_json=json.dumps(profile_json)
        )

        # Create a CSR without organizationName
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
                    # Missing organizationName
                ]
            )
        )

        from pki.util.keys import KeyGenerator

        private_key = KeyGenerator.generate_private_key(domain=domain)
        csr = builder.sign(private_key.as_crypto(), hashes.SHA256())

        context = EstCertificateRequestContext()
        context.cert_requested = csr
        context.certificate_profile_model = cert_profile

        with pytest.raises(ValueError, match='Certificate request validation against profile failed'):
            ProfileValidator.validate(context)

        assert context.http_response_content == 'Request does not match the certificate profile.'
        assert context.http_response_status == 400

    def test_validate_with_pydantic_validation_error(self, domain_instance: dict[str, Any]) -> None:
        """Test validation handles pydantic ValidationError."""
        domain = domain_instance['domain']

        # Create a profile
        profile_json = {'subject': {'commonName': {'required': True}}, 'extensions': {}}

        cert_profile = CertificateProfileModel.objects.create(
            unique_name='test-profile-pydantic', profile_json=json.dumps(profile_json)
        )

        # Create a CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
                ]
            )
        )

        from pki.util.keys import KeyGenerator

        private_key = KeyGenerator.generate_private_key(domain=domain)
        csr = builder.sign(private_key.as_crypto(), hashes.SHA256())

        context = EstCertificateRequestContext()
        context.cert_requested = csr
        context.certificate_profile_model = cert_profile

        # Mock JSONProfileVerifier to raise ValidationError
        with patch('request.profile_validator.JSONProfileVerifier') as mock_verifier:
            # Create a simple validation error by wrapping in ValueError
            validation_error = ValidationError.from_exception_data(
                'error',
                [
                    {
                        'type': 'value_error',
                        'loc': ('field',),
                        'msg': 'Invalid value',
                        'input': 'test',
                        'ctx': {'error': 'test'},
                    }
                ],
            )
            mock_verifier.return_value.apply_profile_to_request.side_effect = validation_error

            with pytest.raises(ValueError, match='Certificate request validation against profile failed'):
                ProfileValidator.validate(context)

            assert context.http_response_content == 'Request does not match the certificate profile.'
            assert context.http_response_status == 400

    def test_validate_with_profile_validation_error_exception(self, domain_instance: dict[str, Any]) -> None:
        """Test validation handles ProfileValidationError exception."""
        domain = domain_instance['domain']

        # Create a profile
        profile_json = {'subject': {'commonName': {'required': True}}, 'extensions': {}}

        cert_profile = CertificateProfileModel.objects.create(
            unique_name='test-profile-exception', profile_json=json.dumps(profile_json)
        )

        # Create a CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
                ]
            )
        )

        from pki.util.keys import KeyGenerator

        private_key = KeyGenerator.generate_private_key(domain=domain)
        csr = builder.sign(private_key.as_crypto(), hashes.SHA256())

        context = EstCertificateRequestContext()
        context.cert_requested = csr
        context.certificate_profile_model = cert_profile

        # Mock JSONProfileVerifier to raise ProfileValidationError
        with patch('request.profile_validator.JSONProfileVerifier') as mock_verifier:
            mock_verifier.return_value.apply_profile_to_request.side_effect = ProfileValidationError(
                'Profile validation failed'
            )

            with pytest.raises(ValueError, match='Certificate request validation against profile failed'):
                ProfileValidator.validate(context)

            assert context.http_response_content == 'Request does not match the certificate profile.'
            assert context.http_response_status == 400

    def test_validate_logging(self, domain_instance: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
        """Test that validation logs certificate request JSON."""
        domain = domain_instance['domain']

        # Create a simple certificate profile (using proper format from conftest)
        profile_json = {'type': 'cert_profile', 'subj': {'allow': '*'}, 'ext': {}, 'validity': {'days': 30}}

        cert_profile = CertificateProfileModel.objects.create(
            unique_name='test-profile-logging', profile_json=json.dumps(profile_json)
        )  # Create a CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
                ]
            )
        )

        from pki.util.keys import KeyGenerator

        private_key = KeyGenerator.generate_private_key(domain=domain)
        csr = builder.sign(private_key.as_crypto(), hashes.SHA256())

        context = EstCertificateRequestContext()
        context.cert_requested = csr
        context.certificate_profile_model = cert_profile

        import logging

        with caplog.at_level(logging.INFO):
            ProfileValidator.validate(context)

        # Check that logging occurred
        log_messages = [record.message for record in caplog.records]
        assert any('Cert Request JSON:' in msg for msg in log_messages)
        assert any('Validated Cert Request JSON:' in msg for msg in log_messages)
