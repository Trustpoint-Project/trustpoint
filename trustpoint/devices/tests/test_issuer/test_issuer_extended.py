"""Extended tests for devices/issuer.py to increase coverage."""

import ipaddress
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pki.util.keys import KeyGenerator

from devices.issuer import (
    CredentialSaver,
    LocalDomainCredentialIssuer,
    LocalTlsClientCredentialIssuer,
    LocalTlsServerCredentialIssuer,
    OpcUaClientCredentialIssuer,
    OpcUaServerCredentialIssuer,
)
from devices.models import IssuedCredentialModel
from onboarding.models import OnboardingStatus


@pytest.mark.django_db
class TestSaveCredentialToDbMixin:
    """Test SaveCredentialToDbMixin functionality."""
    
    def test_save_credential_exception_handling(
        self,
        device_instance: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that _save handles exceptions correctly."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
        
        # Mock CredentialModel.save_credential_serializer to raise an exception
        def mock_save_raises(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Database error")
        
        monkeypatch.setattr(
            'pki.models.credential.CredentialModel.save_credential_serializer',
            mock_save_raises
        )
        
        # Should raise the exception
        with pytest.raises(RuntimeError, match="Database error"):
            issuer.issue_tls_client_credential(common_name='test', validity_days=365)
    
    def test_save_keyless_credential_with_existing_credential(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test _save_keyless_credential updates existing credential with matching subject."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
        
        # Issue first credential with private key
        first_credential = issuer.issue_domain_credential()
        
        # Get the certificate
        first_cert = first_credential.credential.get_certificate()
        
        # Issue another credential with just public key (should update existing one)
        private_key = KeyGenerator.generate_private_key(domain=domain)
        public_key = private_key.public_key_serializer.as_crypto()
        
        second_credential = issuer.issue_domain_credential_certificate(public_key=public_key)
        
        # Should be the same IssuedCredentialModel instance (updated)
        assert first_credential.pk == second_credential.pk
        
        # Verify only one domain credential exists for this device
        domain_credentials = IssuedCredentialModel.objects.filter(
            device=device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
        )
        assert domain_credentials.count() == 1
    
    def test_save_keyless_credential_exception_handling(
        self,
        device_instance: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that _save_keyless_credential handles exceptions correctly."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
        
        # Mock save to raise exception
        def mock_save_raises(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Save failed")
        
        monkeypatch.setattr(
            'pki.models.credential.CredentialModel.save_keyless_credential',
            mock_save_raises
        )
        
        private_key = KeyGenerator.generate_private_key(domain=domain)
        public_key = private_key.public_key_serializer.as_crypto()
        
        with pytest.raises(RuntimeError, match="Save failed"):
            issuer.issue_domain_credential_certificate(public_key=public_key)


@pytest.mark.django_db
class TestCredentialSaver:
    """Test CredentialSaver class."""
    
    def test_credential_saver_properties(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test CredentialSaver device and domain properties."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        saver = CredentialSaver(device=device, domain=domain)
        
        assert saver.device == device
        assert saver.domain == domain
    
    def test_credential_saver_save_keyless_credential(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test CredentialSaver.save_keyless_credential method."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        saver = CredentialSaver(device=device, domain=domain)
        
        # Generate a certificate
        issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
        private_key = KeyGenerator.generate_private_key(domain=domain)
        public_key = private_key.public_key_serializer.as_crypto()
        
        certificate = issuer._build_certificate(
            common_name='test-credential-saver',
            public_key=public_key,
            validity_days=365
        )
        
        chain = [
            domain.get_issuing_ca_or_value_error().credential.get_certificate(),
            *domain.get_issuing_ca_or_value_error().credential.get_certificate_chain(),
        ]
        
        issued_cred = saver.save_keyless_credential(
            certificate=certificate,
            certificate_chain=chain,
            common_name='test-credential-saver',
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            cert_profile_disp_name='Test Profile'
        )
        
        assert issued_cred.common_name == 'test-credential-saver'
        assert issued_cred.issued_using_cert_profile == 'Test Profile'


@pytest.mark.django_db
class TestBaseTlsCredentialIssuer:
    """Test BaseTlsCredentialIssuer error handling."""
    
    def test_raise_value_error(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test _raise_value_error method."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
        
        with pytest.raises(ValueError, match="Test error message"):
            issuer._raise_value_error("Test error message")
    
    def test_raise_type_error(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test _raise_type_error method."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
        
        with pytest.raises(TypeError, match="Type mismatch"):
            issuer._raise_type_error("Type mismatch")
    
    def test_pseudonym_and_domain_component_properties(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test pseudonym and domain_component properties."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
        
        assert issuer.pseudonym == LocalTlsClientCredentialIssuer._pseudonym
        assert issuer.domain_component == domain.unique_name
        assert issuer.serial_number == device.serial_number


@pytest.mark.django_db
class TestTlsServerCredentialIssuer:
    """Test TLS Server Credential issuer edge cases."""
    
    def test_issue_tls_server_certificate_without_key(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test issuing TLS server certificate without private key."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsServerCredentialIssuer(device=device, domain=domain)
        
        # Generate public key only
        private_key = KeyGenerator.generate_private_key(domain=domain)
        public_key = private_key.public_key_serializer.as_crypto()
        
        issued_credential = issuer.issue_tls_server_certificate(
            common_name='server-cert-only',
            ipv4_addresses=[ipaddress.IPv4Address('10.0.0.1')],
            ipv6_addresses=[],
            domain_names=['server.example.com'],
            validity_days=180,
            public_key=public_key,
            san_critical=True
        )
        
        assert issued_credential.common_name == 'server-cert-only'
        
        # Check SAN extension is critical
        cert = issued_credential.credential.get_certificate()
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san_ext.critical is True


@pytest.mark.django_db
class TestLocalDomainCredentialIssuer:
    """Test LocalDomainCredentialIssuer edge cases."""
    
    def test_issue_domain_certificate_updates_onboarding_status(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test that issuing domain certificate updates onboarding status."""
        device = device_instance_onboarding['device']
        domain = device_instance_onboarding['domain']
        
        # Ensure device has onboarding config
        assert device.onboarding_config is not None
        initial_status = device.onboarding_config.onboarding_status
        
        issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
        
        private_key = KeyGenerator.generate_private_key(domain=domain)
        public_key = private_key.public_key_serializer.as_crypto()
        
        issued_credential = issuer.issue_domain_credential_certificate(public_key=public_key)
        
        # Refresh from database
        device.refresh_from_db()
        device.onboarding_config.refresh_from_db()
        
        # Onboarding status should be updated to ONBOARDED
        assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED
        assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL


@pytest.mark.django_db
class TestOpcUaServerCredentialIssuer:
    """Test OPC UA Server Credential issuer edge cases."""
    
    def test_validate_application_uri_empty_list(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test validation fails for empty application URI list."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        with pytest.raises(ValueError, match="Application URI cannot be empty"):
            issuer._validate_application_uri([])
    
    def test_validate_application_uri_multiple_items(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test validation fails for multiple application URIs."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        with pytest.raises(ValueError, match="Application URI cannot be longer than 1 item"):
            issuer._validate_application_uri(['uri:1', 'uri:2'])
    
    def test_get_key_usage_for_rsa(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test _get_key_usage returns correct KeyUsage for RSA key."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        # Generate RSA key
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = rsa_key.public_key()
        
        key_usage = issuer._get_key_usage(public_key)
        
        assert key_usage.digital_signature is True
        assert key_usage.content_commitment is True
        assert key_usage.key_encipherment is True
        assert key_usage.data_encipherment is True
        assert key_usage.key_agreement is False
    
    def test_get_key_usage_for_ecc(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test _get_key_usage returns correct KeyUsage for ECC key."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        # Generate ECC key
        ecc_key = ec.generate_private_key(ec.SECP256R1())
        public_key = ecc_key.public_key()
        
        key_usage = issuer._get_key_usage(public_key)
        
        assert key_usage.digital_signature is True
        assert key_usage.content_commitment is True
        assert key_usage.key_encipherment is False
        assert key_usage.data_encipherment is False
        assert key_usage.key_agreement is False
    
    def test_get_key_usage_unsupported_key_type(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test _get_key_usage raises error for unsupported key type."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        # Create a mock unsupported key type
        mock_key = MagicMock()
        
        with pytest.raises(ValueError, match="Unsupported key type for OPC UA Server Certificate"):
            issuer._get_key_usage(mock_key)
    
    def test_issue_opcua_server_credential_with_all_san_types(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test issuing OPC UA server credential with all SAN types."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        issued_credential = issuer.issue_opc_ua_server_credential(
            common_name='OPC UA Server Full',
            application_uri='urn:example:opcua:server',
            ipv4_addresses=[ipaddress.IPv4Address('192.168.1.100')],
            ipv6_addresses=[ipaddress.IPv6Address('fe80::1')],
            domain_names=['opcua.example.com', 'opcua-backup.example.com'],
            validity_days=730
        )
        
        assert issued_credential.common_name == 'OPC UA Server Full'
        
        # Verify SAN extension contains all types
        cert = issued_credential.credential.get_certificate()
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        
        # Check for URI
        uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert 'urn:example:opcua:server' in uris
        
        # Check for IPs
        ips = san_ext.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address('192.168.1.100') in ips
        assert ipaddress.IPv6Address('fe80::1') in ips
        
        # Check for DNS names
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert 'opcua.example.com' in dns_names
        assert 'opcua-backup.example.com' in dns_names
    
    def test_issue_opcua_server_certificate_without_key(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test issuing OPC UA server certificate without private key."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        # Generate ECC key for testing
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        
        issued_credential = issuer.issue_opc_ua_server_certificate(
            common_name='OPC UA Cert Only',
            application_uri='urn:test:opcua',
            ipv4_addresses=[],
            ipv6_addresses=[],
            domain_names=['test.local'],
            validity_days=365,
            public_key=public_key
        )
        
        assert issued_credential.common_name == 'OPC UA Cert Only'
        
        # Verify it's ECC key
        cert = issued_credential.credential.get_certificate()
        assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)


@pytest.mark.django_db
class TestOpcUaClientCredentialIssuer:
    """Test OPC UA Client Credential issuer."""
    
    def test_issue_opcua_client_credential_full(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test issuing OPC UA client credential with all parameters."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaClientCredentialIssuer(device=device, domain=domain)
        
        issued_credential = issuer.issue_opc_ua_client_credential(
            common_name='OPC UA Client Full Test',
            application_uri='urn:example:opcua:client',
            validity_days=365
        )
        
        assert issued_credential.common_name == 'OPC UA Client Full Test'
        assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
        
        # Verify SAN contains application URI
        cert = issued_credential.credential.get_certificate()
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert 'urn:example:opcua:client' in uris


@pytest.mark.django_db
class TestBuildCertificateEdgeCases:
    """Test certificate building edge cases."""
    
    def test_build_certificate_with_extra_extensions(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test _build_certificate with additional extensions."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
        
        private_key = KeyGenerator.generate_private_key(domain=domain)
        public_key = private_key.public_key_serializer.as_crypto()
        
        # Add custom extension
        extra_extensions = [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), True)
        ]
        
        cert = issuer._build_certificate(
            common_name='test-extra-extensions',
            public_key=public_key,
            validity_days=365,
            extra_extensions=extra_extensions
        )
        
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'test-extra-extensions'
        
        # Verify BasicConstraints extension exists and is critical
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.critical is True
        assert basic_constraints.value.ca is False


@pytest.mark.django_db
class TestCredentialPseudonymProperty:
    """Test pseudonym property in credential issuers."""
    
    def test_tls_client_pseudonym(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test TLS Client issuer has correct pseudonym."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsClientCredentialIssuer(device=device, domain=domain)
        
        assert issuer.pseudonym == 'Trustpoint Application Credential - TLS Client'
        assert issuer._pseudonym == 'Trustpoint Application Credential - TLS Client'
    
    def test_tls_server_pseudonym(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test TLS Server issuer has correct pseudonym."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalTlsServerCredentialIssuer(device=device, domain=domain)
        
        assert issuer.pseudonym == 'Trustpoint Application Credential - TLS Server'
    
    def test_domain_credential_pseudonym(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test Domain Credential issuer has correct pseudonym."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
        
        assert issuer.pseudonym == LocalDomainCredentialIssuer.DOMAIN_CREDENTIAL_CN
        assert issuer._pseudonym == 'Trustpoint Domain Credential'
    
    def test_opcua_server_pseudonym(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test OPC UA Server issuer has correct pseudonym."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaServerCredentialIssuer(device=device, domain=domain)
        
        assert issuer.pseudonym == 'Trustpoint OPC UA Server Credential'
        assert issuer._pseudonym == 'Trustpoint OPC UA Server Credential'
    
    def test_opcua_client_pseudonym(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test OPC UA Client issuer has correct pseudonym."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        issuer = OpcUaClientCredentialIssuer(device=device, domain=domain)
        
        assert issuer.pseudonym == 'Trustpoint OPC UA Client Credential'
