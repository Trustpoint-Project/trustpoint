# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Extended tests for request/authentication.py to increase coverage."""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc4210, rfc5280

from devices.models import (
    DeviceModel,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingProtocol,
)
from pki.util.keys import KeyGenerator
from request.authentication import (
    ClientCertificateAuthentication,
    IDevIDAuthentication,
)
from pki.models import IssuedCredentialModel
from request.authentication.cmp import (
    CmpCertConfAuthentication,
    CmpSharedSecretAuthentication,
    CmpSignatureBasedCertificationAuthentication,
    CmpSignatureBasedInitializationAuthentication,
    CmpSignatureBasedPollAuthentication,
    CmpSignatureBasedRevocationAuthentication,
)
from request.authentication.est import (
    EstAuthentication,
    ReenrollmentAuthentication,
    UsernamePasswordAuthentication,
)
from request.request_context import (
    BaseRequestContext,
    BaseCertificateRequestContext,
    CmpBaseRequestContext,
    CmpCertificateRequestContext,
    CmpPollRequestContext,
    EstBaseRequestContext,
    EstCertificateRequestContext,
    HttpBaseRequestContext,
)


def _certificate_and_csr() -> tuple[x509.Certificate, x509.CertificateSigningRequest]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device')])
    san = x509.SubjectAlternativeName([x509.DNSName('device.example')])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate, csr


def _typed_cmp_message(algorithm: str = '1.2.3') -> rfc4210.PKIMessage:
    message = rfc4210.PKIMessage()
    message['header']['protectionAlg']['algorithm'] = algorithm
    message['body']['pkiconf'] = ''
    return message


def _cmp_message_with_certificate(certificate: x509.Certificate) -> rfc4210.PKIMessage:
    message = _typed_cmp_message()
    cert_asn1, _ = decoder.decode(
        certificate.public_bytes(Encoding.DER), asn1Spec=rfc5280.Certificate()
    )
    message['extraCerts'][0] = cert_asn1
    return message


@pytest.mark.django_db
class TestUsernamePasswordAuthenticationExtended:
    """Extended tests for UsernamePasswordAuthentication."""

    def test_authenticate_rejects_non_base_est_context(self) -> None:
        """Test authentication requires the EST base context contract."""
        with pytest.raises(TypeError, match='requires an EstBaseRequestContext'):
            UsernamePasswordAuthentication().authenticate(BaseRequestContext())

    def test_authenticate_skips_missing_credentials(self) -> None:
        """Test authentication does not run when either credential is absent."""
        context = EstBaseRequestContext(est_username='device', est_password=None)

        assert UsernamePasswordAuthentication().authenticate(context) is None
        assert context.device is None

    def test_authenticate_onboarding_device(self, est_device_with_onboarding: dict[str, Any]) -> None:
        """Test a real device configured for EST onboarding authenticates successfully."""
        device = est_device_with_onboarding['device']
        context = EstBaseRequestContext(
            est_username=device.common_name,
            est_password=device.onboarding_config.est_password,
        )

        UsernamePasswordAuthentication().authenticate(context)

        assert context.device.pk == device.pk

    def test_authenticate_no_onboarding_device(self, est_device_without_onboarding: dict[str, Any]) -> None:
        """Test a real device configured for EST without onboarding authenticates successfully."""
        device = est_device_without_onboarding['device']
        context = EstBaseRequestContext(
            est_username=device.common_name,
            est_password=device.no_onboarding_config.est_password,
        )

        UsernamePasswordAuthentication().authenticate(context)

        assert context.device.pk == device.pk

    def test_authenticate_unknown_user(self) -> None:
        """Test unknown usernames receive the standardized authentication error."""
        context = EstBaseRequestContext(est_username='unknown-user', est_password='secret')

        with pytest.raises(ValueError, match='Authentication failed: Invalid username or password'):
            UsernamePasswordAuthentication().authenticate(context)
        assert context.device is None

    def test_authenticate_invalid_password(self, est_device_without_onboarding: dict[str, Any]) -> None:
        """Test an incorrect password does not populate the security context."""
        device = est_device_without_onboarding['device']
        context = EstBaseRequestContext(est_username=device.common_name, est_password='wrong-password')

        with pytest.raises(ValueError, match='Authentication failed: Invalid username or password'):
            UsernamePasswordAuthentication().authenticate(context)
        assert context.device is None

    def test_authenticate_rejects_malformed_device_model(self) -> None:
        """Test a lookup result that is not a DeviceModel is rejected."""
        context = EstBaseRequestContext(est_username='device', est_password='secret')
        queryset = Mock()
        queryset.filter.return_value.first.return_value = Mock(
            onboarding_config=Mock(est_password='secret'), no_onboarding_config=None
        )

        with patch.object(DeviceModel.objects, 'select_related', return_value=queryset):
            with pytest.raises(ValueError, match='Authentication failed: Invalid username or password'):
                UsernamePasswordAuthentication().authenticate(context)
        assert context.device is None
    
    def test_authenticate_device_without_est_password(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test authentication fails when device has no EST password configured."""
        device = device_instance['device']
        
        # Create no_onboarding_config with manual protocol (which doesn't use EST password)
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.MANUAL])
        no_onboarding_config.est_password = ''  # Empty password  
        no_onboarding_config.save()
        
        device.no_onboarding_config = no_onboarding_config
        device.save()
        
        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = device.common_name
        context.est_password = 'anypassword'
        
        with pytest.raises(ValueError, match="Authentication failed: Invalid username or password"):
            auth.authenticate(context)
    
    def test_authenticate_device_without_config(
        self,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test authentication fails when device has no onboarding or no_onboarding config."""
        domain = domain_instance['domain']
        
        # Create device without any config
        device = DeviceModel.objects.create(
            common_name='device-no-config',
            serial_number='SN-NO-CONFIG',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE
        )
        
        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = device.common_name
        context.est_password = 'anypassword'
        
        with pytest.raises(ValueError, match="Authentication failed: Invalid username or password"):
            auth.authenticate(context)
    
    def test_authenticate_exception_during_lookup(self) -> None:
        """Test authentication handles exceptions during device lookup."""
        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = 'test-user'
        context.est_password = 'test-pass'
        
        # Mock DeviceModel.objects to raise exception
        with patch('devices.models.DeviceModel.objects') as mock_objects:
            mock_objects.select_related.return_value.filter.side_effect = Exception("Database error")
            
            with pytest.raises(ValueError, match="Authentication failed: Invalid username or password"):
                auth.authenticate(context)


@pytest.mark.django_db
class TestEstAuthenticationSpecificComponents:
    """Tests for EST-specific authentication component wiring and guards."""

    def test_est_authentication_contains_components_in_security_order(self) -> None:
        """Test EST tries certificate reenrollment before password authentication."""
        authenticator = EstAuthentication()

        assert [type(component) for component in authenticator.components] == [
            ReenrollmentAuthentication,
            UsernamePasswordAuthentication,
            ClientCertificateAuthentication,
            IDevIDAuthentication,
        ]

    def test_est_authentication_populates_context_from_password(
        self, est_device_without_onboarding: dict[str, Any]
    ) -> None:
        """Test the EST composite preserves the authenticated device in its context."""
        device = est_device_without_onboarding['device']
        context = EstBaseRequestContext(
            est_username=device.common_name,
            est_password=device.no_onboarding_config.est_password,
        )

        EstAuthentication().authenticate(context)

        assert context.device.pk == device.pk
        assert context.domain is None

    def test_reenrollment_rejects_non_est_certificate_context(self) -> None:
        """Test EST reenrollment enforces its certificate request context."""
        with pytest.raises(TypeError, match='requires an EstCertificateRequestContext'):
            ReenrollmentAuthentication().authenticate(BaseRequestContext())

    def test_reenrollment_returns_when_client_certificate_is_absent(self) -> None:
        context = EstCertificateRequestContext(cert_requested=Mock())

        assert ReenrollmentAuthentication().authenticate(context) is None
        assert context.device is None

    def test_reenrollment_rejects_invalid_credential(self) -> None:
        certificate, csr = _certificate_and_csr()
        credential_certificate = Mock()
        credential = Mock(certificate_or_error=credential_certificate)
        credential.is_valid_issued_credential.return_value = (False, 'revoked')
        issued = Mock(credential=credential)
        context = EstCertificateRequestContext(client_certificate=certificate, cert_requested=csr)

        with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=issued):
            with pytest.raises(ValueError, match='Invalid client certificate for reenrollment: revoked'):
                ReenrollmentAuthentication().authenticate(context)

    def test_reenrollment_rejects_invalid_csr_type(self) -> None:
        certificate, _ = _certificate_and_csr()
        context = EstCertificateRequestContext(client_certificate=certificate, cert_requested=Mock())
        issued = Mock(credential=Mock())

        with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=issued):
            with pytest.raises(ValueError, match='Invalid credential model for reenrollment'):
                ReenrollmentAuthentication().authenticate(context)

    def test_reenrollment_rejects_extension_mismatch(self) -> None:
        certificate, _ = _certificate_and_csr()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(certificate.subject)
            .sign(key, hashes.SHA256())
        )

        with pytest.raises(ValueError, match='CSR/client SAN does not match'):
            ReenrollmentAuthentication()._validate_certificate_extensions(certificate, certificate, csr)


@pytest.mark.django_db
class TestClientCertificateAuthenticationExtended:
    """Extended tests for ClientCertificateAuthentication."""
    
    def test_authenticate_no_client_certificate(self) -> None:
        """Test authentication returns None when no client certificate provided."""
        auth = ClientCertificateAuthentication()
        context = Mock(spec=BaseRequestContext)
        context.client_certificate = None
        
        result = auth.authenticate(context)
        
        assert result is None
    
    def test_authenticate_certificate_not_found_in_db(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test authentication fails when certificate is not found in database."""

        domain = device_instance['domain']
        
        # Create a certificate that's not in the database
        private_key = KeyGenerator.generate_private_key(domain=domain)
        
        # Build a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Unknown Certificate'),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key_serializer.as_crypto()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            device_instance['cert'].not_valid_before_utc
        ).not_valid_after(
            device_instance['cert'].not_valid_after_utc
        ).sign(private_key.as_crypto(), hashes.SHA256())
        
        auth = ClientCertificateAuthentication()
        context = Mock(spec=BaseRequestContext)
        context.client_certificate = cert
        
        with pytest.raises(ValueError, match="Client certificate not recognized"):
            auth.authenticate(context)
    
    def test_authenticate_invalid_domain_credential(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test authentication fails with invalid domain credential."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        # Create an issued credential but mock it as invalid
        from devices.issuer import LocalDomainCredentialIssuer
        
        issuer = LocalDomainCredentialIssuer(device=device, domain=domain)
        issued_cred = issuer.issue_domain_credential()
        
        cert = issued_cred.credential.get_certificate()
        
        auth = ClientCertificateAuthentication()
        context = Mock(spec=BaseRequestContext)
        context.client_certificate = cert
        
        # Mock the is_valid_domain_credential to return False
        with patch.object(IssuedCredentialModel, 'is_valid_domain_credential') as mock_valid:
            mock_valid.return_value = (False, "Certificate is revoked")
            
            with pytest.raises(ValueError, match="Invalid HTTP_SSL_CLIENT_CERT header: Certificate is revoked"):
                auth.authenticate(context)


@pytest.mark.django_db
class TestCmpSharedSecretAuthentication:
    """Tests for CMP Shared Secret Authentication."""
    
    def test_authenticate_non_cmp_protocol(self) -> None:
        """Test authentication raises error when protocol is not CMP."""
        auth = CmpSharedSecretAuthentication()
        context = Mock(spec=CmpBaseRequestContext)
        context.protocol = 'est'  # Wrong protocol
        
        with pytest.raises(ValueError, match="CMP shared secret authentication requires CMP protocol"):
            auth.authenticate(context)
    
    def test_authenticate_no_parsed_message(self) -> None:
        """Test authentication raises error when no parsed message."""
        auth = CmpSharedSecretAuthentication()
        context = Mock(spec=CmpBaseRequestContext)
        context.protocol = 'cmp'
        context.parsed_message = None
        
        with pytest.raises(ValueError, match="CMP shared secret authentication requires a parsed message"):
            auth.authenticate(context)
    
    def test_authenticate_invalid_message_type(self) -> None:
        """Test authentication raises error with invalid message type."""
        auth = CmpSharedSecretAuthentication()
        context = Mock(spec=CmpBaseRequestContext)
        context.protocol = 'cmp'
        context.parsed_message = Mock()  # Not a PKIMessage
        context.parsed_message.__class__.__name__ = 'SomeOtherType'
        
        with pytest.raises(TypeError, match="CMP shared secret authentication requires a PKIMessage"):
            auth.authenticate(context)

    def test_non_pbm_message_is_skipped(self) -> None:
        auth = CmpSharedSecretAuthentication()
        message = MagicMock(spec=rfc4210.PKIMessage)
        message.__bool__.return_value = True
        message.__getitem__.return_value = MagicMock()
        message['header']['protectionAlg']['algorithm'].prettyPrint.return_value = '1.2.3'
        context = CmpBaseRequestContext(protocol='cmp', parsed_message=message)
        with patch('request.authentication.cmp.AlgorithmIdentifier.from_dotted_string', return_value='signature'):
            assert auth._validate_context(context) is False

    def test_missing_sender_kid_is_rejected(self) -> None:
        auth = CmpSharedSecretAuthentication()
        message = MagicMock(spec=rfc4210.PKIMessage)
        message['header']['senderKID'].prettyPrint.side_effect = ValueError('missing')
        context = CmpBaseRequestContext(parsed_message=message)

        with pytest.raises(ValueError, match='Invalid or missing senderKID'):
            auth._extract_sender_kid(context)

    def test_device_lookup_and_configuration_failures_are_rejected(self) -> None:
        auth = CmpSharedSecretAuthentication()
        with patch.object(auth, '_validate_context', return_value=True), \
                patch.object(auth, '_extract_sender_kid', return_value=7), \
                patch.object(auth, '_get_device', side_effect=ValueError('device lookup failed')):
            with pytest.raises(ValueError, match='device lookup failed'):
                auth.authenticate(CmpBaseRequestContext(protocol='cmp', parsed_message=Mock()))

        device = Mock(common_name='device', onboarding_config=None, no_onboarding_config=None)
        with pytest.raises(ValueError, match='no shared secret configured'):
            auth._validate_device_configuration(device, sender_kid=7)

    def test_successful_shared_secret_authentication_populates_context(self) -> None:
        auth = CmpSharedSecretAuthentication()
        context = CmpBaseRequestContext(protocol='cmp', parsed_message=Mock())
        device = Mock(common_name='device', domain=Mock())
        config = Mock(cmp_shared_secret='secret')
        with patch.object(auth, '_validate_context', return_value=True), \
                patch.object(auth, '_extract_sender_kid', return_value=7), \
                patch.object(auth, '_get_device', return_value=device), \
                patch.object(auth, '_validate_device_configuration', return_value=config), \
                patch.object(auth, '_verify_hmac_protection') as verify:
            auth.authenticate(context)

        verify.assert_called_once_with(context, 'secret')
        assert context.device is device
        assert context.domain is device.domain


def test_signature_authentication_skips_wrong_context_and_operation() -> None:
    init_auth = CmpSignatureBasedInitializationAuthentication()
    cert_auth = CmpSignatureBasedCertificationAuthentication()
    assert init_auth.authenticate(BaseRequestContext(protocol='cmp')) is None
    assert cert_auth.authenticate(BaseRequestContext(protocol='cmp')) is None
    assert init_auth._should_authenticate(CmpCertificateRequestContext(protocol='cmp', operation='certification')) is False
    assert cert_auth._should_authenticate(CmpCertificateRequestContext(protocol='cmp', operation='initialization')) is False


@pytest.mark.django_db
class TestIDevIDAuthentication:
    """Tests for IDevID Authentication."""
    
    def test_authenticate_no_raw_message(self) -> None:
        """Test authentication returns None when no raw_message."""
        auth = IDevIDAuthentication()
        context = Mock(spec=HttpBaseRequestContext)
        context.raw_message = None
        
        result = auth.authenticate(context)
        
        assert result is None
    
    def test_authenticate_with_valid_idevid(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test authentication with valid IDevID certificate."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        auth = IDevIDAuthentication()
        context = Mock(spec=HttpBaseRequestContext)
        context.raw_message = Mock()  # Non-None raw message
        context.domain = domain
        
        # Mock the IDevIDAuthenticator
        with patch('request.authentication.base.IDevIDAuthenticator.authenticate_idevid') as mock_auth_method:
            mock_auth_method.return_value = device
            
            auth.authenticate(context)
            
            assert context.device == device
    
    def test_authenticate_idevid_authentication_error(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test authentication fails when IDevID authentication raises error."""
        domain = device_instance['domain']
        
        auth = IDevIDAuthentication()
        context = Mock(spec=HttpBaseRequestContext)
        context.raw_message = Mock()  # Non-None raw message
        context.domain = domain
        
        # Mock the IDevIDAuthenticator to raise error
        with patch('request.authentication.base.IDevIDAuthenticator.authenticate_idevid') as mock_auth_method:
            from pki.util.idevid import IDevIDAuthenticationError
            mock_auth_method.side_effect = IDevIDAuthenticationError("Invalid IDevID")
            
            with pytest.raises(ValueError, match="Error validating the IDevID"):
                auth.authenticate(context)
    
    def test_authenticate_no_device_associated(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test authentication fails when no device is associated."""
        domain = device_instance['domain']
        
        auth = IDevIDAuthentication()
        context = Mock(spec=HttpBaseRequestContext)
        context.raw_message = Mock()  # Non-None raw message
        context.domain = domain
        
        # Mock the IDevIDAuthenticator to return None
        with patch('request.authentication.base.IDevIDAuthenticator.authenticate_idevid') as mock_auth_method:
            mock_auth_method.return_value = None
            
            with pytest.raises(ValueError, match="IDevID authentication failed: No device associated"):
                auth.authenticate(context)
    
    def test_authenticate_device_without_domain(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test authentication with device that has no domain set."""
        device = device_instance['device']
        # Temporarily remove domain from device
        device.domain = None
        device.save()
        
        auth = IDevIDAuthentication()
        context = Mock(spec=HttpBaseRequestContext)
        context.raw_message = Mock()  # Non-None raw message
        context.domain = None
        
        # Mock the IDevIDAuthenticator to return device without domain
        with patch('request.authentication.base.IDevIDAuthenticator.authenticate_idevid') as mock_auth_method:
            mock_auth_method.return_value = device
            
            with pytest.raises(ValueError, match="IDevID authentication failed: Device domain is not set"):
                auth.authenticate(context)


@pytest.mark.django_db
class TestCompositeAuthentication:
    """Tests for composite authentication patterns."""
    
    def test_multiple_authentication_methods(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that first successful authentication method is used."""
        device = device_instance['device']
        
        # Setup device with EST password
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD])
        no_onboarding_config.est_password = 'test-password-123'
        no_onboarding_config.save()
        
        device.no_onboarding_config = no_onboarding_config
        device.save()
        
        # Try username/password authentication
        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = device.common_name
        context.est_password = 'test-password-123'
        
        auth.authenticate(context)
        
        assert context.device == device
    
    def test_authentication_with_onboarding_config(
        self,
        device_instance_onboarding: dict[str, Any]
    ) -> None:
        """Test authentication works with onboarding config."""
        device = device_instance_onboarding['device']
        
        # Use the device's existing onboarding config and set a password
        if device.onboarding_config:
            # Update the existing config
            onboarding_config = device.onboarding_config
            # Only set password if protocol supports it
            from onboarding.models import OnboardingProtocol


            def _certificate_and_csr() -> tuple[x509.Certificate, x509.CertificateSigningRequest]:
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device')])
                san = x509.SubjectAlternativeName([x509.DNSName('device.example')])
                csr = (
                    x509.CertificateSigningRequestBuilder()
                    .subject_name(subject)
                    .add_extension(san, critical=False)
                    .sign(key, hashes.SHA256())
                )
                now = datetime.now(timezone.utc)
                certificate = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(subject)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now)
                    .not_valid_after(now + timedelta(days=1))
                    .add_extension(san, critical=False)
                    .sign(key, hashes.SHA256())
                )
                return certificate, csr
            if onboarding_config.onboarding_protocol == OnboardingProtocol.EST_USERNAME_PASSWORD:
                onboarding_config.est_password = 'onboarding-password-123'
                onboarding_config.save()
                
                auth = UsernamePasswordAuthentication()
                context = Mock(spec=EstBaseRequestContext)
                context.est_username = device.common_name
                context.est_password = 'onboarding-password-123'
                
                auth.authenticate(context)
                
                assert context.device == device
        else:
            # Create a new onboarding config with EST_USERNAME_PASSWORD
            from onboarding.models import OnboardingProtocol
            onboarding_config = OnboardingConfigModel()
            onboarding_config.onboarding_protocol = OnboardingProtocol.EST_USERNAME_PASSWORD
            onboarding_config.est_password = 'onboarding-password-123'
            onboarding_config.save()
            
            device.onboarding_config = onboarding_config
            device.save()
            
            auth = UsernamePasswordAuthentication()
            context = Mock(spec=EstBaseRequestContext)
            context.est_username = device.common_name
            context.est_password = 'onboarding-password-123'
            
            auth.authenticate(context)
            
            assert context.device == device


@pytest.mark.django_db
class TestAuthenticationEdgeCases:
    """Tests for authentication edge cases and error conditions."""
    
    def test_username_password_with_special_characters(
        self,
        domain_instance: dict[str, Any]
    ) -> None:
        """Test authentication with special characters in username/password."""
        domain = domain_instance['domain']
        
        # Create device with special characters
        device = DeviceModel.objects.create(
            common_name='device-special-@#$',
            serial_number='SN-SPECIAL',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE
        )
        
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD])
        no_onboarding_config.est_password = 'p@ssw0rd!#$%^&*()'
        no_onboarding_config.save()
        
        device.no_onboarding_config = no_onboarding_config
        device.save()
        
        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = 'device-special-@#$'
        context.est_password = 'p@ssw0rd!#$%^&*()'
        
        auth.authenticate(context)
        
        assert context.device == device
    
    def test_case_sensitive_username(
        self,
        device_instance: dict[str, Any]
    ) -> None:
        """Test that username is case-sensitive."""
        device = device_instance['device']
        
        # Setup device
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols([NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD])
        no_onboarding_config.est_password = 'test-password'
        no_onboarding_config.save()
        
        device.no_onboarding_config = no_onboarding_config
        device.save()
        
        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = device.common_name.upper()  # Wrong case
        context.est_password = 'test-password'
        
        with pytest.raises(ValueError, match="Authentication failed: Invalid username or password"):
            auth.authenticate(context)


class TestRemainingEstAuthenticationBranches:
    """Cover EST validation branches with concrete certificates and contexts."""

    def test_reenrollment_context_validation_errors(self) -> None:
        certificate, csr = _certificate_and_csr()
        auth = ReenrollmentAuthentication()

        with pytest.raises(ValueError, match='Invalid client certificate type'):
            auth._validate_context(EstCertificateRequestContext(client_certificate=Mock(), cert_requested=csr))
        with pytest.raises(ValueError, match='CSR is missing'):
            auth._validate_context(EstCertificateRequestContext(client_certificate=certificate))

    def test_reenrollment_missing_issued_credential(self) -> None:
        certificate, csr = _certificate_and_csr()
        context = EstCertificateRequestContext(client_certificate=certificate, cert_requested=csr)
        with patch.object(IssuedCredentialModel, 'get_credential_for_certificate',
                          side_effect=IssuedCredentialModel.DoesNotExist):
            with pytest.raises(ValueError, match='Issued credential not found'):
                ReenrollmentAuthentication().authenticate(context)

    def test_reenrollment_subject_and_extension_success(self) -> None:
        certificate, csr = _certificate_and_csr()
        credential = Mock()
        credential.is_valid_issued_credential.return_value = (True, '')
        credential.certificate_or_error = Mock()
        credential.certificate_or_error.subjects_match.return_value = True
        credential.certificate_or_error.get_certificate_serializer.return_value.as_crypto.return_value = certificate
        issued = Mock(credential=credential, device=Mock())
        context = EstCertificateRequestContext(client_certificate=certificate, cert_requested=csr)

        with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=issued):
            ReenrollmentAuthentication().authenticate(context)
        assert context.device is issued.device

        credential.certificate_or_error.subjects_match.side_effect = [False, True]
        with pytest.raises(ValueError, match='subject does not match'):
            ReenrollmentAuthentication()._validate_credential(credential, csr, certificate)

    def test_reenrollment_extension_serializer_failure(self) -> None:
        certificate, csr = _certificate_and_csr()
        credential = Mock()
        credential.certificate_or_error.get_certificate_serializer.side_effect = ValueError('bad serializer')
        with pytest.raises(ValueError, match='Certificate extension validation failed'):
            ReenrollmentAuthentication()._validate_certificate_extensions_safe(credential, certificate, csr)


class TestRemainingCmpAuthenticationBranches:
    """Cover CMP protocol guards, certificate paths, and configuration errors."""

    def test_base_helpers_and_extra_certificate_extraction(self) -> None:
        certificate, _ = _certificate_and_csr()
        auth = CmpSignatureBasedInitializationAuthentication()
        context = CmpBaseRequestContext(domain_str='.aoki')
        context.raw_message = Mock(path='/p/.aoki/initialization')
        assert auth._is_aoki_request(context) is True
        context.raw_message = None
        assert auth._is_aoki_request(context) is False

        message = _cmp_message_with_certificate(certificate)
        signer, intermediates = auth._extract_extra_certs(
            CmpBaseRequestContext(parsed_message=message)
        )
        assert signer.subject == certificate.subject
        assert intermediates == []
        with pytest.raises(ValueError, match='No extra certificates'):
            auth._extract_extra_certs(CmpBaseRequestContext(parsed_message=_typed_cmp_message()))

    def test_signature_verification_rsa_and_ec(self) -> None:
        message = _typed_cmp_message()
        message['protection'] = message['protection'].clone(
            value=univ.BitString.fromOctetString(b'signature')
        )
        with patch('request.authentication.cmp.encoder.encode', return_value=b'encoded'), \
            patch('request.authentication.cmp.SignatureSuite.from_certificate') as suite_factory:
            suite_factory.return_value.algorithm_identifier.hash_algorithm = Mock(
                hash_algorithm=lambda: hashes.SHA256()
            )
            rsa_key = Mock(spec=rsa.RSAPublicKey)
            certificate = Mock(spec=x509.Certificate)
            certificate.public_key.return_value = rsa_key
            CmpSignatureBasedInitializationAuthentication()._verify_protection_signature(message, certificate)
            rsa_key.verify.assert_called_once()

            ec_key = Mock(spec=ec.EllipticCurvePublicKey)
            certificate.public_key.return_value = ec_key
            CmpSignatureBasedInitializationAuthentication()._verify_protection_signature(message, certificate)
            ec_key.verify.assert_called_once()

    @pytest.mark.parametrize(
        ('protocol', 'operation', 'parsed_message', 'error'),
        [
            ('est', 'initialization', _typed_cmp_message(), 'requires CMP protocol'),
            ('cmp', 'initialization', None, 'requires a parsed message'),
            ('cmp', 'initialization', object(), 'requires a PKIMessage'),
        ],
    )
    def test_initialization_guards(self, protocol: str, operation: str, parsed_message: Any, error: str) -> None:
        context = CmpCertificateRequestContext(
            protocol=protocol, operation=operation, parsed_message=parsed_message
        )
        with pytest.raises(ValueError, match=error):
            CmpSignatureBasedInitializationAuthentication()._should_authenticate(context)

    def test_initialization_success_and_configuration_errors(self) -> None:
        certificate, _ = _certificate_and_csr()
        context = CmpCertificateRequestContext(
            protocol='cmp', operation='initialization', parsed_message=_typed_cmp_message()
        )
        device = Mock(domain=Mock(), onboarding_config=Mock())
        device.onboarding_config.onboarding_protocol = 'wrong'
        with pytest.raises(ValueError, match='Wrong onboarding protocol'):
            CmpSignatureBasedInitializationAuthentication()._verify_device_configuration(device)
        device.onboarding_config.onboarding_protocol = OnboardingProtocol.CMP_IDEVID
        device.onboarding_config.has_pki_protocol.return_value = False
        with pytest.raises(ValueError, match='PKI protocol CMP expected'):
            CmpSignatureBasedInitializationAuthentication()._verify_device_configuration(device)

        auth = CmpSignatureBasedInitializationAuthentication()
        with patch.object(auth, '_extract_extra_certs', return_value=(certificate, [])), \
                patch.object(auth, '_authenticate_and_verify_device', return_value=device), \
                patch.object(auth, '_should_authenticate', return_value=True):
            auth.authenticate(context)
        assert context.client_certificate is certificate
        assert context.device is device

    def test_certification_and_revocation_guards(self) -> None:
        certificate, _ = _certificate_and_csr()
        cert_auth = CmpSignatureBasedCertificationAuthentication()
        context = CmpCertificateRequestContext(protocol='cmp', operation='certification',
                                                parsed_message=_typed_cmp_message(), cert_profile_str=None)
        with patch('request.authentication.cmp.AlgorithmIdentifier.from_dotted_string', return_value='signature'):
            with pytest.raises(ValueError, match='Missing application certificate template'):
                cert_auth._should_authenticate(context)
        with pytest.raises(ValueError, match='signer certificate is missing'):
            cert_auth._authenticate_device(context)

        rev_auth = CmpSignatureBasedRevocationAuthentication()
        rev_context = CmpBaseRequestContext(protocol='cmp', operation='revocation',
                                            parsed_message=_typed_cmp_message())
        with pytest.raises(ValueError, match='requires a PKIMessage'):
            rev_context.parsed_message = object()
            rev_auth._should_authenticate(rev_context)

    def test_poll_fallback_and_idevid_errors(self) -> None:
        certificate, _ = _certificate_and_csr()
        auth = CmpSignatureBasedPollAuthentication()
        context = CmpPollRequestContext(protocol='cmp', cmp_body_type='pollReq',
                        parsed_message=_typed_cmp_message())
        with patch.object(auth, '_extract_extra_certs', return_value=(certificate, [])), \
                patch.object(auth, '_authenticate_with_domain_credential', return_value=None), \
            patch.object(auth, '_authenticate_with_idevid', return_value=None), \
            patch('request.authentication.cmp.AlgorithmIdentifier.from_dotted_string', return_value='signature'):
            with pytest.raises(ValueError, match='Device authentication failed'):
                auth.authenticate(context)
        with patch('request.authentication.cmp.IDevIDAuthenticator.authenticate_idevid_from_x509',
                   side_effect=ValueError('invalid')):
            assert auth._authenticate_with_idevid(context, certificate, []) is None
