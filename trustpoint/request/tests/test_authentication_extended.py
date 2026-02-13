"""Extended tests for request/authentication.py to increase coverage."""

from typing import Any
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc4210

from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
)
from pki.util.keys import KeyGenerator
from request.authentication import (
    ClientCertificateAuthentication,
    IDevIDAuthentication,
)
from request.authentication.cmp import CmpSharedSecretAuthentication
from request.authentication.est import UsernamePasswordAuthentication
from request.request_context import (
    BaseRequestContext,
    EstBaseRequestContext,
    CmpBaseRequestContext,
    HttpBaseRequestContext,
)


@pytest.mark.django_db
class TestUsernamePasswordAuthenticationExtended:
    """Extended tests for UsernamePasswordAuthentication."""

    def test_authenticate_device_without_est_password(self, device_instance: dict[str, Any]) -> None:
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

        with pytest.raises(ValueError, match='Authentication failed: Invalid username or password'):
            auth.authenticate(context)

    def test_authenticate_device_without_config(self, domain_instance: dict[str, Any]) -> None:
        """Test authentication fails when device has no onboarding or no_onboarding config."""
        domain = domain_instance['domain']

        # Create device without any config
        device = DeviceModel.objects.create(
            common_name='device-no-config',
            serial_number='SN-NO-CONFIG',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
        )

        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = device.common_name
        context.est_password = 'anypassword'

        with pytest.raises(ValueError, match='Authentication failed: Invalid username or password'):
            auth.authenticate(context)

    def test_authenticate_exception_during_lookup(self) -> None:
        """Test authentication handles exceptions during device lookup."""
        auth = UsernamePasswordAuthentication()
        context = Mock(spec=EstBaseRequestContext)
        context.est_username = 'test-user'
        context.est_password = 'test-pass'

        # Mock DeviceModel.objects to raise exception
        with patch('devices.models.DeviceModel.objects') as mock_objects:
            mock_objects.select_related.return_value.filter.side_effect = Exception('Database error')

            with pytest.raises(ValueError, match='Authentication failed: Invalid username or password'):
                auth.authenticate(context)


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

    def test_authenticate_certificate_not_found_in_db(self, device_instance: dict[str, Any]) -> None:
        """Test authentication fails when certificate is not found in database."""
        device = device_instance['device']
        domain = device_instance['domain']

        # Create a certificate that's not in the database
        private_key = KeyGenerator.generate_private_key(domain=domain)

        # Build a self-signed certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Unknown Certificate'),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key_serializer.as_crypto())
            .serial_number(x509.random_serial_number())
            .not_valid_before(device_instance['cert'].not_valid_before_utc)
            .not_valid_after(device_instance['cert'].not_valid_after_utc)
            .sign(private_key.as_crypto(), hashes.SHA256())
        )

        auth = ClientCertificateAuthentication()
        context = Mock(spec=BaseRequestContext)
        context.client_certificate = cert

        with pytest.raises(ValueError, match='Client certificate not recognized'):
            auth.authenticate(context)

    def test_authenticate_invalid_domain_credential(self, device_instance: dict[str, Any]) -> None:
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
            mock_valid.return_value = (False, 'Certificate is revoked')

            with pytest.raises(ValueError, match='Invalid HTTP_SSL_CLIENT_CERT header: Certificate is revoked'):
                auth.authenticate(context)


@pytest.mark.django_db
class TestCmpSharedSecretAuthentication:
    """Tests for CMP Shared Secret Authentication."""

    def test_authenticate_non_cmp_protocol(self) -> None:
        """Test authentication raises error when protocol is not CMP."""
        auth = CmpSharedSecretAuthentication()
        context = Mock(spec=CmpBaseRequestContext)
        context.protocol = 'est'  # Wrong protocol

        with pytest.raises(ValueError, match='CMP shared secret authentication requires CMP protocol'):
            auth.authenticate(context)

    def test_authenticate_no_parsed_message(self) -> None:
        """Test authentication raises error when no parsed message."""
        auth = CmpSharedSecretAuthentication()
        context = Mock(spec=CmpBaseRequestContext)
        context.protocol = 'cmp'
        context.parsed_message = None

        with pytest.raises(ValueError, match='CMP shared secret authentication requires a parsed message'):
            auth.authenticate(context)

    def test_authenticate_invalid_message_type(self) -> None:
        """Test authentication raises error with invalid message type."""
        auth = CmpSharedSecretAuthentication()
        context = Mock(spec=CmpBaseRequestContext)
        context.protocol = 'cmp'
        context.parsed_message = Mock()  # Not a PKIMessage
        context.parsed_message.__class__.__name__ = 'SomeOtherType'

        with pytest.raises(TypeError, match='CMP shared secret authentication requires a PKIMessage'):
            auth.authenticate(context)


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

    def test_authenticate_with_valid_idevid(self, device_instance: dict[str, Any]) -> None:
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

    def test_authenticate_idevid_authentication_error(self, device_instance: dict[str, Any]) -> None:
        """Test authentication fails when IDevID authentication raises error."""
        domain = device_instance['domain']

        auth = IDevIDAuthentication()
        context = Mock(spec=HttpBaseRequestContext)
        context.raw_message = Mock()  # Non-None raw message
        context.domain = domain

        # Mock the IDevIDAuthenticator to raise error
        with patch('request.authentication.base.IDevIDAuthenticator.authenticate_idevid') as mock_auth_method:
            from pki.util.idevid import IDevIDAuthenticationError

            mock_auth_method.side_effect = IDevIDAuthenticationError('Invalid IDevID')

            with pytest.raises(ValueError, match='Error validating the IDevID'):
                auth.authenticate(context)

    def test_authenticate_no_device_associated(self, device_instance: dict[str, Any]) -> None:
        """Test authentication fails when no device is associated."""
        domain = device_instance['domain']

        auth = IDevIDAuthentication()
        context = Mock(spec=HttpBaseRequestContext)
        context.raw_message = Mock()  # Non-None raw message
        context.domain = domain

        # Mock the IDevIDAuthenticator to return None
        with patch('request.authentication.base.IDevIDAuthenticator.authenticate_idevid') as mock_auth_method:
            mock_auth_method.return_value = None

            with pytest.raises(ValueError, match='IDevID authentication failed: No device associated'):
                auth.authenticate(context)

    def test_authenticate_device_without_domain(self, device_instance: dict[str, Any]) -> None:
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

            with pytest.raises(ValueError, match='IDevID authentication failed: Device domain is not set'):
                auth.authenticate(context)


@pytest.mark.django_db
class TestCompositeAuthentication:
    """Tests for composite authentication patterns."""

    def test_multiple_authentication_methods(self, device_instance: dict[str, Any]) -> None:
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

    def test_authentication_with_onboarding_config(self, device_instance_onboarding: dict[str, Any]) -> None:
        """Test authentication works with onboarding config."""
        device = device_instance_onboarding['device']

        # Use the device's existing onboarding config and set a password
        if device.onboarding_config:
            # Update the existing config
            onboarding_config = device.onboarding_config
            # Only set password if protocol supports it
            from devices.models import OnboardingProtocol

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
            from devices.models import OnboardingProtocol

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

    def test_username_password_with_special_characters(self, domain_instance: dict[str, Any]) -> None:
        """Test authentication with special characters in username/password."""
        domain = domain_instance['domain']

        # Create device with special characters
        device = DeviceModel.objects.create(
            common_name='device-special-@#$',
            serial_number='SN-SPECIAL',
            domain=domain,
            device_type=DeviceModel.DeviceType.GENERIC_DEVICE,
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

    def test_case_sensitive_username(self, device_instance: dict[str, Any]) -> None:
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

        with pytest.raises(ValueError, match='Authentication failed: Invalid username or password'):
            auth.authenticate(context)
