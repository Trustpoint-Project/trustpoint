"""Unit tests for authentication components."""
import datetime
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from devices.models import IssuedCredentialModel

from request.authentication.base import (
    ClientCertificateAuthentication,
    UsernamePasswordAuthentication,
)
from request.request_context import RequestContext


class TestUsernamePasswordAuthentication:
    """Test cases for UsernamePasswordAuthentication."""

    def setup_method(self):
        """Set up test fixtures."""
        self.auth = UsernamePasswordAuthentication()
        self.context = Mock(spec=RequestContext)

    def test_authenticate_success(self, est_device_without_onboarding):
        """Test successful username/password authentication."""
        device = est_device_without_onboarding['device']
        self.context.est_username = device.common_name
        self.context.est_password = device.no_onboarding_config.est_password

        self.auth.authenticate(self.context)

        assert self.context.device == device

    def test_authenticate_invalid_password(self, device_instance):
        """Test authentication with invalid password."""
        device = device_instance['device']
        self.context.est_username = device.common_name
        self.context.est_password = 'wrongpass'

        try:
            self.auth.authenticate(self.context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Authentication failed: Invalid username or password.' in str(e)

    def test_authenticate_invalid_username(self, est_device_without_onboarding):
        """Test authentication with invalid username."""
        device = est_device_without_onboarding['device']
        self.context.est_username = 'wronguser'
        self.context.est_password = device.no_onboarding_config.est_password

        try:
            self.auth.authenticate(self.context)
            assert False, 'Expected ValueError to be raised'
        except ValueError as e:
            assert 'Authentication failed: Invalid username or password.' in str(e)

    def test_authenticate_missing_credentials(self):
        """Test authentication with missing credentials."""
        self.context.est_username = None
        self.context.est_password = None

        result = self.auth.authenticate(self.context)

        assert result is None

    def test_authenticate_missing_username(self, est_device_without_onboarding):
        """Test authentication with missing username."""
        device = est_device_without_onboarding['device']
        self.context.est_username = None
        self.context.est_password = device.no_onboarding_config.est_password

        result = self.auth.authenticate(self.context)

        assert result is None

    def test_authenticate_missing_password(self, device_instance):
        """Test authentication with missing password."""
        device = device_instance['device']
        self.context.est_username = device.common_name
        self.context.est_password = None

        result = self.auth.authenticate(self.context)

        assert result is None


class TestClientCertificateAuthentication:
    """Test cases for ClientCertificateAuthentication."""

    def setup_method(self):
        """Set up test fixtures."""
        self.auth = ClientCertificateAuthentication()
        self.context = Mock(spec=RequestContext)

    def test_authenticate_success(self, domain_credential_est_onboarding):
        """Test successful client certificate authentication."""
        device = domain_credential_est_onboarding['device']
        domain_credential = domain_credential_est_onboarding['domain_credential']
        client_cert = domain_credential.credential.get_certificate()

        self.context.client_certificate = client_cert

        self.auth.authenticate(self.context)

        assert self.context.device == device

    def test_authenticate_credential_not_found(self):
        """Test authentication when credential is not found."""
        mock_cert = Mock()
        self.context.client_certificate = mock_cert

        with patch.object(IssuedCredentialModel, 'get_credential_for_certificate',
                          side_effect=IssuedCredentialModel.DoesNotExist()):
            try:
                self.auth.authenticate(self.context)
                assert False, 'Expected ValueError to be raised'
            except ValueError:
                pass

    def test_authenticate_invalid_credential(self, domain_credential_est_onboarding, rsa_private_key):
        """Test authentication with invalid credential."""
        device = domain_credential_est_onboarding['device']

        invalid_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Invalid Certificate')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Invalid Certificate')])
        ).public_key(
            rsa_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365)
        ).sign(rsa_private_key, hashes.SHA256())

        self.context.client_certificate = invalid_cert

        try:
            self.auth.authenticate(self.context)
            assert False, 'Expected ValueError to be raised'
        except ValueError:
            pass

    def test_authenticate_no_client_certificate(self):
        """Test authentication with no client certificate."""
        self.context.client_certificate = None

        result = self.auth.authenticate(self.context)

        assert result is None


# TODO (FHK): Write tests for IDevID auth and reenrollment
