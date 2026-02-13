"""Tests for AOKI views."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.http import JsonResponse
from django.test import RequestFactory
from pki.models.credential import CredentialModel, IDevIDReferenceModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from pki.util.idevid import IDevIDAuthenticationError
from pki.util.x509 import CertificateGenerator, ClientCertificateAuthenticationError

from aoki.views import AokiInitializationRequestView, AokiServiceMixin

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes


@pytest.fixture
def request_factory():
    """Provide a Django RequestFactory."""
    return RequestFactory()


@pytest.fixture
def mock_tls_cert():
    """Mock TLS server certificate."""
    tls_cert = Mock()
    credential = Mock()
    certificate = Mock()
    cert_serializer = Mock()
    cert_serializer.as_pem.return_value = b'-----BEGIN CERTIFICATE-----\nTLS_CERT\n-----END CERTIFICATE-----'
    certificate.get_certificate_serializer.return_value = cert_serializer
    credential.certificate = certificate
    credential.certificate_or_error = certificate
    tls_cert.credential = credential
    return tls_cert


@pytest.fixture
def mock_idevid_cert():
    """Create a mock IDevID certificate."""
    certs, keys = CertificateGenerator.create_test_pki(1)
    return certs[1]


@pytest.fixture
def mock_owner_credential(rsa_private_key: rsa.RSAPrivateKey):
    """Mock owner credential with private key."""
    owner_cred = Mock(spec=CredentialModel)
    
    # Create a real certificate for the owner
    cert, _ = CertificateGenerator.create_root_ca('Owner Certificate')
    cert_serializer = Mock()
    cert_serializer.as_pem.return_value = cert.public_bytes(serialization.Encoding.PEM)
    
    owner_cert = Mock()
    owner_cert.get_certificate_serializer.return_value = cert_serializer
    
    owner_cred.get_private_key.return_value = rsa_private_key
    owner_cred.certificate = owner_cert
    owner_cred.certificate_or_error = owner_cert
    
    return owner_cred


class TestAokiServiceMixin:
    """Tests for AokiServiceMixin."""

    def test_get_idevid_owner_san_uri_with_serial_number(self, mock_idevid_cert: x509.Certificate):
        """Test generating owner SAN URI from IDevID certificate with serial number."""
        san_uri = AokiServiceMixin.get_idevid_owner_san_uri(mock_idevid_cert)
        
        assert san_uri.startswith('dev-owner:')
        parts = san_uri.split(':')[1].split('.')
        assert len(parts) == 3
        # Check that the x509 serial number and fingerprint are present
        assert len(parts[1]) >= 16  # x509 serial number in hex
        assert len(parts[2]) == 64  # SHA256 fingerprint in hex

    def test_get_idevid_owner_san_uri_without_serial_number(self):
        """Test generating owner SAN URI when certificate has no serial number."""
        # Create a certificate without a subject serial number
        cert, _ = CertificateGenerator.create_root_ca('Test CA')
        
        san_uri = AokiServiceMixin.get_idevid_owner_san_uri(cert)
        
        assert san_uri.startswith('dev-owner:_.')
        parts = san_uri.split(':')[1].split('.')
        assert len(parts) == 3
        assert parts[0] == '_'

    def test_get_owner_credential_exists(self, mock_idevid_cert: x509.Certificate, mock_owner_credential):
        """Test retrieving owner credential that exists in database."""
        with patch.object(AokiServiceMixin, 'get_idevid_owner_san_uri', return_value='dev-owner:test.123.abc'):
            with patch.object(IDevIDReferenceModel.objects, 'filter') as mock_filter:
                mock_ref = Mock()
                mock_ref.dev_owner_id.credential = mock_owner_credential
                mock_filter.return_value.first.return_value = mock_ref
                
                result = AokiServiceMixin.get_owner_credential(mock_idevid_cert)
                
                assert result == mock_owner_credential
                mock_filter.assert_called_once_with(idevid_ref='dev-owner:test.123.abc')

    def test_get_owner_credential_not_exists(self, mock_idevid_cert: x509.Certificate):
        """Test retrieving owner credential that does not exist in database."""
        with patch.object(AokiServiceMixin, 'get_idevid_owner_san_uri', return_value='dev-owner:test.123.abc'):
            with patch.object(IDevIDReferenceModel.objects, 'filter') as mock_filter:
                mock_filter.return_value.first.return_value = None
                
                result = AokiServiceMixin.get_owner_credential(mock_idevid_cert)
                
                assert result is None


class TestAokiInitializationRequestView:
    """Tests for AokiInitializationRequestView."""

    def test_get_no_tls_cert(self, request_factory):
        """Test AOKI initialization when no TLS server certificate is available."""
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=None):
            request = request_factory.get('/aoki/init/')
            view = AokiInitializationRequestView()
            
            response = view.get(request)
            
            assert response.status_code == 500
            assert b'No TLS server certificate available' in response.content

    def test_get_no_client_cert(self, request_factory, mock_tls_cert):
        """Test AOKI initialization when no client certificate is provided."""
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=mock_tls_cert):
            with patch('aoki.views.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                      side_effect=ClientCertificateAuthenticationError('No cert')):
                request = request_factory.get('/aoki/init/')
                view = AokiInitializationRequestView()
                
                response = view.get(request)
                
                assert response.status_code == 401
                assert b'No valid TLS client certificate provided' in response.content

    def test_get_idevid_authentication_failed(self, request_factory, mock_tls_cert, mock_idevid_cert):
        """Test AOKI initialization when IDevID authentication fails."""
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=mock_tls_cert):
            with patch('aoki.views.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                      return_value=(mock_idevid_cert, [])):
                with patch('aoki.views.IDevIDAuthenticator.authenticate_idevid_from_x509_no_device',
                          side_effect=IDevIDAuthenticationError('Auth failed')):
                    request = request_factory.get('/aoki/init/')
                    view = AokiInitializationRequestView()
                    
                    response = view.get(request)
                    
                    assert response.status_code == 403
                    assert b'IDevID authentication failed' in response.content

    def test_get_no_owner_credential(self, request_factory, mock_tls_cert, mock_idevid_cert, domain_instance):
        """Test AOKI initialization when no DevOwnerID is present."""
        domain = domain_instance['domain']
        
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=mock_tls_cert):
            with patch('aoki.views.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                      return_value=(mock_idevid_cert, [])):
                with patch('aoki.views.IDevIDAuthenticator.authenticate_idevid_from_x509_no_device',
                          return_value=(domain, 'test_sn')):
                    with patch.object(AokiInitializationRequestView, 'get_owner_credential', return_value=None):
                        request = request_factory.get('/aoki/init/')
                        view = AokiInitializationRequestView()
                        
                        response = view.get(request)
                        
                        assert response.status_code == 422
                        assert b'No DevOwnerID present for this IDevID' in response.content

    def test_get_successful_rsa_signature(
        self, 
        request_factory, 
        mock_tls_cert, 
        mock_idevid_cert, 
        domain_instance,
        mock_owner_credential,
        rsa_private_key: rsa.RSAPrivateKey
    ):
        """Test successful AOKI initialization with RSA signature."""
        domain = domain_instance['domain']
        mock_owner_credential.get_private_key.return_value = rsa_private_key
        
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=mock_tls_cert):
            with patch('aoki.views.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                      return_value=(mock_idevid_cert, [])):
                with patch('aoki.views.IDevIDAuthenticator.authenticate_idevid_from_x509_no_device',
                          return_value=(domain, 'test_sn')):
                    with patch.object(AokiInitializationRequestView, 'get_owner_credential', 
                                    return_value=mock_owner_credential):
                        request = request_factory.get('/aoki/init/')
                        view = AokiInitializationRequestView()
                        
                        response = view.get(request)
                        
                        assert response.status_code == 200
                        assert isinstance(response, JsonResponse)
                        assert 'AOKI-Signature' in response.headers
                        assert 'AOKI-Signature-Algorithm' in response.headers
                        assert response.headers['AOKI-Signature-Algorithm'] == '1.2.840.113549.1.1.11'  # RSA_SHA256
                        
                        # Verify signature can be decoded
                        signature = base64.b64decode(response.headers['AOKI-Signature'])
                        assert len(signature) > 0
                        
                        # Verify response structure
                        import json
                        data = json.loads(response.content)
                        assert 'aoki-init' in data
                        assert data['aoki-init']['version'] == '1.0'
                        assert 'enrollment-info' in data['aoki-init']
                        assert 'owner-id-cert' in data['aoki-init']
                        assert 'tls-truststore' in data['aoki-init']

    def test_get_successful_ec_signature(
        self, 
        request_factory, 
        mock_tls_cert, 
        mock_idevid_cert, 
        domain_instance,
        mock_owner_credential,
        ec_private_key: ec.EllipticCurvePrivateKey
    ):
        """Test successful AOKI initialization with EC signature."""
        domain = domain_instance['domain']
        mock_owner_credential.get_private_key.return_value = ec_private_key
        
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=mock_tls_cert):
            with patch('aoki.views.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                      return_value=(mock_idevid_cert, [])):
                with patch('aoki.views.IDevIDAuthenticator.authenticate_idevid_from_x509_no_device',
                          return_value=(domain, 'test_sn')):
                    with patch.object(AokiInitializationRequestView, 'get_owner_credential', 
                                    return_value=mock_owner_credential):
                        request = request_factory.get('/aoki/init/')
                        view = AokiInitializationRequestView()
                        
                        response = view.get(request)
                        
                        assert response.status_code == 200
                        assert isinstance(response, JsonResponse)
                        assert 'AOKI-Signature' in response.headers
                        assert 'AOKI-Signature-Algorithm' in response.headers
                        assert response.headers['AOKI-Signature-Algorithm'] == '1.2.840.10045.4.3.2'  # ECDSA_SHA256

    def test_get_unsupported_key_type(
        self, 
        request_factory, 
        mock_tls_cert, 
        mock_idevid_cert, 
        domain_instance,
        mock_owner_credential
    ):
        """Test AOKI initialization with unsupported private key type."""
        domain = domain_instance['domain']
        # Mock an unsupported key type
        mock_owner_credential.get_private_key.return_value = Mock()
        
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=mock_tls_cert):
            with patch('aoki.views.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                      return_value=(mock_idevid_cert, [])):
                with patch('aoki.views.IDevIDAuthenticator.authenticate_idevid_from_x509_no_device',
                          return_value=(domain, 'test_sn')):
                    with patch.object(AokiInitializationRequestView, 'get_owner_credential', 
                                    return_value=mock_owner_credential):
                        request = request_factory.get('/aoki/init/')
                        view = AokiInitializationRequestView()
                        
                        with pytest.raises(TypeError, match='Unsupported private key type'):
                            view.get(request)

    def test_http_method_names(self):
        """Test that only GET method is allowed."""
        view = AokiInitializationRequestView()
        assert view.http_method_names == ('get',)

    def test_enrollment_info_structure(
        self, 
        request_factory, 
        mock_tls_cert, 
        mock_idevid_cert, 
        domain_instance,
        mock_owner_credential,
        rsa_private_key: rsa.RSAPrivateKey
    ):
        """Test the structure of enrollment-info in the response."""
        domain = domain_instance['domain']
        mock_owner_credential.get_private_key.return_value = rsa_private_key
        
        with patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'first', return_value=mock_tls_cert):
            with patch('aoki.views.NginxTLSClientCertExtractor.get_client_cert_as_x509',
                      return_value=(mock_idevid_cert, [])):
                with patch('aoki.views.IDevIDAuthenticator.authenticate_idevid_from_x509_no_device',
                          return_value=(domain, 'test_sn')):
                    with patch.object(AokiInitializationRequestView, 'get_owner_credential', 
                                    return_value=mock_owner_credential):
                        request = request_factory.get('/aoki/init/')
                        view = AokiInitializationRequestView()
                        
                        response = view.get(request)
                        
                        import json
                        data = json.loads(response.content)
                        enrollment_info = data['aoki-init']['enrollment-info']
                        
                        assert 'protocols' in enrollment_info
                        assert len(enrollment_info['protocols']) > 0
                        
                        # Check EST protocol is present
                        est_protocol = enrollment_info['protocols'][0]
                        assert est_protocol['protocol'] == 'EST'
                        assert 'url' in est_protocol
                        assert domain.unique_name in est_protocol['url']
