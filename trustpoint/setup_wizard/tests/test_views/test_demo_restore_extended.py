"""Comprehensive tests for demo data and restore views."""

import subprocess
from unittest.mock import Mock, patch

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from pki.models import CredentialModel, CaModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard import SetupWizardState
from setup_wizard.forms import EmptyForm
from setup_wizard.views import (
    SetupWizardDemoDataView,
    BackupRestoreView
)


@pytest.mark.django_db
class TestSetupWizardDemoDataView:
    """Test demo data view."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardDemoDataView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self):
        """Test dispatch when not in Docker."""
        request = self.factory.get('/demo-data/')
        
        response = self.view.dispatch(request)
        
        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_dispatch_wrong_state(self, mock_redirect, mock_get_state):
        """Test dispatch with wrong wizard state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_redirect.return_value = Mock(status_code=302, url='/redirect/')
        
        request = self.factory.get('/demo-data/')
        
        response = self.view.dispatch(request)
        
        assert response.status_code == 302


@pytest.mark.django_db
class TestTrustStoreDownload:
    """Test trust store download functionality in TlsServerCredentialApplyView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        from setup_wizard.views import SetupWizardTlsServerCredentialApplyView
        self.view = SetupWizardTlsServerCredentialApplyView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_generate_trust_store_not_found(self, mock_get, mock_get_state):
        """Test trust store download when credential doesn't exist."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        mock_get.side_effect = ActiveTrustpointTlsServerCredentialModel.DoesNotExist()
        
        request = self.factory.get('/apply-tls/download/pem/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        self.view.kwargs = {'file_format': 'pem'}
        
        response = self.view._generate_trust_store_response('pem')
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('No trust store available' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_generate_trust_store_invalid_format(self, mock_get, mock_get_state):
        """Test trust store download with invalid format."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_credential = Mock(spec=CredentialModel)
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_get.return_value = mock_active
        
        request = self.factory.get('/apply-tls/download/invalid/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        self.view.kwargs = {'file_format': 'invalid'}
        
        response = self.view._generate_trust_store_response('invalid')
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('Invalid file format' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_generate_trust_store_pem_success(self, mock_get, mock_get_state):
        """Test successful PEM trust store download."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_serializer = Mock()
        mock_serializer.as_pem.return_value = b'PEM DATA'
        
        mock_certificate = Mock()
        mock_certificate.get_certificate_serializer.return_value = mock_serializer
        
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.certificate = mock_certificate
        
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_get.return_value = mock_active
        
        request = self.factory.get('/apply-tls/download/pem/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        self.view.kwargs = {'file_format': 'pem'}
        
        response = self.view._generate_trust_store_response('pem')
        
        assert response.status_code == 200
        assert response['Content-Type'] == 'application/x-pem-file'
        assert 'trust_store.pem' in response['Content-Disposition']

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_generate_trust_store_pkcs7_der_success(self, mock_get, mock_get_state):
        """Test successful PKCS7 DER trust store download."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_serializer = Mock()
        mock_serializer.as_pkcs7_der.return_value = b'\x30\x82'  # Binary data that won't decode
        
        mock_certificate = Mock()
        mock_certificate.get_certificate_serializer.return_value = mock_serializer
        
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.certificate = mock_certificate
        
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_get.return_value = mock_active
        
        request = self.factory.get('/apply-tls/download/pkcs7_der/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        self.view.kwargs = {'file_format': 'pkcs7_der'}
        
        response = self.view._generate_trust_store_response('pkcs7_der')
        
        assert response.status_code == 200
        assert response['Content-Type'] == 'application/pkcs7-mime'
        assert 'trust_store.pkcs7_der' in response['Content-Disposition']

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_generate_trust_store_exception(self, mock_get, mock_get_state):
        """Test trust store download with exception during generation."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_certificate = Mock()
        mock_certificate.get_certificate_serializer.side_effect = Exception('Serialization error')
        
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.certificate = mock_certificate
        
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_get.return_value = mock_active
        
        request = self.factory.get('/apply-tls/download/pem/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        self.view.kwargs = {'file_format': 'pem'}
        
        response = self.view._generate_trust_store_response('pem')
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('Error generating' in str(m) for m in messages_list)
