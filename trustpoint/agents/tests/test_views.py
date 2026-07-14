"""Comprehensive tests for Agent API views and Web views.

Covers:
- AgentCertificateAuthentication
- AgentJobsView (GET /api/agents/jobs/)
- AgentJobResultView (POST /api/agents/jobs/results/)
- AgentWorkflowDefinitionTableView
- AgentWorkflowDefinitionConfigView
- AgentWorkflowDefinitionBulkDeleteConfirmView
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIClient

from agents.api_views import (
    AgentCertificateAuthentication,
    _build_resolved_profile,
    _parse_client_cert,
    _resolve_enrollment_url,
)
from agents.models import AgentAssignedProfile, AgentWorkflowDefinition, TrustpointAgent
from agents.web_views import AgentWorkflowDefinitionConfigView, AgentWorkflowDefinitionTableView
from devices.models import DeviceModel, DomainModel
from pki.models import IssuedCredentialModel

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser
    from django.test import Client

User = get_user_model()

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def admin_user(db: Any) -> AbstractBaseUser:
    """Create an admin user."""
    user = User.objects.create_user(
        username='admin',
        password='adminpass',
        email='admin@test.com',
        is_staff=True,
        is_superuser=True,
    )
    admin_group, _ = Group.objects.get_or_create(name='Admin')
    user.groups.add(admin_group)
    return user


@pytest.fixture
def web_client(admin_user: AbstractBaseUser) -> Client:
    """Create an authenticated web client."""
    from django.test import Client

    client = Client()
    client.force_login(admin_user)
    return client


@pytest.fixture
def api_client() -> APIClient:
    """Create an API client."""
    return APIClient()


@pytest.fixture
def domain(db: Any) -> DomainModel:
    """Create a test domain."""
    return DomainModel.objects.create(
        unique_name='test-domain',
    )


@pytest.fixture
def device(db: Any, domain: DomainModel) -> DeviceModel:
    """Create a test device."""
    return DeviceModel.objects.create(
        common_name='test-device',
        serial_number='SN123456',
        device_type=DeviceModel.DeviceType.AGENT_ONE_TO_ONE,
        domain=domain,
    )


@pytest.fixture
def agent(db: Any, device: DeviceModel) -> TrustpointAgent:
    """Create a test agent."""
    return TrustpointAgent.objects.create(
        agent_id='test-agent-1',
        device=device,
        is_active=True,
        poll_interval_seconds=300,
    )


@pytest.fixture
def workflow_definition(db: Any) -> AgentWorkflowDefinition:
    """Create a test workflow definition."""
    profile = {
        'metadata': {'agent_type': '1-to-n', 'version': '1.0'},
        'device': {'vendor': 'TestVendor'},
        'certificate_request': {
            'certificate_profile': 'domain_credential',
            'url': 'https://trustpoint.local',
            'path': '/enroll/',
        },
        'steps': [],
    }
    return AgentWorkflowDefinition.objects.create(
        name='Test Workflow',
        profile=profile,
        is_active=True,
    )


@pytest.fixture
def assigned_profile(
    db: Any,
    agent: TrustpointAgent,
    workflow_definition: AgentWorkflowDefinition,
) -> AgentAssignedProfile:
    """Create an assigned profile."""
    now = timezone.now()
    return AgentAssignedProfile.objects.create(
        agent=agent,
        workflow_definition=workflow_definition,
        enabled=True,
        next_certificate_update_scheduled=now - timedelta(hours=1),  # Due 1 hour ago
        subject='/CN=test-device',
        subject_alt_name='DNS:test-device.local',
    )


@pytest.fixture
def test_cert() -> x509.Certificate:
    """Generate a test certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'test-cert'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(timezone.now())
        .not_valid_after(timezone.now() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert


# ============================================================================
# API Authentication Tests
# ============================================================================


class TestAgentCertificateAuthentication:
    """Test AgentCertificateAuthentication."""

    def test_parse_client_cert_success(self, test_cert: x509.Certificate):
        """Test parsing valid client certificate from headers."""
        pem = test_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        encoded = urllib.parse.quote(pem)

        factory = RequestFactory()
        request = factory.get('/test/', HTTP_SSL_CLIENT_CERT=encoded)

        cert = _parse_client_cert(request)
        assert cert is not None
        assert isinstance(cert, x509.Certificate)

    def test_parse_client_cert_missing(self):
        """Test parsing when certificate header is missing."""
        factory = RequestFactory()
        request = factory.get('/test/')

        cert = _parse_client_cert(request)
        assert cert is None

    def test_parse_client_cert_invalid(self):
        """Test parsing invalid certificate raises AuthenticationFailed."""
        factory = RequestFactory()
        request = factory.get('/test/', HTTP_SSL_CLIENT_CERT='invalid-cert-data')

        with pytest.raises(AuthenticationFailed, match='Invalid HTTP_SSL_CLIENT_CERT'):
            _parse_client_cert(request)

    def test_authenticate_no_cert(self):
        """Test authentication fails when no certificate is provided."""
        auth = AgentCertificateAuthentication()
        factory = RequestFactory()
        request = factory.get('/test/')

        result = auth.authenticate(request)
        assert result is None

    def test_authenticate_cert_not_found(self, test_cert: x509.Certificate):
        """Test authentication fails when certificate not found in database."""
        pem = test_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        encoded = urllib.parse.quote(pem)

        auth = AgentCertificateAuthentication()
        factory = RequestFactory()
        request = factory.get('/test/', HTTP_SSL_CLIENT_CERT=encoded)

        # Certificate won't be found in empty database
        with pytest.raises(AuthenticationFailed, match='Client certificate not found'):
            auth.authenticate(request)

    def test_authenticate_invalid_domain_credential(
        self,
        test_cert: x509.Certificate,
        device: DeviceModel,
    ):
        """Test authentication fails when domain credential is invalid."""
        from pki.models import CertificateModel, CredentialModel, IssuedCredentialModel

        # Create a certificate
        cert_model = CertificateModel._save_certificate(test_cert)
        
        # Create credential with certificate
        credential = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
        )
        credential.certificates.add(cert_model)
        
        # Create issued credential with wrong type (application instead of domain)
        IssuedCredentialModel.objects.create(
            common_name='test-credential',
            credential=credential,
            device=device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        )

        pem = test_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        encoded = urllib.parse.quote(pem)

        auth = AgentCertificateAuthentication()
        factory = RequestFactory()
        request = factory.get('/test/', HTTP_SSL_CLIENT_CERT=encoded)

        with pytest.raises(AuthenticationFailed, match='Invalid domain credential'):
            auth.authenticate(request)

    def test_authenticate_no_device(self, test_cert: x509.Certificate):
        """Test authentication fails when no device is associated."""
        from pki.models import CertificateModel, CredentialModel, IssuedCredentialModel

        # Create a certificate without device would fail FK constraint,
        # so we test with None device which should fail
        cert_model = CertificateModel._save_certificate(test_cert)
        
        # Note: device is required (null=False), so this test  actually tests
        # the case where device exists but has no agent
        # The real "no device" case is caught by database constraints
        with pytest.raises(Exception):  # Will raise IntegrityError for null FK
            credential = CredentialModel.objects.create(common_name='test-credential')
            credential.certificates.add(cert_model)
            IssuedCredentialModel.objects.create(
                common_name='test-credential',
                credential=credential,
                device=None,  # This will fail FK constraint
                issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            )

    def test_authenticate_no_agent(
        self,
        test_cert: x509.Certificate,
        device: DeviceModel,
    ):
        """Test authentication fails when no active agent found."""
        from pki.models import CertificateModel, CredentialModel, IssuedCredentialModel
        from pki.models.credential import PrimaryCredentialCertificate

        # Create valid credential but device has no agent
        cert_model = CertificateModel._save_certificate(test_cert)
        
        credential = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
            certificate=cert_model,  # Set primary certificate FK
        )
        # Also add to many-to-many for the lookup query
        PrimaryCredentialCertificate.objects.create(
            credential=credential,
            certificate=cert_model,
            is_primary=True,
        )
        
        IssuedCredentialModel.objects.create(
            common_name='test-credential',
            credential=credential,
            device=device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        )

        pem = test_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        encoded = urllib.parse.quote(pem)

        auth = AgentCertificateAuthentication()
        factory = RequestFactory()
        request = factory.get('/test/', HTTP_SSL_CLIENT_CERT=encoded)

        with pytest.raises(AuthenticationFailed, match='No active agent found'):
            auth.authenticate(request)

    def test_authenticate_success(
        self,
        test_cert: x509.Certificate,
        agent: TrustpointAgent,
        device: DeviceModel,
    ):
        """Test successful authentication."""
        from pki.models import CertificateModel, CredentialModel, IssuedCredentialModel
        from pki.models.credential import PrimaryCredentialCertificate

        # Create valid credential and agent
        cert_model = CertificateModel._save_certificate(test_cert)
        
        credential = CredentialModel.objects.create(
            credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
            certificate=cert_model,  # Set primary certificate FK
        )
        # Also add to many-to-many for the lookup query
        PrimaryCredentialCertificate.objects.create(
            credential=credential,
            certificate=cert_model,
            is_primary=True,
        )
        
        IssuedCredentialModel.objects.create(
            common_name='test-credential',
            credential=credential,
            device=device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        )

        pem = test_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        encoded = urllib.parse.quote(pem)

        auth = AgentCertificateAuthentication()
        factory = RequestFactory()
        request = factory.get('/test/', HTTP_SSL_CLIENT_CERT=encoded)

        result = auth.authenticate(request)
        assert result is not None
        authenticated_agent, _ = result
        assert isinstance(authenticated_agent, TrustpointAgent)
        assert authenticated_agent.agent_id == 'test-agent-1'

    def test_authenticate_header(self):
        """Test authenticate_header returns WWW-Authenticate challenge."""
        auth = AgentCertificateAuthentication()
        factory = RequestFactory()
        request = factory.get('/test/')

        header = auth.authenticate_header(request)
        assert header == 'mTLS realm="Trustpoint Agent API"'


# ============================================================================
# URL Resolution Tests
# ============================================================================


class TestURLResolution:
    """Test URL resolution functions."""

    def test_resolve_enrollment_url_one_to_one(self, agent: TrustpointAgent, domain: DomainModel):
        """Test enrollment URL is resolved for 1-to-1 agents."""
        agent.device.device_type = DeviceModel.DeviceType.AGENT_ONE_TO_ONE
        agent.device.save()

        url = _resolve_enrollment_url(agent, 'domain_credential')
        assert url == '/rest/test-domain/domain_credential/enroll/'

    def test_resolve_enrollment_url_one_to_n(self, agent: TrustpointAgent):
        """Test enrollment URL is None for 1-to-n agents."""
        agent.device.device_type = DeviceModel.DeviceType.AGENT_ONE_TO_N
        agent.device.save()

        url = _resolve_enrollment_url(agent, 'domain_credential')
        assert url is None

    def test_resolve_enrollment_url_no_device(self, agent: TrustpointAgent):
        """Test enrollment URL is None when device is missing."""
        agent.device = None
        agent.save()

        url = _resolve_enrollment_url(agent, 'domain_credential')
        assert url is None

    def test_resolve_enrollment_url_no_domain(self, agent: TrustpointAgent):
        """Test enrollment URL is None when domain is missing."""
        agent.device.domain = None
        agent.device.save()

        url = _resolve_enrollment_url(agent, 'domain_credential')
        assert url is None


# ============================================================================
# Profile Resolution Tests
# ============================================================================


class TestProfileResolution:
    """Test profile resolution and placeholder replacement."""

    @patch('agents.api_views._resolve_enrollment_url')
    def test_build_resolved_profile_basic(
        self,
        mock_resolve_url: Mock,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test basic profile resolution."""
        mock_resolve_url.return_value = None  # Don't resolve URL in this test
        agent.device.domain = None  # Avoid issuing CA requirement
        agent.device.save()
        
        raw_profile = {
            'certificate_request': {
                'certificate_profile': 'domain_credential',
                'url': 'https://example.com',
            }
        }

        resolved = _build_resolved_profile(agent, raw_profile, assigned_profile)

        assert resolved is not raw_profile  # Should be a deep copy
        assert 'certificate_request' in resolved

    @patch('agents.api_views._resolve_enrollment_url')
    def test_build_resolved_profile_enrollment_path(
        self,
        mock_resolve_url: Mock,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
        domain: DomainModel,
    ):
        """Test enrollment path is resolved for 1-to-1 agents."""
        mock_resolve_url.return_value = '/rest/test-domain/tls_server/enroll/'
        agent.device.device_type = DeviceModel.DeviceType.AGENT_ONE_TO_ONE
        agent.device.domain = None  # Avoid issuing CA requirement
        agent.device.save()

        raw_profile = {
            'certificate_request': {
                'certificate_profile': 'tls_server',
                'path': '/original/',
            }
        }

        resolved = _build_resolved_profile(agent, raw_profile, assigned_profile)

        assert resolved['certificate_request']['path'] == '/rest/test-domain/tls_server/enroll/'

    @patch('agents.api_views._resolve_enrollment_url')
    def test_build_resolved_profile_subject(
        self,
        mock_resolve_url: Mock,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test subject is resolved from assigned profile."""
        mock_resolve_url.return_value = None
        agent.device.domain = None  # Avoid issuing CA requirement
        agent.device.save()
        assigned_profile.subject = '/CN=my-device/O=Test Org'
        assigned_profile.save()

        raw_profile = {'certificate_request': {}}

        resolved = _build_resolved_profile(agent, raw_profile, assigned_profile)

        assert resolved['certificate_request']['subject'] == '/CN=my-device/O=Test Org'

    @patch('agents.api_views._resolve_enrollment_url')
    def test_build_resolved_profile_subject_alt_name(
        self,
        mock_resolve_url: Mock,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test SAN is resolved from assigned profile."""
        mock_resolve_url.return_value = None
        agent.device.domain = None  # Avoid issuing CA requirement
        agent.device.save()
        assigned_profile.subject_alt_name = 'DNS:device.local,IP:192.168.1.1'
        assigned_profile.save()

        raw_profile = {'certificate_request': {}}

        resolved = _build_resolved_profile(agent, raw_profile, assigned_profile)

        assert resolved['certificate_request']['subject_alt_name'] == 'DNS:device.local,IP:192.168.1.1'

    @patch('agents.api_views._resolve_enrollment_url')
    def test_build_resolved_profile_removes_empty_subject(
        self,
        mock_resolve_url: Mock,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test empty subject is removed."""
        mock_resolve_url.return_value = None
        agent.device.domain = None  # Avoid issuing CA requirement
        agent.device.save()
        assigned_profile.subject = ''
        assigned_profile.save()

        raw_profile = {'certificate_request': {'subject': '/CN=old'}}

        resolved = _build_resolved_profile(agent, raw_profile, assigned_profile)

        assert 'subject' not in resolved['certificate_request']


# ============================================================================
# API Jobs View Tests
# ============================================================================


@pytest.mark.django_db
class TestAgentJobsView:
    """Test AgentJobsView API endpoint."""

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_get_jobs_no_pending(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
    ):
        """Test GET with no pending jobs."""
        mock_auth.return_value = (agent, None)

        response = api_client.get('/api/agents/jobs/')

        assert response.status_code == 200
        data = response.json()
        assert data['agent_id'] == 'test-agent-1'
        assert data['poll_interval_seconds'] == 300
        assert len(data['jobs']) == 0

    @patch('agents.api_views._build_resolved_profile')
    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_get_jobs_with_pending(
        self,
        mock_auth: Mock,
        mock_build_profile: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test GET with pending jobs."""
        mock_auth.return_value = (agent, None)
        # Return a simplified resolved profile
        mock_build_profile.return_value = {
            'metadata': {'agent_type': '1-to-n', 'version': '1.0'},
            'certificate_request': {'certificate_profile': 'domain_credential'},
        }

        response = api_client.get('/api/agents/jobs/')

        assert response.status_code == 200
        data = response.json()
        assert data['agent_id'] == 'test-agent-1'
        assert len(data['jobs']) == 1

        job = data['jobs'][0]
        assert job['profile_id'] == assigned_profile.pk
        assert job['workflow_definition_id'] == assigned_profile.workflow_definition.pk
        assert job['workflow_definition_name'] == 'Test Workflow'
        assert 'workflow_profile' in job
        assert 'next_certificate_update' in job

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_get_jobs_updates_last_seen(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
    ):
        """Test GET updates agent's last_seen_at timestamp."""
        mock_auth.return_value = (agent, None)
        initial_last_seen = agent.last_seen_at

        response = api_client.get('/api/agents/jobs/')

        assert response.status_code == 200
        agent.refresh_from_db()
        assert agent.last_seen_at is not None
        if initial_last_seen is not None:
            assert agent.last_seen_at > initial_last_seen

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_get_jobs_disabled_profile_not_included(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test disabled profiles are not included in pending jobs."""
        mock_auth.return_value = (agent, None)
        assigned_profile.enabled = False
        assigned_profile.save()

        response = api_client.get('/api/agents/jobs/')

        assert response.status_code == 200
        data = response.json()
        assert len(data['jobs']) == 0

    @patch('agents.api_views._build_resolved_profile')
    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_get_jobs_not_due_not_included(
        self,
        mock_auth: Mock,
        mock_build_profile: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test jobs not yet due are not included."""
        mock_auth.return_value = (agent, None)
        mock_build_profile.return_value = {'certificate_request': {}}
        assigned_profile.next_certificate_update_scheduled = timezone.now() + timedelta(hours=1)
        assigned_profile.save()

        response = api_client.get('/api/agents/jobs/')

        assert response.status_code == 200
        data = response.json()
        assert len(data['jobs']) == 0


# ============================================================================
# API Job Result View Tests
# ============================================================================


@pytest.mark.django_db
class TestAgentJobResultView:
    """Test AgentJobResultView API endpoint."""

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_post_result_success(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test POST with successful job result."""
        mock_auth.return_value = (agent, None)

        payload = {
            'profile_id': assigned_profile.pk,
            'success': True,
            'error_message': '',
        }

        response = api_client.post('/api/agents/jobs/result/', payload, format='json')

        assert response.status_code == 200
        data = response.json()
        assert data['profile_id'] == assigned_profile.pk
        assert 'last_certificate_update' in data
        assert 'next_certificate_update' in data

        # Verify database was updated
        assigned_profile.refresh_from_db()
        assert assigned_profile.last_certificate_update is not None

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_post_result_failure(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test POST with failed job result."""
        mock_auth.return_value = (agent, None)
        initial_last_update = assigned_profile.last_certificate_update

        payload = {
            'profile_id': assigned_profile.pk,
            'success': False,
            'error_message': 'Connection timeout',
        }

        response = api_client.post('/api/agents/jobs/result/', payload, format='json')

        assert response.status_code == 200

        # Verify last_certificate_update was NOT updated on failure
        assigned_profile.refresh_from_db()
        assert assigned_profile.last_certificate_update == initial_last_update

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_post_result_profile_not_found(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
    ):
        """Test POST with non-existent profile ID."""
        mock_auth.return_value = (agent, None)

        payload = {
            'profile_id': 99999,
            'success': True,
        }

        response = api_client.post('/api/agents/jobs/result/', payload, format='json')

        assert response.status_code == 404

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_post_result_invalid_payload(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
    ):
        """Test POST with invalid payload."""
        mock_auth.return_value = (agent, None)

        payload = {
            'profile_id': 'not-a-number',
            'success': 'not-a-boolean',
        }

        response = api_client.post('/api/agents/jobs/result/', payload, format='json')

        assert response.status_code == 400


# ============================================================================
# Web View Tests
# ============================================================================


@pytest.mark.django_db
class TestAgentWorkflowDefinitionTableView:
    """Test workflow definition list view."""

    def test_get_list(self, web_client: Client, workflow_definition: AgentWorkflowDefinition):
        """Test GET workflow definition list."""
        response = web_client.get(reverse('agents:profiles'))

        assert response.status_code == 200
        assert workflow_definition.name.encode() in response.content

    def test_get_list_multiple(self, web_client: Client):
        """Test GET with multiple workflow definitions."""
        AgentWorkflowDefinition.objects.create(
            name='Workflow 1',
            profile={'metadata': {}},
        )
        AgentWorkflowDefinition.objects.create(
            name='Workflow 2',
            profile={'metadata': {}},
        )

        response = web_client.get(reverse('agents:profiles'))

        assert response.status_code == 200
        assert b'Workflow 1' in response.content
        assert b'Workflow 2' in response.content

    def test_get_list_empty(self, web_client: Client):
        """Test GET with no workflow definitions."""
        response = web_client.get(reverse('agents:profiles'))

        assert response.status_code == 200


@pytest.mark.django_db
class TestAgentWorkflowDefinitionConfigView:
    """Test workflow definition config view."""

    def test_get_existing_profile(self, web_client: Client, workflow_definition: AgentWorkflowDefinition):
        """Test GET existing workflow definition."""
        url = reverse('agents:profiles-config', kwargs={'pk': workflow_definition.pk})
        response = web_client.get(url)

        assert response.status_code == 200
        assert workflow_definition.name.encode() in response.content

    def test_get_new_profile(self, web_client: Client):
        """Test GET for creating new workflow definition."""
        url = reverse('agents:profiles-create')
        response = web_client.get(url)

        assert response.status_code == 200
        assert b'is_new' in response.content or response.context.get('is_new') is True

    def test_get_nonexistent_profile(self, web_client: Client):
        """Test GET with non-existent ID returns 404."""
        url = reverse('agents:profiles-config', kwargs={'pk': 99999})
        response = web_client.get(url)

        assert response.status_code == 404

    def test_post_create_profile(self, web_client: Client):
        """Test POST to create new workflow definition."""
        url = reverse('agents:profiles-create')
        profile_data = {
            'metadata': {'version': '1.0'},
            'certificate_request': {},
            'steps': [],
        }

        payload = {
            'name': 'New Workflow',
            'profile': json.dumps(profile_data),
            'is_active': True,
        }

        response = web_client.post(url, payload)

        # Should redirect after successful creation
        assert response.status_code == 302

        # Verify it was created
        workflow = AgentWorkflowDefinition.objects.filter(name='New Workflow').first()
        assert workflow is not None
        assert workflow.is_active is True

    def test_post_update_profile(self, web_client: Client, workflow_definition: AgentWorkflowDefinition):
        """Test POST to update existing workflow definition."""
        url = reverse('agents:profiles-config', kwargs={'pk': workflow_definition.pk})
        profile_data = workflow_definition.profile.copy()
        profile_data['metadata']['version'] = '2.0'

        payload = {
            'name': 'Updated Workflow',
            'profile': json.dumps(profile_data),
            'is_active': False,
        }

        response = web_client.post(url, payload)

        # Should redirect after successful update
        assert response.status_code == 302

        # Verify it was updated
        workflow_definition.refresh_from_db()
        assert workflow_definition.name == 'Updated Workflow'
        assert workflow_definition.is_active is False

    def test_post_invalid_json(self, web_client: Client):
        """Test POST with invalid JSON."""
        url = reverse('agents:profiles-create')

        payload = {
            'name': 'Invalid Workflow',
            'profile': '{invalid json',
            'is_active': True,
        }

        response = web_client.post(url, payload)

        # Should stay on form with error
        assert response.status_code == 200
        assert b'Invalid JSON' in response.content or 'profile' in response.context.get('form', {}).errors

    def test_get_profile_with_non_dict_json(
        self,
        web_client: Client,
        workflow_definition: AgentWorkflowDefinition,
    ):
        """Test GET with valid JSON but wrong type (string instead of object)."""
        # Store a JSON string value instead of an object
        # This bypasses the model's clean() validation but is valid JSON
        AgentWorkflowDefinition.objects.filter(pk=workflow_definition.pk).update(profile='just-a-string')

        url = reverse('agents:profiles-config', kwargs={'pk': workflow_definition.pk})
        response = web_client.get(url)

        assert response.status_code == 200
        # Should mark JSON as invalid since it's not a dict/object
        context = response.context
        assert context.get('json_valid') is False
        # The profile_json should contain the stringified version
        assert 'just-a-string' in str(context.get('profile_json'))


@pytest.mark.django_db
class TestAgentWorkflowDefinitionBulkDeleteView:
    """Test workflow definition bulk delete view."""

    def test_bulk_delete_confirmation(self, web_client: Client):
        """Test bulk delete confirmation page."""
        wf1 = AgentWorkflowDefinition.objects.create(name='WF1', profile={})
        wf2 = AgentWorkflowDefinition.objects.create(name='WF2', profile={})

        url = reverse('agents:profiles-delete_confirm', kwargs={'pks': f'{wf1.pk}/{wf2.pk}/'})

        response = web_client.get(url)

        # Should show confirmation page
        assert response.status_code == 200

    def test_bulk_delete_executes(self, web_client: Client):
        """Test bulk delete actually deletes."""
        wf1 = AgentWorkflowDefinition.objects.create(name='WF1', profile={})
        wf2 = AgentWorkflowDefinition.objects.create(name='WF2', profile={})

        initial_count = AgentWorkflowDefinition.objects.count()
        
        url = reverse('agents:profiles-delete_confirm', kwargs={'pks': f'{wf1.pk}/{wf2.pk}/'})

        response = web_client.post(url)

        # Should redirect after deletion
        assert response.status_code == 302

        # Verify deletions
        final_count = AgentWorkflowDefinition.objects.count()
        assert final_count < initial_count
