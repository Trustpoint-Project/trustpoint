# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Comprehensive tests for Agent API views and Web views.

Covers:
- AgentCertificateAuthentication
- AgentJobsView (GET /api/agents/jobs/)
- AgentJobResultView (POST /api/agents/jobs/result/)
- AgentProfileDefinitionTableView
- AgentProfileDefinitionConfigView
- AgentProfileDefinitionBulkDeleteConfirmView
"""

from __future__ import annotations

import json
import urllib.parse
import uuid
from datetime import timedelta
from io import StringIO
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import connection
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIClient

from agents.api_views import (
    AgentCertificateAuthentication,
    _build_resolved_profile,
    _parse_client_cert,
    _resolve_enrollment_url,
    next_update_after_success,
)
from agents.checks import literal_password_steps
from agents.models import AgentAssignedProfile, AgentProfileDefinition, TrustpointAgent
from agents.web_views import AgentProfileDefinitionConfigView, AgentProfileDefinitionTableView
from devices.models import DeviceModel, DomainModel
from management.models import AuditLog, SecurityConfig
from pki.models.cert_profile import CertificateProfileModel
from pki.models import IssuedCredentialModel
from onboarding.models import OnboardingProtocol

if TYPE_CHECKING:
    from pathlib import Path

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
    manage_devices_perm = Permission.objects.get(codename='manage_devices')
    user.role.permissions.add(manage_devices_perm)
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
def workflow_definition(db: Any) -> AgentProfileDefinition:
    """Create a test workflow definition."""
    profile = {
        'metadata': {'agent_type': '1-to-1', 'version': '1.0'},
        'device': {'vendor': 'TestVendor'},
        'certificate_request': {
            'certificate_profile': 'domain_credential',
            'url': 'https://trustpoint.local',
            'path': '/enroll/',
        },
        'steps': [],
    }
    return AgentProfileDefinition.objects.create(
        name='Test Workflow',
        profile=profile,
        is_active=True,
    )


@pytest.fixture
def assigned_profile(
    db: Any,
    agent: TrustpointAgent,
    workflow_definition: AgentProfileDefinition,
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

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, 'test-cert'),
        ]
    )

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

    def test_untrusted_peer_cannot_assert_an_agent_certificate(self, settings):
        settings.TRUSTPOINT_TRUSTED_PROXY_IPS = ['127.0.0.1']
        request = RequestFactory().get(
            '/api/agents/jobs/',
            HTTP_SSL_CLIENT_CERT='untrusted-assertion',
            REMOTE_ADDR='198.51.100.10',
        )
        with patch('agents.api_views.x509.load_pem_x509_certificate') as parser:
            with pytest.raises(AuthenticationFailed):
                _parse_client_cert(request)
            parser.assert_not_called()

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

    def test_parse_client_cert_does_not_expose_parser_exception(self):
        """Keep parser diagnostics in the exception chain, outside the public detail."""
        request = RequestFactory().get('/test/', HTTP_SSL_CLIENT_CERT='invalid-cert-data')
        parser_error = ValueError('internal parser detail: /private/server/path and sensitive input')

        with patch('agents.api_views.x509.load_pem_x509_certificate', side_effect=parser_error):
            with pytest.raises(AuthenticationFailed) as error:
                _parse_client_cert(request)

        assert str(error.value.detail) == 'Invalid HTTP_SSL_CLIENT_CERT header.'
        assert error.value.__cause__ is parser_error

    @pytest.mark.parametrize('method,endpoint', [('get', '/api/agents/jobs/'), ('post', '/api/agents/jobs/result/')])
    @pytest.mark.parametrize('mock_parser', [False, True])
    def test_invalid_certificate_api_response_is_generic(self, api_client, method, endpoint, mock_parser):
        """Rendered API errors contain no parser exception details or certificate input."""
        parser_error = ValueError('sensitive-parser-detail /private/server/path')
        with patch('agents.api_views.x509.load_pem_x509_certificate', wraps=x509.load_pem_x509_certificate) as parser:
            if mock_parser:
                parser.side_effect = parser_error
            response = getattr(api_client, method)(endpoint, HTTP_SSL_CLIENT_CERT='invalid-cert-data')

        assert response.status_code == 401
        assert response.json() == {'detail': 'Invalid HTTP_SSL_CLIENT_CERT header.'}
        assert response['WWW-Authenticate'] == 'mTLS realm="Trustpoint Agent API"'
        for private_detail in ('sensitive-parser-detail', '/private/server/path', 'invalid-cert-data', 'ValueError'):
            assert private_detail not in response.content.decode()

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
            certificate_profile=CertificateProfileModel.objects.get_or_create(
                unique_name='test_profile', defaults={'profile_json': {}}
            )[0],
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
                certificate_profile=CertificateProfileModel.objects.get_or_create(
                    unique_name='test_profile', defaults={'profile_json': {}}
                )[0],
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
            certificate_profile=CertificateProfileModel.objects.get_or_create(
                unique_name='test_profile', defaults={'profile_json': {}}
            )[0],
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
            certificate_profile=CertificateProfileModel.objects.get_or_create(
                unique_name='test_profile', defaults={'profile_json': {}}
            )[0],
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
    def test_get_jobs_disabled_by_security_config(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
    ):
        """Test GET is forbidden when the AGENT protocol is not permitted."""
        mock_auth.return_value = (agent, None)
        SecurityConfig.objects.create(permitted_onboarding_protocols=[])

        response = api_client.get('/api/agents/jobs/')

        assert response.status_code == 403
        assert response.json()['detail'] == ('Agent functionality is disabled by the current security configuration.')

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
    def test_post_result_disabled_by_security_config(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        """Test POST is forbidden when the AGENT protocol is not permitted."""
        mock_auth.return_value = (agent, None)
        SecurityConfig.objects.create(permitted_onboarding_protocols=[])

        response = api_client.post(
            '/api/agents/jobs/result/',
            {'profile_id': assigned_profile.pk, 'success': True},
            format='json',
        )

        assert response.status_code == 403
        assert response.json()['detail'] == ('Agent functionality is disabled by the current security configuration.')

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
    def test_long_error_message_is_stored_truncated(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        response = api_client.post(
            '/api/agents/jobs/result/',
            {'profile_id': assigned_profile.pk, 'success': False, 'error_message': 'x' * 3000},
            format='json',
        )

        assert response.status_code == 200
        assigned_profile.refresh_from_db()
        assert len(assigned_profile.last_error) == 2000

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
class TestAgentProfileDefinitionTableView:
    """Test workflow definition list view."""

    def test_get_list_disabled_by_security_config(self, web_client: Client):
        """Test agent pages redirect when the AGENT protocol is not permitted."""
        SecurityConfig.objects.create(permitted_onboarding_protocols=[])

        response = web_client.get(reverse('agents:profiles'))

        assert response.status_code == 302
        assert response.url == reverse('devices:devices')

    def test_get_list(self, web_client: Client, workflow_definition: AgentProfileDefinition):
        """Test GET workflow definition list."""
        response = web_client.get(reverse('agents:profiles'))

        assert response.status_code == 200
        assert workflow_definition.name.encode() in response.content

    def test_get_list_multiple(self, web_client: Client):
        """Test GET with multiple workflow definitions."""
        AgentProfileDefinition.objects.create(
            name='Workflow 1',
            profile={'metadata': {}},
        )
        AgentProfileDefinition.objects.create(
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
class TestAgentProfileDefinitionConfigView:
    """Test workflow definition config view."""

    def test_get_existing_profile(self, web_client: Client, workflow_definition: AgentProfileDefinition):
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
        workflow = AgentProfileDefinition.objects.filter(name='New Workflow').first()
        assert workflow is not None
        assert workflow.is_active is True

    def test_post_update_profile(self, web_client: Client, workflow_definition: AgentProfileDefinition):
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
        workflow_definition: AgentProfileDefinition,
    ):
        """Test GET with valid JSON but wrong type (string instead of object)."""
        # Store a JSON string value instead of an object
        # This bypasses the model's clean() validation but is valid JSON
        AgentProfileDefinition.objects.filter(pk=workflow_definition.pk).update(profile='just-a-string')

        url = reverse('agents:profiles-config', kwargs={'pk': workflow_definition.pk})
        response = web_client.get(url)

        assert response.status_code == 200
        # Should mark JSON as invalid since it's not a dict/object
        context = response.context
        assert context.get('json_valid') is False
        # The profile_json should contain the stringified version
        assert 'just-a-string' in str(context.get('profile_json'))


@pytest.mark.django_db
class TestAgentProfileDefinitionBulkDeleteView:
    """Test workflow definition bulk delete view."""

    def test_bulk_delete_confirmation(self, web_client: Client):
        """Test bulk delete confirmation page."""
        wf1 = AgentProfileDefinition.objects.create(name='WF1', profile={})
        wf2 = AgentProfileDefinition.objects.create(name='WF2', profile={})

        url = reverse('agents:profiles-delete_confirm', kwargs={'pks': f'{wf1.pk}/{wf2.pk}/'})

        response = web_client.get(url)

        # Should show confirmation page
        assert response.status_code == 200

    def test_bulk_delete_executes(self, web_client: Client):
        """Test bulk delete actually deletes."""
        wf1 = AgentProfileDefinition.objects.create(name='WF1', profile={})
        wf2 = AgentProfileDefinition.objects.create(name='WF2', profile={})

        initial_count = AgentProfileDefinition.objects.count()

        url = reverse('agents:profiles-delete_confirm', kwargs={'pks': f'{wf1.pk}/{wf2.pk}/'})

        response = web_client.post(url)

        # Should redirect after deletion
        assert response.status_code == 302

        # Verify deletions
        final_count = AgentProfileDefinition.objects.count()
        assert final_count < initial_count


# ============================================================================
# Regression tests for audit fixes
# ============================================================================


@pytest.fixture
def second_agent(db: Any, domain: DomainModel) -> TrustpointAgent:
    """Create a second agent with its own device."""
    device = DeviceModel.objects.create(
        common_name='second-device',
        serial_number='SN654321',
        device_type=DeviceModel.DeviceType.AGENT_ONE_TO_ONE,
        domain=domain,
    )
    return TrustpointAgent.objects.create(
        agent_id='second-agent-1',
        name='Second Agent',
        device=device,
        is_active=True,
    )


@pytest.mark.django_db
class TestProfileValidationFixes:
    """Validation gaps found in the audit."""

    def test_certificate_request_must_be_an_object(self):
        profile = AgentProfileDefinition(name='Bad Request', profile={'certificate_request': None})
        with pytest.raises(ValidationError):
            profile.full_clean()

    def test_literal_password_is_rejected(self):
        profile = AgentProfileDefinition(
            name='Plain Password',
            profile={'steps': [{'type': 'fill', 'selector': '#password', 'value': 'plain'}]},
        )
        with pytest.raises(ValidationError, match='password'):
            profile.full_clean()

    def test_secret_placeholder_is_accepted(self):
        profile = AgentProfileDefinition(
            name='Secret Password',
            profile={'steps': [{'type': 'fill', 'selector': '#password', 'value': '{{ secret:wbm_password }}'}]},
            secrets={'wbm_password': 'value'},
        )
        profile.full_clean()

    def test_incomplete_click_step_is_rejected(self):
        profile = AgentProfileDefinition(name='Incomplete', profile={'steps': [{'type': 'click'}]})
        with pytest.raises(ValidationError, match='selector'):
            profile.full_clean()

    def test_missing_secret_reference_is_rejected(self):
        profile = AgentProfileDefinition(
            name='Missing Secret',
            profile={'steps': [{'type': 'fill', 'selector': '#username', 'value': '{{ secret:missing }}'}]},
            secrets={},
        )
        with pytest.raises(ValidationError, match='Missing secret'):
            profile.full_clean()


@pytest.mark.django_db
class TestScheduleFromCertificate:
    """The renewal threshold is measured before certificate expiry."""

    def test_next_update_uses_certificate_expiry(self, assigned_profile: AgentAssignedProfile):
        now = timezone.now()
        assigned_profile.renewal_threshold_days = 4
        with patch.object(AgentAssignedProfile, 'certificate_not_after', return_value=now + timedelta(days=10)):
            result = next_update_after_success(assigned_profile, now)
        assert result == now + timedelta(days=6)

    def test_custom_domain_profile_name_is_used_for_lookup(
        self,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        expiry = timezone.now() + timedelta(days=10)
        credential = Mock()
        credential.credential.certificate.not_valid_after = expiry
        manager = Mock()
        manager.select_related.return_value.order_by.return_value.first.return_value = credential
        calls: list[tuple[Any, ...]] = []

        def fake_filter(*args: Any, **_kwargs: Any) -> Mock:
            calls.append(args)
            return manager

        manager.filter.side_effect = fake_filter
        with (
            patch('pki.models.IssuedCredentialModel.objects.filter', side_effect=fake_filter),
            patch.object(agent.device.domain, 'get_domain_credential_profile_name', return_value='custom-domain'),
        ):
            result = assigned_profile.certificate_not_after()

        assert result == expiry
        assert 'custom-domain' in str(calls[1][0])

    def test_threshold_larger_than_lifetime_does_not_loop(
        self,
        assigned_profile: AgentAssignedProfile,
    ):
        now = timezone.now()
        assigned_profile.renewal_threshold_days = 30
        with patch.object(AgentAssignedProfile, 'certificate_not_after', return_value=now + timedelta(days=10)):
            result = next_update_after_success(assigned_profile, now)
        assert result == now + timedelta(days=1)

    def test_recalculate_schedules_command_moves_old_dates_earlier(
        self,
        assigned_profile: AgentAssignedProfile,
    ):
        now = timezone.now()
        assigned_profile.next_certificate_update_scheduled = now + timedelta(days=30)
        assigned_profile.save()
        with patch.object(
            AgentAssignedProfile,
            'next_update_from_certificate',
            return_value=now + timedelta(days=1),
        ):
            call_command('recalculate_agent_renewal_schedules')

        assigned_profile.refresh_from_db()
        assert assigned_profile.next_certificate_update_scheduled is not None
        assert assigned_profile.next_certificate_update_scheduled < now + timedelta(days=2)

    def test_success_ack_uses_certificate_expiry(
        self,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        now = timezone.now()
        assigned_profile.renewal_threshold_days = 5
        assigned_profile.save()
        with (
            patch('agents.api_views.AgentCertificateAuthentication.authenticate', return_value=(agent, None)),
            patch.object(AgentAssignedProfile, 'certificate_not_after', return_value=now + timedelta(days=20)),
        ):
            response = api_client.post(
                '/api/agents/jobs/result/',
                {'profile_id': assigned_profile.pk, 'success': True},
                format='json',
            )
        assert response.status_code == 200
        assigned_profile.refresh_from_db()
        assert assigned_profile.next_certificate_update_scheduled is not None
        assert assigned_profile.next_certificate_update_scheduled > now + timedelta(days=14)
        assert assigned_profile.next_certificate_update_scheduled < now + timedelta(days=16)


@pytest.mark.django_db
class TestJobClaims:
    """Jobs are leased so two pollers do not run them twice."""

    @pytest.mark.parametrize('success', [True, False])
    def test_result_does_not_overwrite_a_replacement_claim(
        self,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
        *,
        success: bool,
    ) -> None:
        """A result cannot clear a claim installed after its initial token check."""
        original_token = uuid.uuid4()
        replacement_token = uuid.uuid4()
        replacement_time = timezone.now()
        AgentAssignedProfile.objects.filter(pk=assigned_profile.pk).update(
            claim_token=original_token,
            claimed_at=replacement_time - timedelta(hours=1),
        )

        def replace_claim(*_args: Any) -> Any:
            AgentAssignedProfile.objects.filter(pk=assigned_profile.pk).update(
                claim_token=replacement_token,
                claimed_at=replacement_time,
            )
            return replacement_time + timedelta(days=1) if success else 3600

        scheduling_function = 'next_update_after_success' if success else '_failure_backoff_seconds'
        with (
            patch('agents.api_views.AgentCertificateAuthentication.authenticate', return_value=(agent, None)),
            patch(f'agents.api_views.{scheduling_function}', side_effect=replace_claim),
        ):
            response = api_client.post(
                '/api/agents/jobs/result/',
                {'profile_id': assigned_profile.pk, 'success': success, 'job_token': str(original_token)},
                format='json',
            )

        assert response.status_code == status.HTTP_409_CONFLICT
        original_schedule = assigned_profile.next_certificate_update_scheduled
        assigned_profile.refresh_from_db()
        assert assigned_profile.claim_token == replacement_token
        assert assigned_profile.claimed_at == replacement_time
        assert assigned_profile.next_certificate_update_scheduled == original_schedule
        assert assigned_profile.last_certificate_update is None
        assert assigned_profile.failure_count == 0

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_job_is_claimed_once(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        agent.device.domain = None
        agent.device.save()
        first = api_client.get('/api/agents/jobs/')
        assert first.status_code == 200
        jobs = first.json()['jobs']
        assert len(jobs) == 1
        token = jobs[0]['job_token']

        second = api_client.get('/api/agents/jobs/')
        assert second.status_code == 200
        assert second.json()['jobs'] == []

        response = api_client.post(
            '/api/agents/jobs/result/',
            {'profile_id': assigned_profile.pk, 'success': True, 'job_token': token},
            format='json',
        )
        assert response.status_code == 200
        assigned_profile.refresh_from_db()
        assert assigned_profile.claimed_at is None
        assert assigned_profile.claim_token is None

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_stale_token_is_rejected(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        agent.device.domain = None
        agent.device.save()
        assert api_client.get('/api/agents/jobs/').json()['jobs']
        response = api_client.post(
            '/api/agents/jobs/result/',
            {
                'profile_id': assigned_profile.pk,
                'success': True,
                'job_token': '00000000-0000-0000-0000-000000000000',
            },
            format='json',
        )
        assert response.status_code == 409

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_failure_records_backoff_and_error(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        agent.device.domain = None
        agent.device.save()
        assert api_client.get('/api/agents/jobs/').json()['jobs']
        before = timezone.now()
        response = api_client.post(
            '/api/agents/jobs/result/',
            {'profile_id': assigned_profile.pk, 'success': False, 'error_message': 'timeout'},
            format='json',
        )
        assert response.status_code == 200
        assigned_profile.refresh_from_db()
        assert assigned_profile.failure_count == 1
        assert assigned_profile.last_error == 'timeout'
        assert assigned_profile.claimed_at is None
        assert assigned_profile.next_certificate_update_scheduled is not None
        assert assigned_profile.next_certificate_update_scheduled > before

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_inactive_definition_is_not_offered(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        assigned_profile.workflow_definition.is_active = False
        assigned_profile.workflow_definition.save()
        response = api_client.get('/api/agents/jobs/')
        assert response.status_code == 200
        assert response.json()['jobs'] == []

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_one_job_is_claimed_per_poll(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        agent.device.domain = None
        agent.device.save()
        second_profile = AgentProfileDefinition.objects.create(
            name='Second Profile',
            profile={
                'certificate_request': {'certificate_profile': 'tls_server'},
                'steps': [],
            },
        )
        AgentAssignedProfile.objects.create(
            agent=agent,
            workflow_definition=second_profile,
            next_certificate_update_scheduled=timezone.now() - timedelta(hours=1),
        )

        assert len(api_client.get('/api/agents/jobs/').json()['jobs']) == 1
        assert len(api_client.get('/api/agents/jobs/').json()['jobs']) == 1
        assert api_client.get('/api/agents/jobs/').json()['jobs'] == []

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_corrupt_secret_is_skipped_without_breaking_poll(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        agent.device.domain = None
        agent.device.save()
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE {AgentProfileDefinition._meta.db_table} SET secrets = %s WHERE id = %s',
                ['tpsec:v1:broken', assigned_profile.workflow_definition_id],
            )

        response = api_client.get('/api/agents/jobs/')

        assert response.status_code == 200
        assert response.json()['jobs'] == []
        assigned_profile.refresh_from_db()
        assert assigned_profile.claimed_at is None

    @patch('agents.api_views.AgentCertificateAuthentication.authenticate')
    def test_expired_claim_is_reclaimed(
        self,
        mock_auth: Mock,
        api_client: APIClient,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        mock_auth.return_value = (agent, None)
        agent.device.domain = None
        agent.device.save()
        assigned_profile.claimed_at = timezone.now() - timedelta(hours=1)
        assigned_profile.claim_token = None
        assigned_profile.save()

        response = api_client.get('/api/agents/jobs/')

        assert len(response.json()['jobs']) == 1


@pytest.mark.django_db
class TestAssignedProfileWebViews:
    """Regression coverage for the assigned-profile operator views."""

    def test_delete_does_not_touch_another_agent(
        self,
        web_client: Client,
        agent: TrustpointAgent,
        second_agent: TrustpointAgent,
        workflow_definition: AgentProfileDefinition,
    ):
        assignment = AgentAssignedProfile.objects.create(
            agent=second_agent,
            workflow_definition=workflow_definition,
        )
        url = reverse(
            'agents:assigned-profiles-delete_confirm',
            kwargs={'agent_id': agent.pk, 'pks': f'{assignment.pk}/'},
        )
        response = web_client.post(url)
        assert response.status_code == 302
        assert AgentAssignedProfile.objects.filter(pk=assignment.pk).exists()

    def test_delete_own_assignment(
        self,
        web_client: Client,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        url = reverse(
            'agents:assigned-profiles-delete_confirm',
            kwargs={'agent_id': agent.pk, 'pks': f'{assigned_profile.pk}/'},
        )
        response = web_client.post(url)
        assert response.status_code == 302
        assert not AgentAssignedProfile.objects.filter(pk=assigned_profile.pk).exists()

    def test_second_domain_credential_assignment_is_rejected(
        self,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
        workflow_definition: AgentProfileDefinition,
    ):
        other = AgentProfileDefinition.objects.create(
            name='Other Domain Credential',
            profile=workflow_definition.profile,
        )
        assignment = AgentAssignedProfile(agent=agent, workflow_definition=other)
        with pytest.raises(ValidationError, match='domain credential'):
            assignment.full_clean()

    def test_duplicate_assignment_shows_form_error(
        self,
        web_client: Client,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        url = reverse('agents:assigned-profiles-create', kwargs={'agent_id': agent.pk})
        response = web_client.post(
            url,
            {
                'workflow_definition': assigned_profile.workflow_definition.pk,
                'renewal_threshold_days': 30,
                'subject': '',
                'subject_alt_name': '',
            },
        )
        assert response.status_code == 200
        assert AgentAssignedProfile.objects.filter(agent=agent).count() == 1

    def test_agent_without_device_shows_form_error(
        self,
        web_client: Client,
        workflow_definition: AgentProfileDefinition,
    ):
        agent = TrustpointAgent.objects.create(agent_id='no-device-agent', name='No Device Agent')
        url = reverse('agents:assigned-profiles-create', kwargs={'agent_id': agent.pk})
        response = web_client.post(
            url,
            {
                'workflow_definition': workflow_definition.pk,
                'renewal_threshold_days': 30,
                'subject': '',
                'subject_alt_name': '',
            },
        )
        assert response.status_code == 200
        assert not AgentAssignedProfile.objects.filter(agent=agent).exists()

    def test_new_agent_assignment_gets_a_grace_period(self, domain: DomainModel):
        from devices.views.agents import AgentCreateOneToOneOnboardingView

        AgentProfileDefinition.objects.create(
            name='Domain Credential Update',
            profile={'certificate_request': {'certificate_profile': 'domain_credential'}, 'steps': []},
        )
        device = DeviceModel.objects.create(
            common_name='new-agent-device',
            serial_number='SN-NEW-AGENT',
            device_type=DeviceModel.DeviceType.AGENT_ONE_TO_ONE,
            domain=domain,
        )
        form = Mock()
        form.cleaned_data = {'agent_os_path': '/etc/trustpoint'}
        form.save.return_value = device
        view = AgentCreateOneToOneOnboardingView()
        view.request = RequestFactory().post('/')
        view.request.user = Mock(has_perm=Mock(return_value=True))

        view.form_valid(form)

        agent = TrustpointAgent.objects.get(device=device)
        assignment = AgentAssignedProfile.objects.get(agent=agent)
        assert assignment.next_certificate_update_scheduled is not None
        assert assignment.next_certificate_update_scheduled > timezone.now()

    def test_list_shows_inactive_profile_badge(
        self,
        web_client: Client,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        assigned_profile.workflow_definition.is_active = False
        assigned_profile.workflow_definition.save()
        response = web_client.get(reverse('agents:assigned-profiles-list', kwargs={'agent_id': agent.pk}))
        assert b'Profile inactive' in response.content

    def test_list_and_edit_pages_render(
        self,
        web_client: Client,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        list_response = web_client.get(reverse('agents:assigned-profiles-list', kwargs={'agent_id': agent.pk}))
        assert list_response.status_code == 200
        edit_response = web_client.get(
            reverse(
                'agents:assigned-profiles-edit',
                kwargs={'agent_id': agent.pk, 'pk': assigned_profile.pk},
            )
        )
        assert edit_response.status_code == 200

    def test_edit_threshold_recomputes_schedule(
        self,
        web_client: Client,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        assigned_profile.next_certificate_update_scheduled = timezone.now() - timedelta(days=1)
        assigned_profile.save()
        response = web_client.post(
            reverse(
                'agents:assigned-profiles-edit',
                kwargs={'agent_id': agent.pk, 'pk': assigned_profile.pk},
            ),
            {
                'renewal_threshold_days': 7,
                'subject': assigned_profile.subject,
                'subject_alt_name': assigned_profile.subject_alt_name,
                'enabled': True,
            },
        )
        assert response.status_code == 302
        assigned_profile.refresh_from_db()
        assert assigned_profile.next_certificate_update_scheduled is not None
        assert assigned_profile.next_certificate_update_scheduled > timezone.now() + timedelta(days=6)

    def test_force_update_sets_schedule(
        self,
        web_client: Client,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        assigned_profile.next_certificate_update_scheduled = timezone.now() + timedelta(days=30)
        assigned_profile.save()
        url = reverse(
            'agents:assigned-profiles-force-update',
            kwargs={'agent_id': agent.pk, 'pk': assigned_profile.pk},
        )
        response = web_client.post(url)
        assert response.status_code == 302
        assigned_profile.refresh_from_db()
        assert assigned_profile.next_certificate_update_scheduled <= timezone.now()


@pytest.mark.django_db
class TestProfileSecretsAndEditor:
    """Secrets are encrypted and non-ASCII editor content is preserved."""

    def test_dumpdata_loaddata_preserves_encrypted_secrets(self, tmp_path: Path) -> None:
        """Restoring a fixture encrypts JSON secrets exactly once."""
        profile = AgentProfileDefinition.objects.create(
            name='Restored Secrets', profile={'steps': []}, secrets={'password': 'Müller-secret'},
        )
        output = StringIO()
        call_command('dumpdata', 'agents.AgentProfileDefinition', stdout=output)
        fixture = tmp_path / 'agent-profiles.json'
        fixture.write_text(output.getvalue(), encoding='utf-8')
        assert 'Müller-secret' not in output.getvalue()

        AgentProfileDefinition.objects.filter(pk=profile.pk).delete()
        call_command('loaddata', str(fixture))

        profile.refresh_from_db()
        assert profile.secrets == {'password': 'Müller-secret'}

    def test_secrets_are_encrypted_and_resolved(self, agent: TrustpointAgent):
        profile = AgentProfileDefinition.objects.create(
            name='Encrypted Profile',
            profile={
                'certificate_request': {},
                'steps': [{'type': 'fill', 'selector': '#password', 'value': '{{ secret:wbm_password }}'}],
            },
            secrets={'wbm_password': 'hunter2'},
        )
        with connection.cursor() as cursor:
            cursor.execute(
                f'SELECT secrets FROM {profile._meta.db_table} WHERE id = %s',
                [profile.pk],
            )
            raw = cursor.fetchone()[0]
        assert raw.startswith('tpsec:v1:')
        assert 'hunter2' not in raw

        profile.refresh_from_db()
        assert profile.secrets == {'wbm_password': 'hunter2'}

        agent.device.domain = None
        agent.device.save()
        assignment = AgentAssignedProfile.objects.create(agent=agent, workflow_definition=profile)
        resolved = _build_resolved_profile(agent, profile.profile, assignment)
        assert resolved['steps'][0]['value'] == 'hunter2'

        output = StringIO()
        call_command('dumpdata', 'agents.AgentProfileDefinition', stdout=output)
        assert 'hunter2' not in output.getvalue()
        assert 'tpsec:v1:' in output.getvalue()

    def test_management_command_encrypts_legacy_password(self):
        profile = AgentProfileDefinition.objects.create(
            name='Legacy Password',
            profile={'steps': [{'type': 'fill', 'selector': '#password', 'value': 'plain'}]},
        )
        call_command('encrypt_agent_profile_secrets')
        profile.refresh_from_db()
        assert profile.profile['steps'][0]['value'].startswith('{{ secret:')
        assert profile.secrets
        profile.full_clean()

    def test_profile_editor_preserves_non_ascii(self, web_client: Client, workflow_definition: AgentProfileDefinition):
        workflow_definition.profile['metadata']['description'] = 'Müller GmbH'
        workflow_definition.save()
        url = reverse('agents:profiles-config', kwargs={'pk': workflow_definition.pk})
        response = web_client.get(url)
        content = response.content.decode()
        assert 'Müller GmbH' in content
        assert 'MÃ¼ller' not in content
        assert isinstance(response.context['profile_json'], dict)

    @patch('agents.api_views._resolve_enrollment_url', return_value=None)
    def test_local_storage_placeholders_are_resolved(
        self,
        _mock_url: Mock,
        agent: TrustpointAgent,
        assigned_profile: AgentAssignedProfile,
    ):
        agent.device.domain = None
        agent.device.save()
        raw_profile = {
            'certificate_request': {'certificate_profile': 'tls_server', 'url': '{{ endpoint }}'},
            'local_storage': {'certificate_path': '{{ os_path }}/{{ certificate_profile }}-{{ profile_id }}.pem'},
        }
        resolved = _build_resolved_profile(agent, raw_profile, assigned_profile)
        assert resolved['local_storage']['certificate_path'] == (
            f'{agent.os_path}/tls_server-{assigned_profile.pk}.pem'
        )
        assert 'url' not in resolved['certificate_request']


@pytest.mark.django_db
class TestAuditAndThrottleFixes:
    """Audit entries and the authenticated-agent principal."""

    def test_profile_create_and_update_are_audited(self, web_client: Client):
        create_url = reverse('agents:profiles-create')
        payload = {
            'name': 'Audited Profile',
            'profile': json.dumps({'certificate_request': {}, 'steps': []}),
            'secrets': '{}',
            'is_active': True,
        }
        assert web_client.post(create_url, payload).status_code == 302
        profile = AgentProfileDefinition.objects.get(name='Audited Profile')
        assert AuditLog.objects.filter(
            operation_type=AuditLog.OperationType.AGENT_PROFILE_CREATED,
            target_object_id=str(profile.pk),
        ).exists()

        payload['is_active'] = False
        assert (
            web_client.post(
                reverse('agents:profiles-config', kwargs={'pk': profile.pk}),
                payload,
            ).status_code
            == 302
        )
        assert AuditLog.objects.filter(
            operation_type=AuditLog.OperationType.AGENT_PROFILE_UPDATED,
            target_object_id=str(profile.pk),
        ).exists()

    def test_profile_in_use_cannot_be_deleted(self, web_client: Client, assigned_profile: AgentAssignedProfile):
        url = reverse(
            'agents:profiles-delete_confirm',
            kwargs={'pks': f'{assigned_profile.workflow_definition.pk}/'},
        )
        response = web_client.post(url)
        assert response.status_code == 302
        assert AgentProfileDefinition.objects.filter(pk=assigned_profile.workflow_definition.pk).exists()

    def test_profile_delete_audit_keeps_target_id(self, web_client: Client):
        profile = AgentProfileDefinition.objects.create(
            name='Delete Audit Target',
            profile={'certificate_request': {}, 'steps': []},
        )
        profile_pk = profile.pk
        response = web_client.post(reverse('agents:profiles-delete_confirm', kwargs={'pks': f'{profile_pk}/'}))
        assert response.status_code == 302
        entry = AuditLog.objects.get(
            operation_type=AuditLog.OperationType.AGENT_PROFILE_DELETED,
            target_display='Agent Profile Definition: Delete Audit Target',
        )
        assert entry.target_object_id == str(profile_pk)

    def test_audit_failure_rolls_back_profile_creation(self, web_client: Client):
        payload = {
            'name': 'Rollback Profile',
            'profile': json.dumps({'certificate_request': {}, 'steps': []}),
            'secrets': '{}',
            'is_active': True,
        }
        with (
            patch('agents.web_views.AuditLog.create_entry', side_effect=RuntimeError('audit down')),
            pytest.raises(RuntimeError),
        ):
            web_client.post(reverse('agents:profiles-create'), payload)

        assert not AgentProfileDefinition.objects.filter(name='Rollback Profile').exists()

    def test_literal_password_check_warns_until_migrated(self):
        profile = AgentProfileDefinition.objects.create(
            name='Check Legacy Password',
            profile={'steps': [{'type': 'fill', 'selector': '#password', 'value': 'plain'}]},
        )
        warnings = literal_password_steps(app_configs=None)
        assert any(warning.id == 'agents.W001' for warning in warnings)

        call_command('encrypt_agent_profile_secrets')
        warnings = literal_password_steps(app_configs=None)
        assert not any(warning.id == 'agents.W001' for warning in warnings)
        profile.refresh_from_db()
        assert profile.secrets

    def test_agent_is_an_authenticated_principal(self, agent: TrustpointAgent):
        assert agent.is_authenticated is True
        assert agent.is_anonymous is False
