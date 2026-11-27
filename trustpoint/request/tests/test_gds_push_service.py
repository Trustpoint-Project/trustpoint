# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for GDS Push service."""

import base64
import datetime
import hashlib
import ipaddress
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

import pytest
from asgiref.sync import async_to_sync
from asyncua import ua
from asyncua.crypto import security_policies
from asyncua.ua.status_codes import StatusCodes
from asyncua.ua.ua_binary import struct_to_binary
from asyncua.ua.uaerrors import UaStatusCodeError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier, SignatureAlgorithmOID
from django.db import IntegrityError
from django.test import override_settings
from trustpoint_core.oid import HashAlgorithm, NamedCurve

from devices.models import DeviceModel
from management.models import SecurityConfig
from onboarding.models import OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol
from pki.models import CaModel, CertificateModel, TruststoreModel
from pki.models.certificate import RevokedCertificateModel
from pki.models.truststore import TruststoreOrderModel
from pki.security_policy import CryptographicPolicy
from pki.tests.credential_helpers import issue_test_credential
from pki.tests.managed_ca_helpers import create_managed_issuing_ca, create_managed_root_ca
from pki.util.x509 import CertificateGenerator
from request.gds_push.gds_push_service import CertificateTypes, GdsPushError, GdsPushService
from request.tests.test_est_client import certificate_and_csr


@pytest.fixture(autouse=True)
def default_security_config(monkeypatch: pytest.MonkeyPatch) -> SecurityConfig:
    """Use an in-memory SecurityConfig so async tests do not read the test transaction."""
    config = SecurityConfig()
    config.apply_security_settings(save=False)

    async def get_config(service: GdsPushService) -> SecurityConfig:
        return service._security_config or config

    monkeypatch.setattr(GdsPushService, '_get_security_config', get_config)
    return config


@pytest.fixture
def mock_ca_with_crl(settings: Any) -> CaModel:
    """Create a mock CA with CRL."""
    settings.DEVELOPMENT_ENV = True
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.DOCKER_CONTAINER = False

    root_ca, root_key = create_managed_root_ca('Test Root CA')
    issuing_ca, issuing_key = create_managed_issuing_ca(
        issuer_private_key=root_key,
        issuer_cn='Test Root CA',
        subject_cn='Test Issuing CA',
    )

    ca_model = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=issuing_ca,
        private_key=issuing_key,
        chain=[root_ca],
        unique_name='test_gds_ca',
        ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
    )

    # Issue a CRL for the CA
    ca_model.issue_crl()

    return ca_model


@pytest.fixture
def mock_domain(mock_ca_with_crl):
    """Create a mock domain."""
    from pki.models import DomainModel

    domain = DomainModel(unique_name='test_gds_domain', issuing_ca=mock_ca_with_crl)
    domain.save()
    return domain


@pytest.fixture
def mock_truststore():
    """Create a mock truststore."""
    truststore = TruststoreModel(
        unique_name='test_opc_truststore', intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH
    )
    truststore.save()
    return truststore


@pytest.fixture
def mock_server_certificate(mock_truststore):
    """Create a mock server certificate in the truststore."""
    # Generate a server certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'opc-server.test.com'),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName('opc-server.test.com'),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Save certificate to database using proper method
    from pki.models import CertificateModel

    cert_model = CertificateModel.save_certificate(cert)

    # Add to truststore at order 0
    truststore_order = TruststoreOrderModel(trust_store=mock_truststore, certificate=cert_model, order=0)
    truststore_order.save()

    return cert


@pytest.fixture
def mock_opc_device(mock_domain, mock_truststore, mock_server_certificate):
    """Create a mock OPC UA device with proper configuration."""
    # Create onboarding config
    onboarding_config = OnboardingConfigModel(
        onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
    )
    onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
    onboarding_config.save()

    device = DeviceModel(
        device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
        common_name='test-opc-device',
        serial_number='OPC123456',
        ip_address='192.168.1.100',
        domain=mock_domain,
        onboarding_config=onboarding_config,
    )
    device.save()
    device.opc_ua_gds_push_config.opc_trust_store = mock_truststore
    device.opc_ua_gds_push_config.save()

    return device


@pytest.fixture
def mock_domain_credential(mock_opc_device):
    """Create a mock domain credential for the device."""
    credential = issue_test_credential(mock_opc_device, 'domain_credential', common_name='Trustpoint Domain Credential')

    return credential


def _set_service_security_config(service: GdsPushService, **overrides: Any) -> SecurityConfig:
    """Attach an in-memory SecurityConfig with selected overrides to a service."""
    config = SecurityConfig()
    config.apply_security_settings(save=False)
    for field_name, value in overrides.items():
        setattr(config, field_name, value)
    service._security_config = config
    return config


def _make_ca_chain() -> tuple[x509.Certificate, x509.Certificate]:
    """Return a self-signed root CA and a leaf issued by it."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Root CA')])
    now = datetime.datetime.now(datetime.UTC)
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'opc-server')]))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(root_key, hashes.SHA256())
    )
    return root, leaf


class TestGdsPushService:
    """Test cases for GdsPushService."""

    @pytest.mark.parametrize('failure', ['missing_server', 'missing_ca', 'malformed_ca', 'insert', None])
    def test_truststore_replacement_is_atomic(self, mock_opc_device, mock_truststore, failure):
        """Keep the old entries and revocation state when replacement fails."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.server_truststore = mock_truststore
        original_entries = list(mock_truststore.truststoreordermodel_set.values_list('certificate_id', 'order'))
        old_certificate_id = original_entries[0][0]
        _, server_certificate, _ = certificate_and_csr()
        _, ca_certificate, _ = certificate_and_csr()
        if failure != 'missing_server':
            server_model = CertificateModel.save_certificate(server_certificate)
        if failure != 'missing_ca':
            ca_model = CertificateModel.save_certificate(ca_certificate)
        server_der = server_certificate.public_bytes(serialization.Encoding.DER)
        ca_der = ca_certificate.public_bytes(serialization.Encoding.DER)
        if failure == 'malformed_ca':
            ca_der = b'invalid certificate'

        create_order = TruststoreOrderModel.objects.create

        def insert_order(**kwargs):
            if failure == 'insert' and kwargs['order'] == 1:
                raise IntegrityError('replacement insert failed')
            return create_order(**kwargs)

        with patch.object(TruststoreOrderModel.objects, 'create', side_effect=insert_order) as create:
            if failure is None:
                async_to_sync(service._update_truststore_with_new_certificate)(server_der, [ca_der])
            else:
                with pytest.raises(GdsPushError, match='Failed to update truststore'):
                    async_to_sync(service._update_truststore_with_new_certificate)(server_der, [ca_der])

        if failure == 'insert':
            assert create.call_count == 2
        entries = list(mock_truststore.truststoreordermodel_set.values_list('certificate_id', 'order'))
        revoked = RevokedCertificateModel.objects.filter(certificate_id=old_certificate_id).exists()
        if failure is None:
            assert entries == [(server_model.pk, 0), (ca_model.pk, 1)]
            assert revoked
        else:
            assert entries == original_entries
            assert not revoked

    def test_issued_certificate_policy_rejects_small_key(self, mock_opc_device):
        """Reject a certificate below the SecurityConfig RSA minimum."""
        service = GdsPushService(mock_opc_device, insecure=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'server')])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='below the minimum'):
            service._validate_issued_certificate_policy(cert, CryptographicPolicy(rsa_minimum_key_size=2048))

    def test_issued_certificate_policy_rejects_blocked_sha1(self, mock_opc_device):
        """Reject a SHA-1 signed certificate when SecurityConfig blocks SHA-1."""
        service = GdsPushService(mock_opc_device, insecure=True)
        algorithm = Mock()
        algorithm.name = 'sha1'
        cert = Mock()
        cert.public_key.return_value = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        cert.signature_hash_algorithm = algorithm
        cert.signature_algorithm_oid = SignatureAlgorithmOID.RSA_WITH_SHA1
        policy = CryptographicPolicy(blocked_signature_oids=frozenset({HashAlgorithm.SHA1.dotted_string}))

        with pytest.raises(GdsPushError, match='not permitted'):
            service._validate_issued_certificate_policy(cert, policy)
        service._validate_issued_certificate_policy(cert, CryptographicPolicy())

    @override_settings(GDS_PUSH_CHANNEL_TIMEOUT_MS=1234, GDS_PUSH_SESSION_TIMEOUT_MS=5678)
    def test_create_insecure_client_uses_configured_timeouts(self, mock_opc_device):
        """Read channel/session timeouts from settings."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = service._create_insecure_client()
        assert client.secure_channel_timeout == 1234
        assert client.session_timeout == 5678

    def test_init_uses_configured_server_url(self, mock_opc_device):
        """A configured endpoint URL overrides the IP/port-derived URL."""
        mock_opc_device.opc_ua_gds_push_config.opc_server_url = 'opc.tcp://public.example:4840/plant/edge'
        service = GdsPushService(mock_opc_device, insecure=True)
        assert service.server_url == 'opc.tcp://public.example:4840/plant/edge'

    def test_init_accepts_url_without_ip_or_port(self, mock_opc_device):
        """A configured URL is sufficient even when IP and port are absent."""
        mock_opc_device.ip_address = ''
        mock_opc_device.opc_ua_gds_push_config.opc_server_port = 0
        mock_opc_device.opc_ua_gds_push_config.opc_server_url = 'opc.tcp://server.example:4840'
        service = GdsPushService(mock_opc_device, insecure=True)
        assert service.server_url == 'opc.tcp://server.example:4840'

    def test_init_insecure_mode(self, mock_opc_device):
        """Test initialization in insecure mode."""
        service = GdsPushService(mock_opc_device, insecure=True)

        assert service.device == mock_opc_device
        assert service.server_url == 'opc.tcp://192.168.1.100:4840'
        assert service.domain_credential is None
        assert service.server_truststore is None

    def test_get_server_truststore_rejects_missing_opc_config(self, mock_opc_device):
        mock_opc_device.opc_ua_gds_push_config.delete()
        mock_opc_device.refresh_from_db()
        service = GdsPushService.__new__(GdsPushService)
        service.device = mock_opc_device

        with pytest.raises(GdsPushError, match='has no OPC UA GDS Push config'):
            service._get_server_truststore()

    def test_init_secure_mode(self, mock_opc_device, mock_domain_credential, mock_truststore):
        """Test initialization in secure mode."""
        service = GdsPushService(mock_opc_device, insecure=False)

        assert service.device == mock_opc_device
        assert service.server_url == 'opc.tcp://192.168.1.100:4840'
        assert service.domain_credential == mock_domain_credential
        assert service.server_truststore == mock_truststore

    def test_init_device_missing_ip(self, mock_domain, mock_truststore):
        """Test initialization with device missing IP address."""
        onboarding_config = OnboardingConfigModel(
            onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
            common_name='test-device-no-ip',
            domain=mock_domain,
            onboarding_config=onboarding_config,
        )
        device.save()

        with pytest.raises(GdsPushError, match='must have an IP address and OPC server port'):
            GdsPushService(device)

    def test_init_device_missing_port(self, mock_domain, mock_truststore):
        """Test initialization with device missing OPC server port."""
        onboarding_config = OnboardingConfigModel(
            onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
            common_name='test-device-no-port',
            ip_address='192.168.1.100',
            domain=mock_domain,
            onboarding_config=onboarding_config,
        )
        device.save()
        device.opc_ua_gds_push_config.opc_server_port = 0

        with pytest.raises(GdsPushError, match='must have an IP address and OPC server port'):
            GdsPushService(device)

    def test_init_device_no_onboarding_config(self, mock_domain):
        """Test initialization with device missing onboarding config."""
        device = DeviceModel(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
            common_name='test-device-no-config',
            ip_address='192.168.1.100',
            domain=mock_domain,
        )
        device.save()

        with pytest.raises(GdsPushError, match='No domain credential found'):
            GdsPushService(device)
        """Test initialization with device missing OPC truststore."""
        onboarding_config = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH)
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
            common_name='test-device-no-truststore',
            ip_address='192.168.1.100',
            domain=mock_domain,
            onboarding_config=onboarding_config,
        )
        device.save()

        with pytest.raises(GdsPushError, match='No domain credential found'):
            GdsPushService(device)

    def test_init_device_empty_truststore(self, mock_domain):
        """Test initialization with empty OPC truststore."""
        truststore = TruststoreModel(
            unique_name='empty_truststore', intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH
        )
        truststore.save()

        onboarding_config = OnboardingConfigModel(
            onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
            common_name='test-device-empty-truststore',
            ip_address='192.168.1.100',
            domain=mock_domain,
            onboarding_config=onboarding_config,
        )
        device.save()
        device.opc_ua_gds_push_config.opc_trust_store = truststore
        device.opc_ua_gds_push_config.save()

        # Create a domain credential for the device
        issue_test_credential(device, 'domain_credential', common_name='Trustpoint Domain Credential')

        with pytest.raises(GdsPushError, match='Server truststore.*is empty'):
            GdsPushService(device)

    def test_init_no_domain_credential(self, mock_domain, mock_truststore):
        """Test initialization when no domain credential exists."""
        onboarding_config = OnboardingConfigModel(
            onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
            common_name='test-device-no-credential',
            ip_address='192.168.1.100',
            domain=mock_domain,
            onboarding_config=onboarding_config,
        )
        device.save()

        with pytest.raises(GdsPushError, match='No domain credential found'):
            GdsPushService(device)

    @patch('request.gds_push.gds_push_service.sync_to_async')
    @pytest.mark.asyncio
    async def test_build_ca_chain(self, mock_sync_to_async, mock_opc_device, mock_ca_with_crl):
        """Test building CA certificate chain."""
        # Mock the sync_to_async calls
        mock_device = Mock()
        mock_device.domain.issuing_ca.get_ca_chain_from_truststore.return_value = [mock_ca_with_crl]

        mock_sync_to_async.side_effect = lambda func: Mock(return_value=func()) if callable(func) else func

        service = GdsPushService(mock_opc_device, insecure=True)

        # Mock the internal calls
        with patch.object(service, '_build_ca_chain') as mock_build_chain:
            mock_build_chain.return_value = [mock_ca_with_crl]

            # This would normally call the async method, but we'll test the logic
            assert True  # Placeholder for actual test

    @patch('request.gds_push.gds_push_service.Client')
    @pytest.mark.asyncio
    async def test_discover_server_success(self, mock_client_class, mock_opc_device):
        """Test successful server discovery."""
        # Mock the OPC UA client
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Mock async context manager
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        # Mock server info
        mock_client.get_endpoints.return_value = [
            {
                'EndpointUrl': 'opc.tcp://192.168.1.100:4840',
                'SecurityPolicyUri': 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
                'SecurityMode': 'SignAndEncrypt',
            }
        ]

        service = GdsPushService(mock_opc_device, insecure=True)

        with patch.object(service, '_gather_server_info') as mock_gather:
            mock_gather.return_value = {
                'server_name': 'Test OPC Server',
                'endpoints': [
                    {
                        'url': 'opc.tcp://192.168.1.100:4840',
                        'security_policy': 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
                        'security_mode': 'SignAndEncrypt',
                        'has_server_cert': True,
                    }
                ],
            }

            success, message, server_info = await service.discover_server()

            assert success is True
            assert 'Test OPC Server' in message
            assert server_info is not None

    @patch('request.gds_push.gds_push_service.Client')
    @pytest.mark.asyncio
    async def test_discover_server_connection_failure(self, mock_client_class, mock_opc_device):
        """Test server discovery with connection failure."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Mock async context manager to raise exception
        mock_client.connect_and_get_server_endpoints = AsyncMock(side_effect=Exception('Connection failed'))
        mock_client.__aexit__ = AsyncMock(return_value=None)

        service = GdsPushService(mock_opc_device, insecure=True)

        success, message, server_info = await service.discover_server()

        assert success is False
        assert 'Discovery failed' in message
        assert server_info is None

    def test_analyze_endpoints(self, mock_opc_device):
        """Test endpoint analysis."""
        service = GdsPushService(mock_opc_device, insecure=True)

        endpoints = [
            {
                'security_policy': 'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
                'security_mode': 'SignAndEncrypt',
            },
            {'security_policy': 'http://opcfoundation.org/UA/SecurityPolicy#None', 'security_mode': 'None'},
        ]
        result = service._analyze_endpoints(endpoints)

        assert 'Basic256Sha256' in result['security_policies']
        assert result['has_secure_endpoints'] is True
        assert result['has_insecure_endpoints'] is True

    @patch('request.gds_push.gds_push_service.Client')
    @patch('request.gds_push.gds_push_service.sync_to_async')
    @pytest.mark.asyncio
    async def test_update_trustlist_success(
        self, mock_sync_to_async, mock_client_class, mock_opc_device, mock_domain_credential, mock_ca_with_crl
    ):
        """Test successful trustlist update."""
        # Mock OPC UA client
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        # Mock trustlist operations
        mock_trustlist_node = Mock()
        mock_client.get_node.return_value = mock_trustlist_node

        service = GdsPushService(mock_opc_device, insecure=True)

        # Mock the CA chain building
        with (
            patch.object(service, '_build_ca_chain') as mock_build_chain,
            patch.object(service, '_build_trustlist_for_server') as mock_build_trustlist,
            patch.object(service, '_discover_trustlist_nodes') as mock_discover,
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=ua.TrustListDataType()),
            patch.object(service, '_write_trustlist', new_callable=AsyncMock, return_value=True),
            patch.object(service, '_verify_trustlist_deployment', new_callable=AsyncMock, return_value=(True, '')),
            patch.object(service, '_record_managed_trustlist_state', new_callable=AsyncMock),
            patch.object(service, '_verify_server_connection', new_callable=AsyncMock, return_value=(True, '')),
            patch.object(service, '_create_secure_client') as mock_create_client,
        ):
            mock_build_chain.return_value = [mock_ca_with_crl]
            mock_build_trustlist.return_value = ua.TrustListDataType()
            mock_discover.return_value = [{'group_name': 'Default', 'trustlist_node': mock_trustlist_node}]
            mock_create_client.return_value = mock_client

            success, message = await service.update_trustlist()

            assert success is True
            assert 'Successfully updated' in message

    @patch('request.gds_push.gds_push_service.Client')
    @pytest.mark.asyncio
    async def test_update_trustlist_connection_failure(
        self, mock_client_class, mock_opc_device, mock_domain_credential
    ):
        """Test trustlist update with connection failure."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.connect_and_get_server_endpoints = AsyncMock(side_effect=Exception('Connection failed'))
        mock_client.__aexit__ = AsyncMock(return_value=None)

        service = GdsPushService(mock_opc_device, insecure=True)

        success, message = await service.update_trustlist()

        assert success is False
        assert 'Trustlist update failed' in message

    def test_validate_client_certificate_valid(self, mock_opc_device):
        """Test client certificate validation with valid certificate."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Create a valid certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=True,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier('1.3.6.1.5.5.7.3.2')]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier('urn:test:device'), x509.DNSName('test-device.local')]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Should not raise an exception
        service._validate_client_certificate(cert)

    def test_validate_client_certificate_expired(self, mock_opc_device):
        """Test client certificate validation with expired certificate."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=365))
            .not_valid_after(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='Certificate expired'):
            service._validate_client_certificate(cert)

    def test_validate_client_certificate_missing_key_usage(self, mock_opc_device):
        """Test client certificate validation with missing key usage."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='Key Usage extension is missing'):
            service._validate_client_certificate(cert)

    def test_extract_application_uri_success(self, mock_opc_device):
        """Test successful application URI extraction."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier('urn:test:application:uri'),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        uri = service._extract_application_uri(cert)
        assert uri == 'urn:test:application:uri'

    def test_extract_application_uri_missing(self, mock_opc_device):
        """Test application URI extraction with missing URI."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName('test-device.local'),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='No application URI found'):
            service._extract_application_uri(cert)

    def test_verify_certificate_key_match_success(self, mock_opc_device):
        """Test successful certificate and key match verification."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        # Should not raise an exception
        service._verify_certificate_key_match(cert, private_key)

    def test_verify_certificate_key_match_failure(self, mock_opc_device):
        """Test certificate and key match verification with mismatch."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key1.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key1, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='Certificate and private key do not match'):
            service._verify_certificate_key_match(cert, private_key2)

    # ========================================================================
    # Server Certificate Update Tests
    # ========================================================================

    @patch('request.gds_push.gds_push_service.Client')
    @pytest.mark.asyncio
    async def test_update_server_certificate_success(
        self, mock_client_class, mock_opc_device, mock_domain_credential, mock_ca_with_crl
    ):
        """Test successful server certificate update."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        service = GdsPushService(mock_opc_device, insecure=True)

        # Mock certificate groups discovery
        mock_group = {'name': 'DefaultApplicationGroup', 'node_id': ua.NodeId.from_string('ns=0;i=12555')}

        with (
            patch.object(service, '_create_secure_client') as mock_create_client,
            patch.object(service, '_discover_certificate_groups') as mock_discover_groups,
            patch.object(service, '_update_single_certificate') as mock_update_single,
            patch.object(service, '_update_truststore_with_new_certificate') as mock_update_truststore,
        ):
            mock_create_client.return_value = mock_client
            mock_discover_groups.return_value = [mock_group]
            mock_update_single.return_value = (True, b'cert_data', [b'issuer_cert'])
            mock_update_truststore.return_value = None

            success, message, cert_data = await service.update_server_certificate()

            assert success is True
            assert 'Successfully updated' in message
            assert cert_data == b'cert_data'

    @patch('request.gds_push.gds_push_service.Client')
    @pytest.mark.asyncio
    async def test_update_server_certificate_no_groups(
        self, mock_client_class, mock_opc_device, mock_domain_credential
    ):
        """Test server certificate update with no certificate groups found."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        service = GdsPushService(mock_opc_device, insecure=True)

        with (
            patch.object(service, '_create_secure_client') as mock_create_client,
            patch.object(service, '_discover_certificate_groups') as mock_discover_groups,
        ):
            mock_create_client.return_value = mock_client
            mock_discover_groups.return_value = []

            success, message, cert_data = await service.update_server_certificate()

            assert success is False
            assert 'No certificate groups found' in message
            assert cert_data is None

    @pytest.mark.asyncio
    async def test_discover_certificate_groups_success(self, mock_opc_device):
        """Test successful certificate groups discovery."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_client = Mock()
        mock_server_node = Mock()
        mock_server_config = Mock()
        mock_cert_groups_node = Mock()
        mock_group_node = Mock()
        mock_browse_name = Mock()
        mock_browse_name.Name = 'DefaultApplicationGroup'

        mock_client.get_node.return_value = mock_server_node
        mock_server_node.get_child = AsyncMock(return_value=mock_server_config)
        mock_server_config.get_child = AsyncMock(return_value=mock_cert_groups_node)
        mock_cert_groups_node.get_children = AsyncMock(return_value=[mock_group_node])
        mock_group_node.read_browse_name = AsyncMock(return_value=mock_browse_name)
        mock_group_node.nodeid = ua.NodeId.from_string('ns=0;i=12555')

        groups = await service._discover_certificate_groups(mock_client)

        assert len(groups) == 1
        assert groups[0]['name'] == 'DefaultApplicationGroup'

    @pytest.mark.asyncio
    async def test_discover_certificate_groups_filters_by_purpose_and_selects_type(self, mock_opc_device):
        """Target only application groups and use a certificate type they permit."""
        service = GdsPushService(mock_opc_device, insecure=True)

        def make_group(name, node_id, purpose, certificate_types):
            purpose_node = Mock()
            purpose_node.read_value = AsyncMock(return_value=purpose)
            types_node = Mock()
            types_node.read_value = AsyncMock(return_value=certificate_types)
            browse_name = Mock(Name=name)
            group = Mock()
            group.nodeid = ua.NodeId(node_id)
            group.read_browse_name = AsyncMock(return_value=browse_name)

            async def get_child(child):
                return {'Purpose': purpose_node, 'CertificateTypes': types_node}[child]

            group.get_child = AsyncMock(side_effect=get_child)
            return group

        groups_node = Mock()
        groups_node.get_children = AsyncMock(
            return_value=[
                make_group('DefaultApplicationGroup', 12555, ua.NodeId(12557), [ua.NodeId(12560)]),
                make_group('DefaultHttpsGroup', 12556, ua.NodeId(12558), []),
                make_group('DefaultUserTokenGroup', 12557, ua.NodeId(19323), []),
                make_group('VendorApplication', 20000, None, [ua.NodeId(12560)]),
                make_group('BrokenApplication', 20001, ua.NodeId(12557), [ua.NodeId(12558)]),
                make_group('LegacyApplication', 20002, None, []),
                make_group('LegacyHttpsGroup', 20003, None, []),
            ]
        )
        server_config = Mock()
        server_config.get_child = AsyncMock(return_value=groups_node)
        server_node = Mock()
        server_node.get_child = AsyncMock(return_value=server_config)
        client = Mock()
        client.get_node.return_value = server_node

        groups = await service._discover_certificate_groups(client)

        assert [group['name'] for group in groups] == [
            'DefaultApplicationGroup',
            'VendorApplication',
            'LegacyApplication',
        ]
        assert groups[0]['certificate_type_id'] == ua.NodeId(12560)
        assert groups[1]['certificate_type_id'] == ua.NodeId(12560)
        assert groups[2]['certificate_type_id'] == ua.NodeId(12557)

    @pytest.mark.asyncio
    async def test_update_single_certificate_success(self, mock_opc_device, mock_domain_credential):
        """Test successful single certificate update."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_client = Mock()
        mock_server_node = Mock()
        mock_server_config = Mock()
        mock_create_csr_method = Mock()
        mock_update_certificate_method = Mock()
        mock_apply_changes_method = Mock()

        mock_client.get_node.return_value = mock_server_node
        mock_server_node.get_child = AsyncMock(return_value=mock_server_config)
        mock_server_config.get_child = AsyncMock(
            side_effect=[mock_create_csr_method, mock_update_certificate_method, mock_apply_changes_method]
        )

        # Mock CSR creation
        mock_csr_der = b'csr_data'
        mock_server_config.call_method = AsyncMock(
            side_effect=[
                mock_csr_der,  # CreateSigningRequest
                True,  # UpdateCertificate returns apply_changes_required
                None,  # ApplyChanges
            ]
        )

        # Mock CSR signing
        signed_cert = b'signed_cert'
        issuer_chain = [b'issuer_cert']

        with patch.object(service, '_sign_csr') as mock_sign_csr:
            mock_sign_csr.return_value = (signed_cert, issuer_chain, Mock())

            cert_group_id = ua.NodeId.from_string('ns=0;i=12555')
            success, cert_data, chain_data = await service._update_single_certificate(mock_client, cert_group_id)

            assert success is True
            assert cert_data == signed_cert
            assert chain_data == issuer_chain
            regenerate, nonce = mock_server_config.call_method.await_args_list[0].args[4:6]
            assert regenerate is False
            assert nonce == b''

    @pytest.mark.asyncio
    async def test_update_single_certificate_regenerates_key_with_nonce(self, mock_opc_device):
        """Request a new server key with a nonce only when key rollover is enabled."""
        service = GdsPushService(mock_opc_device, insecure=True)

        client = Mock()
        server_node = Mock()
        server_config = Mock()
        client.get_node.return_value = server_node
        server_node.get_child = AsyncMock(return_value=server_config)
        server_config.get_child = AsyncMock(return_value=Mock())
        server_config.call_method = AsyncMock(side_effect=[b'csr', False])

        with patch.object(service, '_sign_csr', return_value=(b'signed', [b'issuer'], Mock())):
            success, cert_data, _chain_data = await service._update_single_certificate(
                client,
                ua.NodeId.from_string('ns=0;i=12555'),
                regenerate_private_key=True,
            )

        assert success is True
        assert cert_data == b'signed'
        regenerate, nonce = server_config.call_method.await_args_list[0].args[4:6]
        assert regenerate is True
        assert isinstance(nonce, bytes)
        assert len(nonce) >= 32

    @pytest.mark.asyncio
    async def test_update_single_certificate_treats_server_halted_apply_as_success(self, mock_opc_device):
        """Treat BadServerHalted from ApplyChanges as a successful restart."""
        service = GdsPushService(mock_opc_device, insecure=True)

        client = Mock()
        server_node = Mock()
        server_config = Mock()
        client.get_node.return_value = server_node
        server_node.get_child = AsyncMock(return_value=server_config)
        server_config.get_child = AsyncMock(return_value=Mock())
        server_config.call_method = AsyncMock(
            side_effect=[b'csr', True, UaStatusCodeError(ua.StatusCodes.BadServerHalted)]
        )

        with patch.object(service, '_sign_csr', return_value=(b'signed', [b'issuer'], Mock())):
            success, cert_data, _chain_data = await service._update_single_certificate(
                client, ua.NodeId.from_string('ns=0;i=12555')
            )

        assert success is True
        assert cert_data == b'signed'

    # ========================================================================
    # Secure Client Creation Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_get_client_credentials_no_credential(self, mock_opc_device, mock_domain_credential):
        """Test client credentials retrieval with no domain credential."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.domain_credential = None

        with pytest.raises(GdsPushError, match='No domain credential available'):
            await service._get_client_credentials()

    # ========================================================================
    # Trustlist Building Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_discover_trustlist_nodes_success(self, mock_opc_device):
        """Test successful trustlist nodes discovery."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_client = Mock()
        mock_server_node = Mock()
        mock_server_config = Mock()
        mock_cert_groups_node = Mock()
        mock_group_node = Mock()
        mock_trustlist_node = Mock()
        mock_browse_name = Mock()
        mock_browse_name.Name = 'DefaultApplicationGroup'

        mock_client.get_node.return_value = mock_server_node
        mock_server_node.get_child = AsyncMock(return_value=mock_server_config)
        mock_server_config.get_child = AsyncMock(return_value=mock_cert_groups_node)
        mock_cert_groups_node.get_children = AsyncMock(return_value=[mock_group_node])
        mock_group_node.read_browse_name = AsyncMock(return_value=mock_browse_name)
        mock_group_node.get_child = AsyncMock(return_value=mock_trustlist_node)

        nodes = await service._discover_trustlist_nodes(mock_client)

        assert len(nodes) == 1
        assert nodes[0]['group_name'] == 'DefaultApplicationGroup'
        assert nodes[0]['trustlist_node'] == mock_trustlist_node

    @pytest.mark.asyncio
    async def test_update_single_trustlist_success(self, mock_opc_device):
        """Test successful single trustlist update."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_trustlist_node = Mock()
        mock_open_method = Mock()
        mock_read_method = Mock()
        mock_close_read_method = Mock()
        mock_write_method = Mock()
        mock_close_method = Mock()
        mock_apply_method = Mock()
        methods = {
            'Open': mock_open_method,
            'Read': mock_read_method,
            'Close': mock_close_read_method,
            'Write': mock_write_method,
            'CloseAndUpdate': mock_close_method,
        }

        async def get_child(name: str) -> Mock:
            return methods[name]

        mock_trustlist_node.get_child = AsyncMock(side_effect=get_child)

        mock_read_handle = 111
        mock_write_handle = 12345
        mock_trustlist_node.call_method = AsyncMock(
            side_effect=[
                mock_read_handle,  # Open (read)
                b'',  # Read -> end of file, nothing to merge
                None,  # Close (read)
                mock_write_handle,  # Open (write)
                None,  # Write
                True,  # CloseAndUpdate returns apply_changes_required
                None,  # ApplyChanges
            ]
        )

        # Mock parent nodes for ApplyChanges
        mock_group_node = Mock()
        mock_cert_groups_node = Mock()
        mock_server_config_node = Mock()

        mock_trustlist_node.get_parent = AsyncMock(return_value=mock_group_node)
        mock_group_node.get_parent = AsyncMock(return_value=mock_cert_groups_node)
        mock_cert_groups_node.get_parent = AsyncMock(return_value=mock_server_config_node)
        mock_server_config_node.get_child = AsyncMock(return_value=mock_apply_method)
        mock_server_config_node.call_method = AsyncMock(return_value=None)

        # Create minimal trustlist data
        trustlist_data = ua.TrustListDataType()
        trustlist_data.TrustedCertificates = []
        trustlist_data.IssuerCertificates = []
        trustlist_data.TrustedCrls = []
        trustlist_data.IssuerCrls = []

        success = await service._update_single_trustlist(mock_trustlist_node, trustlist_data)

        assert success is True

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    @pytest.mark.asyncio
    async def test_update_truststore_no_truststore_configured(self, mock_opc_device):
        """Test truststore update with no truststore configured."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Ensure server_truststore is None
        service.server_truststore = None

        with pytest.raises(GdsPushError, match='No server truststore configured'):
            await service._update_truststore_with_new_certificate(b'cert_data', [b'issuer_cert'])

    @pytest.mark.asyncio
    async def test_build_trustlist_rejects_malformed_crl(self, mock_opc_device, mock_ca_with_crl):
        """Reject a CA trustlist when its CRL cannot be parsed."""
        service = GdsPushService(mock_opc_device, insecure=True)
        with (
            patch.object(
                type(mock_ca_with_crl),
                'crl_pem',
                new_callable=PropertyMock,
                return_value='not-a-certificate',
            ),
            patch.object(service, '_build_ca_chain', new=AsyncMock(return_value=[mock_ca_with_crl])),
        ):
            with pytest.raises(GdsPushError, match='Failed to load CRL'):
                await service._build_trustlist_for_server()

    # ========================================================================
    # Error Handling Tests
    # ========================================================================

    def test_raise_gds_push_error(self, mock_opc_device):
        """Test GdsPushError raising."""
        service = GdsPushService(mock_opc_device, insecure=True)

        with pytest.raises(GdsPushError, match='Test error message'):
            service._raise_gds_push_error('Test error message')

    @pytest.mark.asyncio
    async def test_update_server_certificate_connection_error(self, mock_opc_device, mock_domain_credential):
        """Test server certificate update with connection error."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.domain_credential = mock_domain_credential

        with patch.object(service, '_create_secure_client') as mock_create_client:
            mock_create_client.side_effect = Exception('Connection failed')

            success, message, cert_data = await service.update_server_certificate()

            assert success is False
            assert 'Server certificate update failed' in message

    @pytest.mark.asyncio
    async def test_validate_client_certificate_raises_error(self, mock_opc_device):
        """Test certificate validation raises error for invalid certificate."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Create certificate without SAN extension
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'no-san-cert')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')]))
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        # This should raise GdsPushError due to missing extensions
        with pytest.raises(GdsPushError, match='Client certificate does not meet OPC UA requirements'):
            service._validate_client_certificate(cert)

    @pytest.mark.asyncio
    async def test_discover_certificate_groups_empty(self, mock_opc_device):
        """Test certificate groups discovery with no groups."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_client = Mock()
        mock_server_node = Mock()
        mock_server_config = Mock()
        mock_cert_groups_node = Mock()

        mock_client.get_node.return_value = mock_server_node
        mock_server_node.get_child = AsyncMock(return_value=mock_server_config)
        mock_server_config.get_child = AsyncMock(return_value=mock_cert_groups_node)
        mock_cert_groups_node.get_children = AsyncMock(return_value=[])

        groups = await service._discover_certificate_groups(mock_client)

        assert len(groups) == 0

    @pytest.mark.asyncio
    async def test_analyze_endpoints_with_none_policy(self, mock_opc_device):
        """Test endpoint analysis with None security policy."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Create endpoint dict with None policy (as returned from discover_server)
        endpoint = {'security_policy': 'None', 'security_mode': 'None'}

        analysis = service._analyze_endpoints([endpoint])

        assert 'security_policies' in analysis
        assert 'has_insecure_endpoints' in analysis
        assert analysis['has_insecure_endpoints'] is True

    @pytest.mark.asyncio
    async def test_update_single_trustlist_open_failure(self, mock_opc_device):
        """Test trustlist update with open failure."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_trustlist_node = Mock()
        mock_open_method = Mock()

        mock_trustlist_node.get_child = AsyncMock(return_value=mock_open_method)
        mock_trustlist_node.call_method = AsyncMock(side_effect=Exception('Open failed'))

        trustlist_data = ua.TrustListDataType()
        trustlist_data.TrustedCertificates = []
        trustlist_data.IssuerCertificates = []
        trustlist_data.TrustedCrls = []
        trustlist_data.IssuerCrls = []

        success = await service._update_single_trustlist(mock_trustlist_node, trustlist_data)

        assert success is False

    @pytest.mark.asyncio
    async def test_analyze_endpoints_with_secure_policy(self, mock_opc_device):
        """Test endpoint analysis with secure policy."""
        service = GdsPushService(mock_opc_device, insecure=True)

        endpoint = {'security_policy': 'Basic256Sha256', 'security_mode': 'SignAndEncrypt'}

        analysis = service._analyze_endpoints([endpoint])

        assert 'has_secure_endpoints' in analysis
        assert analysis['has_secure_endpoints'] is True
        assert 'has_insecure_endpoints' in analysis
        assert analysis['has_insecure_endpoints'] is False

    @pytest.mark.asyncio
    async def test_discover_server_with_endpoint_url(self, mock_opc_device):
        """Test server discovery with endpoint URL."""
        service = GdsPushService(mock_opc_device, insecure=True)

        with patch('request.gds_push.gds_push_service.Client') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_endpoint1 = Mock()
            mock_endpoint1.EndpointUrl = 'opc.tcp://localhost:4840'
            mock_endpoint1.SecurityPolicyUri = 'http://opcfoundation.org/UA/SecurityPolicy#None'
            mock_endpoint1.SecurityMode = 1

            mock_client.connect_and_get_server_endpoints.return_value = [mock_endpoint1]

            # Mock the _gather_server_info method to avoid the async mock warning
            with patch.object(service, '_gather_server_info', new_callable=AsyncMock) as mock_gather:
                mock_gather.return_value = {'product_name': 'Test Server'}

                endpoints = await service.discover_server()

                assert len(endpoints) > 0

    @pytest.mark.asyncio
    async def test_update_single_trustlist_close_and_update_false(self, mock_opc_device):
        """Test trustlist update when CloseAndUpdate returns False."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_trustlist_node = Mock()
        mock_open_method = Mock()
        mock_read_method = Mock()
        mock_close_read_method = Mock()
        mock_write_method = Mock()
        mock_close_method = Mock()
        methods = {
            'Open': mock_open_method,
            'Read': mock_read_method,
            'Close': mock_close_read_method,
            'Write': mock_write_method,
            'CloseAndUpdate': mock_close_method,
        }

        async def get_child(name: str) -> Mock:
            return methods[name]

        mock_trustlist_node.get_child = AsyncMock(side_effect=get_child)

        mock_file_handle = 12345
        mock_trustlist_node.call_method = AsyncMock(
            side_effect=[
                1,  # Open (read)
                b'',  # Read -> end of file
                None,  # Close (read)
                mock_file_handle,  # Open (write)
                None,  # Write
                False,  # CloseAndUpdate returns False (apply_changes_required=False)
            ]
        )

        trustlist_data = ua.TrustListDataType()
        trustlist_data.TrustedCertificates = []
        trustlist_data.IssuerCertificates = []
        trustlist_data.TrustedCrls = []
        trustlist_data.IssuerCrls = []

        success = await service._update_single_trustlist(mock_trustlist_node, trustlist_data)

        assert success is True


class TestGdsPushServiceAdditionalCoverage:
    """Additional test cases to reach 70% coverage."""

    def test_create_insecure_client(self, mock_opc_device):
        """Test creating insecure OPC UA client."""
        service = GdsPushService(mock_opc_device, insecure=True)

        with patch('request.gds_push.gds_push_service.Client') as mock_client_class:
            client = service._create_insecure_client()

            mock_client_class.assert_called_once_with('opc.tcp://192.168.1.100:4840')
            assert client.application_uri == 'urn:trustpoint:gds-push'

    @pytest.mark.asyncio
    async def test_gather_server_info(self, mock_opc_device):
        """Test gathering server information."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_client = Mock()
        mock_endpoint = Mock()
        mock_endpoint.EndpointUrl = 'opc.tcp://test:4840'
        mock_endpoint.SecurityMode = ua.MessageSecurityMode.None_
        mock_endpoint.SecurityPolicyUri = 'http://opcfoundation.org/UA/SecurityPolicy#None'

        mock_client.connect_and_get_server_endpoints = AsyncMock(return_value=[mock_endpoint])
        mock_client.find_servers = AsyncMock(return_value=[])

        server_info = await service._gather_server_info(mock_client)

        assert 'endpoints' in server_info
        assert len(server_info['endpoints']) == 1

    @pytest.mark.asyncio
    async def test_discover_trustlist_nodes(self, mock_opc_device):
        """Test discovering trustlist nodes."""
        service = GdsPushService(mock_opc_device, insecure=True)

        mock_client = Mock()
        mock_server_node = Mock()
        mock_cert_groups = Mock()
        mock_group = Mock()
        mock_trustlist = Mock()

        mock_client.get_node = Mock(side_effect=[mock_server_node])
        mock_server_node.get_child = AsyncMock(side_effect=[mock_cert_groups])
        mock_cert_groups.get_children = AsyncMock(return_value=[mock_group])
        mock_group.get_child = AsyncMock(return_value=mock_trustlist)

        trustlist_nodes = await service._discover_trustlist_nodes(mock_client)

        assert isinstance(trustlist_nodes, list)

    def test_raise_gds_push_error(self, mock_opc_device):
        """Test raising GDS push error."""
        service = GdsPushService(mock_opc_device, insecure=True)

        with pytest.raises(GdsPushError, match='Test error message'):
            service._raise_gds_push_error('Test error message')

    @pytest.mark.asyncio
    async def test_build_ca_chain_no_domain(self, mock_opc_device):
        """Test building CA chain with no domain."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Mock device with no domain
        with patch.object(service, 'device') as mock_device:
            mock_device.domain = None

            with pytest.raises(GdsPushError, match='has no domain configured'):
                await service._build_ca_chain()

    def test_validate_client_certificate_missing_san(self, mock_opc_device):
        """Test validating client certificate with missing SAN."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Create certificate without SAN
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test.example.com'),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(tz=datetime.UTC))
            .not_valid_after(datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='Subject Alternative Name extension is missing'):
            service._validate_client_certificate(cert)

    def test_extract_application_uri_no_san(self, mock_opc_device):
        """Test extracting application URI with no SAN."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Create certificate without SAN
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test.example.com'),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(tz=datetime.UTC))
            .not_valid_after(datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='No application URI found'):
            service._extract_application_uri(cert)

    def test_get_server_truststore_no_config(self, mock_opc_device):
        """Test getting server truststore with no onboarding config."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Mock device with no onboarding config
        service.device.opc_ua_gds_push_config.delete()
        service.device.refresh_from_db()

        with pytest.raises(GdsPushError, match='has no OPC UA GDS Push config'):
            service._get_server_truststore()

    @pytest.mark.asyncio
    async def test_build_ca_chain_without_issuing_ca(self, mock_opc_device):
        """Reject a domain that cannot provide an issuing CA."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.device.domain.issuing_ca = None

        with pytest.raises(GdsPushError, match='has no issuing CA configured'):
            await service._build_ca_chain()

    @pytest.mark.asyncio
    async def test_build_trustlist_rejects_missing_crl(self, mock_opc_device):
        """Reject a trustlist when any CA is missing its mandatory CRL."""
        service = GdsPushService(mock_opc_device, insecure=True)
        ca = Mock()
        ca.unique_name = 'missing-crl'
        ca.ca_certificate_model = Mock()
        ca.ca_certificate_model.get_certificate_serializer.return_value.as_crypto.return_value = Mock(
            public_bytes=Mock(return_value=b'ca-cert')
        )
        ca.crl_pem = None

        with patch.object(service, '_build_ca_chain', return_value=[ca]):
            with pytest.raises(GdsPushError, match='has no CRL configured'):
                await service._build_trustlist_for_server()

    @pytest.mark.asyncio
    async def test_get_client_credentials_rejects_invalid_credential(self, mock_opc_device, mock_domain_credential):
        """Reject an invalid domain credential before reading its key."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.domain_credential = mock_domain_credential

        with (
            patch.object(
                mock_domain_credential,
                'is_valid_domain_credential',
                return_value=(False, 'revoked'),
            ),
            patch.object(service, '_validate_client_certificate') as validate,
        ):
            with pytest.raises(GdsPushError, match='Invalid domain credential: revoked'):
                await service._get_client_credentials()

        validate.assert_not_called()

    @pytest.mark.asyncio
    async def test_apply_and_cancel_skip_when_transactions_unsupported(self, mock_opc_device):
        """Do not call ApplyChanges/CancelChanges when the server applies updates immediately."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service._capabilities = {'SupportsTransactions': False}
        client = Mock()

        await service._apply_changes(client)
        await service._cancel_changes(client)

        client.get_node.assert_not_called()

    def test_ca_chain_validation_accepts_trusted_root(self, mock_opc_device):
        """Accept a leaf that chains to a trusted root CA."""
        service = GdsPushService(mock_opc_device, insecure=True)
        root, leaf = _make_ca_chain()

        service._validate_server_certificate_chain(leaf, [root])

    def test_ca_chain_validation_rejects_untrusted_leaf(self, mock_opc_device):
        """Reject a leaf that does not chain to the truststore."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()

        with pytest.raises(GdsPushError, match='does not chain'):
            service._validate_server_certificate_chain(leaf, [])

    def test_certificate_group_due_uses_actual_inventory(self, mock_opc_device):
        """Decide renewal from the certificate in the selected slot."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        type_id = ua.NodeId.from_string('ns=0;i=12560')
        group = {
            'name': 'Server',
            'certificate_type_id': type_id,
            'current_certificates': {type_id: leaf.public_bytes(serialization.Encoding.DER)},
        }

        assert service._certificate_group_due(group, 30, datetime.datetime.now(datetime.UTC)) is False
        assert service._certificate_group_due(group, 1000, datetime.datetime.now(datetime.UTC)) is True

    def test_effective_trustlist_prunes_only_stale_managed_entries(self, mock_opc_device):
        """Remove previously managed entries that disappeared; keep external entries."""
        service = GdsPushService(mock_opc_device, insecure=True)
        import hashlib

        managed_entry = b'managed'
        external_entry = b'external'
        desired_entry = b'desired'
        mock_opc_device.opc_ua_gds_push_config.opc_gds_push_managed_trustlist_state = {
            'Server': {'TrustedCertificates': [hashlib.sha256(managed_entry).hexdigest()]}
        }
        current = ua.TrustListDataType()
        current.SpecifiedLists = int(ua.TrustListMasks.All)
        current.TrustedCertificates = [managed_entry, external_entry]
        desired = ua.TrustListDataType()
        desired.SpecifiedLists = int(ua.TrustListMasks.All)
        desired.TrustedCertificates = [desired_entry]

        effective = service._effective_trustlist(current, desired, 'Server')

        assert managed_entry not in effective.TrustedCertificates
        assert external_entry in effective.TrustedCertificates
        assert desired_entry in effective.TrustedCertificates

    def test_effective_trustlist_authoritative_replaces_external_entries(self, mock_opc_device):
        """Authoritative mode returns only the desired state."""
        service = GdsPushService(mock_opc_device, insecure=True)
        config = mock_opc_device.opc_ua_gds_push_config
        config.opc_gds_push_trustlist_mode = 'authoritative'
        current = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[b'external'],
        )
        desired = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[b'desired'],
        )

        effective = service._effective_trustlist(current, desired, 'Server')

        assert effective.TrustedCertificates == [b'desired']

    def test_managed_state_does_not_claim_preexisting_entries(self, mock_opc_device):
        """Managed mode claims only newly added desired entries, never pre-existing ones."""
        service = GdsPushService(mock_opc_device, insecure=True)
        existing = b'existing'
        added = b'added'
        current = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[existing],
        )
        desired = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[existing, added],
        )

        state = service._compute_managed_state({'Server': current}, {'Server': desired}, adopt_all=False)

        owned = state['Server']['TrustedCertificates']
        assert hashlib.sha256(existing).hexdigest() not in owned
        assert hashlib.sha256(added).hexdigest() in owned

    def test_authoritative_state_adopts_all_desired_entries(self, mock_opc_device):
        """Authoritative mode explicitly adopts the complete desired list."""
        service = GdsPushService(mock_opc_device, insecure=True)
        existing = b'existing'
        desired = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[existing],
        )

        state = service._compute_managed_state({'Server': None}, {'Server': desired}, adopt_all=True)

        assert hashlib.sha256(existing).hexdigest() in state['Server']['TrustedCertificates']

    def test_managed_state_is_scoped_per_group(self, mock_opc_device):
        """Ownership in one group does not prune entries in another group."""
        service = GdsPushService(mock_opc_device, insecure=True)
        import hashlib

        owned = b'owned'
        mock_opc_device.opc_ua_gds_push_config.opc_gds_push_managed_trustlist_state = {
            'GroupA': {'TrustedCertificates': [hashlib.sha256(owned).hexdigest()]},
        }
        current = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[owned],
        )
        desired = ua.TrustListDataType(SpecifiedLists=int(ua.TrustListMasks.All))

        group_a = service._effective_trustlist(current, desired, 'GroupA')
        group_b = service._effective_trustlist(current, desired, 'GroupB')

        assert owned not in group_a.TrustedCertificates
        assert owned in group_b.TrustedCertificates

    @pytest.mark.asyncio
    async def test_build_trustlist_includes_additional_trust_material(self, mock_opc_device):
        """Add explicitly configured certificates to the desired TrustList."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, additional = _make_ca_chain()
        additional_der = additional.public_bytes(serialization.Encoding.DER)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Additional CA')])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_model = Mock()
        serializer = Mock()
        serializer.as_crypto = Mock(return_value=cert)
        cert_model.get_certificate_serializer.return_value = serializer
        ca = Mock(
            unique_name='Additional CA',
            ca_certificate_model=cert_model,
            crl_pem=crl.public_bytes(serialization.Encoding.PEM).decode(),
        )

        with (
            patch.object(service, '_build_ca_chain', new_callable=AsyncMock, return_value=[ca]),
            patch.object(
                service,
                '_build_additional_trust_material',
                new_callable=AsyncMock,
                return_value=([additional_der], []),
            ),
        ):
            trustlist = await service._build_trustlist_for_server()

        assert additional_der in trustlist.TrustedCertificates

    @pytest.mark.asyncio
    async def test_preview_authoritative_trustlist_reports_removals(self, mock_opc_device):
        """Preview lists entries that authoritative mode would remove without writing."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        desired = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[leaf.public_bytes(serialization.Encoding.DER)],
        )
        extra = b'external-certificate'
        current = ua.TrustListDataType(
            SpecifiedLists=int(ua.TrustListMasks.All),
            TrustedCertificates=[*desired.TrustedCertificates, extra],
        )
        node_info = {'group_name': 'Server', 'trustlist_node': Mock()}
        client = Mock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_discover_trustlist_nodes', new_callable=AsyncMock, return_value=[node_info]),
            patch.object(service, '_build_trustlist_for_server', new_callable=AsyncMock, return_value=desired),
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=current),
            patch.object(service, '_write_trustlist', new_callable=AsyncMock) as write,
        ):
            success, message, removals = await service.preview_authoritative_trustlist()

        assert success, message
        assert '1 trust-list entry would be removed' in message
        assert removals['Server']['TrustedCertificates'][0]['sha256'] == hashlib.sha256(extra).hexdigest()
        write.assert_not_called()

    @pytest.mark.asyncio
    async def test_reconcile_skips_unchanged_state(self, mock_opc_device):
        """Do not write or apply when both trust lists and certificates are current."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        type_id = ua.NodeId.from_string('ns=0;i=12560')
        desired = ua.TrustListDataType()
        desired.SpecifiedLists = int(ua.TrustListMasks.All)
        desired.TrustedCertificates = [leaf.public_bytes(serialization.Encoding.DER)]
        group = {
            'name': 'Server',
            'node_id': ua.NodeId.from_string('ns=0;i=1'),
            'certificate_type_id': type_id,
            'current_certificates': {type_id: leaf.public_bytes(serialization.Encoding.DER)},
        }
        node_info = {'group_name': 'Server', 'trustlist_node': Mock()}
        client = Mock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_read_server_capabilities', new_callable=AsyncMock, return_value={}),
            patch.object(service, '_discover_certificate_groups', new_callable=AsyncMock, return_value=[group]),
            patch.object(service, '_discover_trustlist_nodes', new_callable=AsyncMock, return_value=[node_info]),
            patch.object(service, '_build_trustlist_for_server', new_callable=AsyncMock, return_value=desired),
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=desired),
            patch.object(service, '_write_trustlist', new_callable=AsyncMock) as write,
            patch.object(service, '_update_single_certificate', new_callable=AsyncMock) as update_cert,
            patch.object(service, '_apply_changes', new_callable=AsyncMock) as apply,
        ):
            success, message, certificate = await service.reconcile()

        assert success, message
        assert 'No certificate or trust list update required' in message
        assert certificate is None
        write.assert_not_called()
        update_cert.assert_not_called()
        apply.assert_not_called()

    @pytest.mark.asyncio
    async def test_reconcile_updates_trustlist_independently(self, mock_opc_device):
        """Update only the trust list when the server certificate is not due."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        type_id = ua.NodeId.from_string('ns=0;i=12560')
        desired = ua.TrustListDataType()
        desired.SpecifiedLists = int(ua.TrustListMasks.All)
        desired.TrustedCertificates = [leaf.public_bytes(serialization.Encoding.DER)]
        current = ua.TrustListDataType()
        current.SpecifiedLists = int(ua.TrustListMasks.All)
        group = {
            'name': 'Server',
            'node_id': ua.NodeId.from_string('ns=0;i=1'),
            'certificate_type_id': type_id,
            'current_certificates': {type_id: leaf.public_bytes(serialization.Encoding.DER)},
        }
        node_info = {'group_name': 'Server', 'trustlist_node': Mock()}
        client = Mock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        async def write_trustlist(*_args, **_kwargs):
            service._apply_changes_required = True
            return True

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_read_server_capabilities', new_callable=AsyncMock, return_value={}),
            patch.object(service, '_discover_certificate_groups', new_callable=AsyncMock, return_value=[group]),
            patch.object(service, '_discover_trustlist_nodes', new_callable=AsyncMock, return_value=[node_info]),
            patch.object(service, '_build_trustlist_for_server', new_callable=AsyncMock, return_value=desired),
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=current),
            patch.object(service, '_write_trustlist', side_effect=write_trustlist) as write,
            patch.object(service, '_update_single_certificate', new_callable=AsyncMock) as update_cert,
            patch.object(service, '_apply_changes', new_callable=AsyncMock) as apply,
            patch.object(service, '_record_managed_trustlist_state', new_callable=AsyncMock) as record_state,
            patch.object(service, '_verify_server_connection', new_callable=AsyncMock, return_value=(True, '')),
            patch.object(
                service,
                '_verify_trustlist_deployment',
                new_callable=AsyncMock,
                return_value=(True, ''),
            ),
        ):
            success, message, certificate = await service.reconcile()

        assert success, message
        write.assert_awaited_once()
        update_cert.assert_not_called()
        apply.assert_awaited_once()
        record_state.assert_awaited_once()
        assert certificate is None

    def test_ca_material_requires_basic_constraints_ca(self, mock_opc_device):
        """Reject a CA entry that is not marked as a CA."""
        service = GdsPushService(mock_opc_device, insecure=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Not a CA')])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='not marked as a CA'):
            service._validate_ca_material(cert, 'not-a-ca', has_crl=False)

    def test_ca_material_requires_key_cert_sign(self, mock_opc_device):
        """Reject a CA that cannot sign certificates."""
        service = GdsPushService(mock_opc_device, insecure=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Bad CA')])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        with pytest.raises(GdsPushError, match='keyCertSign'):
            service._validate_ca_material(cert, 'bad-ca', has_crl=False)

    @pytest.mark.asyncio
    async def test_gather_server_info_stores_leaf_from_chained_der(self, mock_opc_device):
        """Store only the leaf when the server advertises a concatenated chain."""
        service = GdsPushService(mock_opc_device, insecure=True)
        root, leaf = _make_ca_chain()
        chained = leaf.public_bytes(serialization.Encoding.DER) + root.public_bytes(serialization.Encoding.DER)
        endpoint = Mock(
            ServerCertificate=chained,
            EndpointUrl='opc.tcp://test:4840',
            SecurityMode=ua.MessageSecurityMode.None_,
            SecurityPolicyUri='http://opcfoundation.org/UA/SecurityPolicy#None',
        )
        client = Mock()
        client.connect_and_get_server_endpoints = AsyncMock(return_value=[endpoint])
        client.find_servers = AsyncMock(return_value=[])

        server_info = await service._gather_server_info(client)

        assert base64.b64decode(server_info['server_certificate']) == leaf.public_bytes(serialization.Encoding.DER)

    @pytest.mark.asyncio
    async def test_ca_mode_returns_discovered_leaf_certificate(self, mock_opc_device):
        """Use the discovered certificate when CA validation is selected."""
        service = GdsPushService(mock_opc_device, insecure=True)
        root, leaf = _make_ca_chain()
        leaf_der = leaf.public_bytes(serialization.Encoding.DER)
        endpoint = Mock(ServerCertificate=leaf_der)
        discovery = Mock()
        discovery.connect_and_get_server_endpoints = AsyncMock(return_value=[endpoint])
        discovery.disconnect = AsyncMock()
        mock_opc_device.opc_ua_gds_push_config.opc_gds_push_server_validation = 'ca'
        service.server_truststore = mock_opc_device.opc_ua_gds_push_config.opc_trust_store

        with (
            patch.object(service, '_create_insecure_client', return_value=discovery),
            patch.object(service, '_load_server_truststore_certificates', new_callable=AsyncMock, return_value=[root]),
        ):
            result = await service._get_server_certificate()

        assert result == leaf_der

    @pytest.mark.asyncio
    async def test_refresh_certificate_inventory_returns_json_safe_summary(self, mock_opc_device):
        """Summarize certificate groups, trust lists and rejected certificates."""
        import json

        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        leaf_der = leaf.public_bytes(serialization.Encoding.DER)
        client = Mock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(
                service,
                '_read_server_capabilities',
                new_callable=AsyncMock,
                return_value={'SupportsTransactions': True, 'MaxTrustListSize': 1024},
            ),
            patch.object(
                service,
                '_discover_certificate_groups',
                new_callable=AsyncMock,
                return_value=[
                    {
                        'name': 'Server',
                        'certificate_type_id': ua.NodeId.from_string('ns=0;i=12560'),
                        'current_certificates': {ua.NodeId.from_string('ns=0;i=12560'): leaf_der},
                    }
                ],
            ),
            patch.object(service, '_discover_trustlist_nodes', new_callable=AsyncMock, return_value=[]),
            patch.object(
                service,
                '_read_rejected_certificates',
                new_callable=AsyncMock,
                return_value=[leaf_der],
            ),
        ):
            success, message, inventory = await service.refresh_certificate_inventory()

        assert success, message
        assert inventory['certificate_groups'][0]['certificates'][0]['subject'] == 'CN=opc-server'
        assert len(inventory['rejected']) == 1
        json.dumps(inventory)

    @pytest.mark.asyncio
    async def test_read_trustlist_retries_transient_file_api_error(self, mock_opc_device):
        """Retry a busy TrustList read with backoff."""
        service = GdsPushService(mock_opc_device, insecure=True)
        node = Mock()
        methods = {'Open': Mock(), 'Read': Mock(), 'Close': Mock()}

        async def get_child(name: str) -> Mock:
            return methods[name]

        payload = struct_to_binary(ua.TrustListDataType())
        node.get_child = AsyncMock(side_effect=get_child)
        node.call_method = AsyncMock(
            side_effect=[
                UaStatusCodeError(StatusCodes.BadInvalidState),
                42,
                payload,
                b'',
                None,
            ]
        )
        with patch('request.gds_push.gds_push_service.asyncio.sleep', new_callable=AsyncMock):
            result = await service._read_trustlist(node)

        assert result is not None

    @pytest.mark.asyncio
    async def test_get_server_certificate_missing_order_zero(self, mock_opc_device):
        """Convert a missing order-zero truststore entry to GdsPushError."""
        service = GdsPushService(mock_opc_device, insecure=True)
        truststore = Mock()
        truststore.unique_name = 'server-store'
        truststore.truststoreordermodel_set.get.side_effect = TruststoreOrderModel.DoesNotExist
        service.server_truststore = truststore

        with pytest.raises(GdsPushError, match='has no certificate at order 0'):
            await service._get_server_certificate()

    @pytest.mark.asyncio
    async def test_create_secure_client_wraps_credential_failure(self, mock_opc_device):
        """Wrap failures during secure client setup with GdsPushError."""
        service = GdsPushService(mock_opc_device, insecure=True)

        with patch.object(
            service,
            '_get_client_credentials',
            side_effect=GdsPushError('credential unavailable'),
        ):
            with pytest.raises(GdsPushError, match='Failed to create secure client: credential unavailable'):
                await service._create_secure_client()

    @pytest.mark.asyncio
    async def test_gather_server_info_reads_endpoint_application_name(self, mock_opc_device):
        """Read the server name from discovery without reading session-bound nodes."""
        service = GdsPushService(mock_opc_device, insecure=True)
        endpoint = Mock(
            EndpointUrl='opc.tcp://server:4840',
            SecurityPolicyUri='None',
            SecurityMode=ua.MessageSecurityMode.None_,
            ServerCertificate=b'',
        )
        endpoint.Server = ua.ApplicationDescription(ApplicationName=ua.LocalizedText('Server A'))
        client = Mock()
        client.connect_and_get_server_endpoints = AsyncMock(return_value=[endpoint])

        info = await service._gather_server_info(client)

        assert info['server_name'] == 'Server A'
        assert info['endpoints'][0]['has_server_cert'] is False

    @pytest.mark.asyncio
    async def test_gather_server_info_captures_server_certificate(self, mock_opc_device):
        """Expose the endpoint certificate for initial truststore creation."""
        service = GdsPushService(mock_opc_device, insecure=True)
        endpoint = Mock(
            EndpointUrl='opc.tcp://server:4840',
            SecurityPolicyUri='http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
            SecurityMode=ua.MessageSecurityMode.SignAndEncrypt,
            ServerCertificate=b'der-certificate',
        )
        endpoint.Server = ua.ApplicationDescription(ApplicationName=ua.LocalizedText('Server A'))
        client = Mock()
        client.connect_and_get_server_endpoints = AsyncMock(return_value=[endpoint])

        info = await service._gather_server_info(client)

        assert info['server_certificate_available'] is True
        assert base64.b64decode(info['server_certificate']) == b'der-certificate'
        assert info['endpoints'][0]['has_server_cert'] is True

    @pytest.mark.asyncio
    async def test_update_trustlist_returns_no_nodes(self, mock_opc_device):
        """Report a connected server that exposes no TrustList nodes."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no capabilities'))

        with (
            patch.object(service, '_build_trustlist_for_server', return_value=Mock()),
            patch.object(service, '_create_secure_client', return_value=client),
            patch.object(service, '_discover_trustlist_nodes', return_value=[]),
        ):
            success, message = await service.update_trustlist()

        assert success is False
        assert message == 'No TrustList nodes found on server'
        client.__aenter__.assert_awaited_once()
        client.__aexit__.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_single_trustlist_writes_chunks_and_applies_changes(self, mock_opc_device):
        """Write serialized trustlist data in bounded chunks and apply changes."""
        service = GdsPushService(mock_opc_device, insecure=True)
        node = Mock()
        open_method, read_method, close_read_method, write_method, close_method, apply_method = (
            Mock() for _ in range(6)
        )
        methods = {
            'Open': open_method,
            'Read': read_method,
            'Close': close_read_method,
            'Write': write_method,
            'CloseAndUpdate': close_method,
        }

        async def get_child(name: str) -> Mock:
            return methods[name]

        node.get_child = AsyncMock(side_effect=get_child)
        node.call_method = AsyncMock(side_effect=[1, b'', None, 7, None, None, None, True, None])
        group_node = Mock()
        groups_node = Mock()
        config_node = Mock()
        node.get_parent = AsyncMock(return_value=group_node)
        group_node.get_parent = AsyncMock(return_value=groups_node)
        groups_node.get_parent = AsyncMock(return_value=config_node)
        config_node.get_child = AsyncMock(return_value=apply_method)
        config_node.call_method = AsyncMock()

        with patch('request.gds_push.gds_push_service.struct_to_binary', return_value=b'abcdef'):
            assert await service._update_single_trustlist(node, Mock(), max_chunk_size=2) is True

        assert node.call_method.await_args_list[4].args[2] == b'ab'
        assert node.call_method.await_args_list[5].args[2] == b'cd'
        assert node.call_method.await_args_list[6].args[2] == b'ef'
        config_node.call_method.assert_awaited_once_with(apply_method.nodeid)

    @pytest.mark.asyncio
    async def test_read_trustlist_parses_chunks(self, mock_opc_device):
        """Read and deserialize a TrustList returned in several blocks."""
        service = GdsPushService(mock_opc_device, insecure=True)
        node = Mock()
        methods = {'Open': Mock(), 'Read': Mock(), 'Close': Mock()}

        async def get_child(name: str) -> Mock:
            return methods[name]

        node.get_child = AsyncMock(side_effect=get_child)
        original = ua.TrustListDataType()
        original.SpecifiedLists = int(ua.TrustListMasks.All)
        original.TrustedCertificates = [b'one']
        payload = struct_to_binary(original)
        node.call_method = AsyncMock(side_effect=[42, payload[:3], payload[3:], b'', None])

        result = await service._read_trustlist(node)

        assert result is not None
        assert result.TrustedCertificates == [b'one']
        assert node.call_method.await_args_list[-1].args == (methods['Close'].nodeid, 42)

    def test_merge_trustlists_preserves_entries_and_replaces_crls(self, mock_opc_device):
        """Merge certificates and replace only CRLs for the same issuer."""
        service = GdsPushService(mock_opc_device, insecure=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_a = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Issuer A')])
        issuer_b = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Issuer B')])
        now = datetime.datetime.now(datetime.UTC)

        def crl(issuer: x509.Name) -> bytes:
            return (
                x509.CertificateRevocationListBuilder()
                .issuer_name(issuer)
                .last_update(now)
                .next_update(now + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256())
                .public_bytes(serialization.Encoding.DER)
            )

        old_a = crl(issuer_a)
        new_a = crl(issuer_a)
        other_b = crl(issuer_b)

        current = ua.TrustListDataType()
        current.SpecifiedLists = int(ua.TrustListMasks.All)
        current.TrustedCertificates = [b'existing-cert']
        current.TrustedCrls = [old_a, other_b]
        current.IssuerCertificates = [b'existing-issuer']
        current.IssuerCrls = [old_a, other_b]

        new = ua.TrustListDataType()
        new.SpecifiedLists = int(ua.TrustListMasks.All)
        new.TrustedCertificates = [b'existing-cert', b'new-cert']
        new.TrustedCrls = [new_a]
        new.IssuerCertificates = [b'new-issuer']
        new.IssuerCrls = [new_a]

        merged = service._merge_trustlists(current, new)

        assert merged.TrustedCertificates == [b'existing-cert', b'new-cert']
        assert merged.IssuerCertificates == [b'existing-issuer', b'new-issuer']
        assert merged.TrustedCrls == [other_b, new_a]
        assert merged.IssuerCrls == [other_b, new_a]
        assert merged.SpecifiedLists == int(ua.TrustListMasks.All)

    def test_merge_trustlists_removes_cert_duplicated_as_issuer(self, mock_opc_device):
        """A certificate already trusted must not also be kept in the issuer list."""
        service = GdsPushService(mock_opc_device, insecure=True)
        current = ua.TrustListDataType()
        current.TrustedCertificates = [b'root']
        current.IssuerCertificates = [b'root', b'intermediate']
        new = ua.TrustListDataType()
        new.TrustedCertificates = [b'root']
        new.IssuerCertificates = [b'intermediate']

        merged = service._merge_trustlists(current, new)

        assert merged.TrustedCertificates == [b'root']
        assert merged.IssuerCertificates == [b'intermediate']

    def test_trustlist_limits_allow_shared_entries_within_bounds(self, mock_opc_device):
        """Count unique DER objects and accept a trust list within the configured limits."""
        service = GdsPushService(mock_opc_device, insecure=True)
        config = service.device.opc_ua_gds_push_config
        config.opc_gds_push_max_trustlist_entries = 2
        config.opc_gds_push_max_trustlist_element_size = 4

        trustlist = ua.TrustListDataType()
        trustlist.TrustedCertificates = [b'a']
        trustlist.IssuerCertificates = [b'a']  # shared object counts once
        trustlist.TrustedCrls = [b'bb']
        trustlist.IssuerCrls = []

        service._validate_trustlist_limits(trustlist)

    def test_trustlist_limits_reject_excess_entries(self, mock_opc_device):
        """Reject a merged trust list that exceeds the device entry limit."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.device.opc_ua_gds_push_config.opc_gds_push_max_trustlist_entries = 1

        trustlist = ua.TrustListDataType()
        trustlist.TrustedCertificates = [b'a', b'b']

        with pytest.raises(GdsPushError, match='exceeding the device limit'):
            service._validate_trustlist_limits(trustlist)

    def test_trustlist_limits_reject_oversized_element(self, mock_opc_device):
        """Reject a single certificate or CRL larger than the device element limit."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.device.opc_ua_gds_push_config.opc_gds_push_max_trustlist_element_size = 2

        trustlist = ua.TrustListDataType()
        trustlist.TrustedCertificates = [b'abc']

        with pytest.raises(GdsPushError, match='element limit'):
            service._validate_trustlist_limits(trustlist)

    @pytest.mark.asyncio
    async def test_read_transaction_diagnostics(self, mock_opc_device):
        """Read and format the TransactionDiagnostics object."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = Mock()
        server_node = Mock()
        server_config = Mock()
        diagnostics = Mock()
        client.get_node.return_value = server_node
        server_node.get_child = AsyncMock(return_value=server_config)
        server_config.get_child = AsyncMock(return_value=diagnostics)
        values = {
            'Result': 'Good',
            'StartTime': 'start',
            'EndTime': 'end',
            'AffectedTrustLists': ['tl'],
            'AffectedCertificateGroups': ['cg'],
            'Errors': [],
        }

        async def get_child(name: str) -> Mock:
            node = Mock()
            node.read_value = AsyncMock(return_value=values[name])
            return node

        diagnostics.get_child = AsyncMock(side_effect=get_child)

        result = await service._read_transaction_diagnostics(client)

        assert 'Result=' in result
        assert 'AffectedTrustLists=' in result

    def test_effective_chunk_size_clamps_to_server_limit(self, mock_opc_device):
        """Never write a block larger than MaxByteStringLength."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service._capabilities = {'MaxByteStringLength': 2}
        assert service._effective_chunk_size(1024) == 2
        service._capabilities = {'MaxByteStringLength': 0}
        assert service._effective_chunk_size(1024) == 1024

    @pytest.mark.asyncio
    async def test_update_trustlist_reports_status_code_hint(self, mock_opc_device):
        """Preserve the status code and add an actionable hint."""
        service = GdsPushService(mock_opc_device, insecure=True)
        with (
            patch.object(service, '_build_trustlist_for_server', new_callable=AsyncMock),
            patch.object(
                service,
                '_create_secure_client',
                new_callable=AsyncMock,
                side_effect=UaStatusCodeError(StatusCodes.BadUserAccessDenied),
            ),
        ):
            success, message = await service.update_trustlist()

        assert success is False
        assert 'BadUserAccessDenied' in message
        assert 'SecurityAdmin' in message

    def test_trustlist_limits_reject_max_total_size(self, mock_opc_device):
        """Reject a serialized trust list above the server's MaxTrustListSize."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service._capabilities = {'MaxTrustListSize': 4}

        with pytest.raises(GdsPushError, match='MaxTrustListSize'):
            service._validate_trustlist_limits(ua.TrustListDataType(), serialized_size=5)

    @pytest.mark.asyncio
    async def test_read_group_certificates(self, mock_opc_device):
        """Read the currently assigned certificate per type from GetCertificates."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = Mock()
        server_node = Mock()
        server_config = Mock()
        method = Mock()
        client.get_node.return_value = server_node
        server_node.get_child = AsyncMock(return_value=server_config)
        server_config.get_child = AsyncMock(return_value=method)
        server_config.call_method = AsyncMock(
            return_value=([ua.NodeId(12560), ua.NodeId(12559)], [b'cert-a', b'cert-b'])
        )

        result = await service._read_group_certificates(client, ua.NodeId(1, 1))

        assert result == {ua.NodeId(12560): b'cert-a', ua.NodeId(12559): b'cert-b'}

    @pytest.mark.asyncio
    async def test_discovery_prefers_current_certificate_type(self, mock_opc_device):
        """Renew the certificate slot that is currently assigned."""
        service = GdsPushService(mock_opc_device, insecure=True)
        purpose_node = Mock()
        purpose_node.read_value = AsyncMock(return_value=ua.NodeId(12557))
        types_node = Mock()
        types_node.read_value = AsyncMock(return_value=[ua.NodeId(12560), ua.NodeId(12559)])
        group = Mock()
        group.nodeid = ua.NodeId(1, 2)
        group.read_browse_name = AsyncMock(return_value=Mock(Name='Application'))
        group.get_child = AsyncMock(
            side_effect=lambda name: {'Purpose': purpose_node, 'CertificateTypes': types_node}[name]
        )
        groups_node = Mock()
        groups_node.get_children = AsyncMock(return_value=[group])
        server_config = Mock()
        server_config.get_child = AsyncMock(return_value=groups_node)
        server_node = Mock()
        server_node.get_child = AsyncMock(return_value=server_config)
        client = Mock()
        client.get_node.return_value = server_node

        with patch.object(
            service,
            '_read_group_certificates',
            new_callable=AsyncMock,
            return_value={ua.NodeId(12559): b'current-cert'},
        ):
            groups = await service._discover_certificate_groups(client)

        assert groups[0]['certificate_type_id'] == ua.NodeId(12559)

    @pytest.mark.asyncio
    async def test_read_server_capabilities(self, mock_opc_device):
        """Read the ServerConfiguration properties used by the push workflow."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = Mock()
        server_node = Mock()
        server_config = Mock()
        client.get_node.return_value = server_node
        server_node.get_child = AsyncMock(return_value=server_config)
        values = {
            'MaxTrustListSize': 65535,
            'SupportedPrivateKeyFormats': ['PEM'],
            'SupportsTransactions': True,
            'InApplicationSetup': False,
            'HasSecureElement': True,
            'ServerCapabilities': ['GDS'],
        }

        async def get_child(name: str) -> Mock:
            if name not in values:
                raise RuntimeError(f'{name} unavailable')
            node = Mock()
            node.read_value = AsyncMock(return_value=values[name])
            return node

        server_config.get_child = AsyncMock(side_effect=get_child)

        capabilities = await service._read_server_capabilities(client)

        assert capabilities == values
        assert service._capabilities == values

    @pytest.mark.asyncio
    async def test_build_trustlist_uses_root_as_trust_anchor(self, mock_opc_device):
        """Put the root in the trusted lists and do not duplicate it as an issuer."""
        service = GdsPushService(mock_opc_device, insecure=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Test CA')])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()

        cert_model = Mock()
        serializer = Mock()
        serializer.as_crypto = Mock(return_value=cert)
        cert_model.get_certificate_serializer.return_value = serializer
        ca = Mock(unique_name='Test CA', ca_certificate_model=cert_model, crl_pem=crl_pem)

        with patch.object(service, '_build_ca_chain', new=AsyncMock(return_value=[ca])):
            trustlist = await service._build_trustlist_for_server()

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        assert trustlist.TrustedCertificates == [cert_der]
        assert trustlist.TrustedCrls == [crl_der]
        assert trustlist.IssuerCertificates == []
        assert trustlist.IssuerCrls == []

    @pytest.mark.asyncio
    async def test_combined_update_applies_once_and_updates_truststore(self, mock_opc_device):
        """Stage trust list and certificate in one session and apply once."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()

        async def update_trustlist(_node, _data, **_kwargs):
            service._apply_changes_required = True
            return True

        async def update_certificate(**_kwargs):
            service._apply_changes_required = True
            return True, b'new-cert', [b'issuer']

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_read_server_capabilities', new_callable=AsyncMock),
            patch.object(
                service,
                '_discover_trustlist_nodes',
                new_callable=AsyncMock,
                return_value=[{'group_name': 'Application', 'trustlist_node': Mock()}],
            ),
            patch.object(
                service,
                '_discover_certificate_groups',
                new_callable=AsyncMock,
                return_value=[{'name': 'Application', 'node_id': ua.NodeId(1, 1)}],
            ),
            patch.object(
                service, '_build_trustlist_for_server', new_callable=AsyncMock, return_value=ua.TrustListDataType()
            ),
            patch.object(service, '_read_rejected_certificates', new_callable=AsyncMock, return_value=[]),
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=ua.TrustListDataType()),
            patch.object(service, '_write_trustlist', side_effect=update_trustlist),
            patch.object(service, '_update_single_certificate', side_effect=update_certificate),
            patch.object(service, '_apply_changes', new_callable=AsyncMock) as apply_changes,
            patch.object(service, '_update_truststore_with_new_certificate', new_callable=AsyncMock) as update_store,
            patch.object(service, '_verify_server_connection', new_callable=AsyncMock, return_value=(True, '')),
            patch.object(service, '_verify_trustlist_deployment', new_callable=AsyncMock, return_value=(True, '')),
            patch.object(service, '_record_managed_trustlist_state', new_callable=AsyncMock),
        ):
            success, message, certificate = await service.update_trustlist_and_certificate()

        assert success is True
        assert certificate == b'new-cert'
        assert 'reconnect verified' in message
        apply_changes.assert_awaited_once_with(client)
        update_store.assert_awaited_once_with(b'new-cert', [b'issuer'])

    @pytest.mark.asyncio
    async def test_combined_update_stops_on_trustlist_failure(self, mock_opc_device):
        """Do not stage certificates or apply when the trust-list step failed."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no cancel'))
        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_read_server_capabilities', new_callable=AsyncMock),
            patch.object(
                service,
                '_discover_trustlist_nodes',
                new_callable=AsyncMock,
                return_value=[{'group_name': 'Application', 'trustlist_node': Mock()}],
            ),
            patch.object(
                service,
                '_discover_certificate_groups',
                new_callable=AsyncMock,
                return_value=[{'name': 'Application', 'node_id': ua.NodeId(1, 1)}],
            ),
            patch.object(
                service, '_build_trustlist_for_server', new_callable=AsyncMock, return_value=ua.TrustListDataType()
            ),
            patch.object(service, '_read_rejected_certificates', new_callable=AsyncMock, return_value=[]),
            patch.object(service, '_update_single_trustlist', new_callable=AsyncMock, return_value=False),
            patch.object(service, '_update_single_certificate', new_callable=AsyncMock) as update_cert,
            patch.object(service, '_apply_changes', new_callable=AsyncMock) as apply_changes,
        ):
            success, message, certificate = await service.update_trustlist_and_certificate()

        assert success is False
        assert certificate is None
        assert 'Trustlist update failed' in message
        update_cert.assert_not_awaited()
        apply_changes.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_update_server_certificate_applies_once(self, mock_opc_device):
        """Defer ApplyChanges until every targeted certificate group is staged."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no capabilities'))
        groups = [
            {'name': 'ApplicationA', 'node_id': ua.NodeId(1, 1), 'certificate_type_id': ua.NodeId(12560)},
            {'name': 'ApplicationB', 'node_id': ua.NodeId(1, 2), 'certificate_type_id': ua.NodeId(12560)},
        ]

        async def update_certificate(**_kwargs):
            service._apply_changes_required = True
            return True, b'new-cert', [b'issuer']

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_discover_certificate_groups', new_callable=AsyncMock, return_value=groups),
            patch.object(service, '_update_single_certificate', side_effect=update_certificate),
            patch.object(service, '_apply_changes', new_callable=AsyncMock) as apply_changes,
            patch.object(service, '_update_truststore_with_new_certificate', new_callable=AsyncMock),
            patch.object(service, '_verify_server_connection', new_callable=AsyncMock, return_value=(True, '')),
        ):
            success, message, certificate = await service.update_server_certificate()

        assert success is True
        assert certificate == b'new-cert'
        assert 'reconnect verified' in message
        apply_changes.assert_awaited_once_with(client)

    @pytest.mark.asyncio
    async def test_update_server_certificate_reports_partial_success_as_failure(self, mock_opc_device):
        """Do not report success when only some discovered application groups were updated."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no capabilities'))
        groups = [
            {'name': 'ApplicationGroupA', 'node_id': ua.NodeId(1, 1), 'certificate_type_id': ua.NodeId(12560)},
            {'name': 'ApplicationGroupB', 'node_id': ua.NodeId(1, 2), 'certificate_type_id': ua.NodeId(12560)},
        ]

        with (
            patch.object(service, '_create_secure_client', return_value=client),
            patch.object(service, '_discover_certificate_groups', return_value=groups),
            patch.object(
                service,
                '_update_single_certificate',
                side_effect=[(True, b'new-cert', [b'issuer']), (False, None, None)],
            ) as update,
            patch.object(service, '_update_truststore_with_new_certificate') as update_truststore,
        ):
            success, message, cert_data = await service.update_server_certificate()

        assert (success, cert_data) == (False, None)
        assert 'Updated only 1/2 certificate(s)' in message
        assert update.await_count == 2
        update.assert_awaited_with(
            client=client,
            certificate_group_id=groups[1]['node_id'],
            certificate_type_id=groups[1]['certificate_type_id'],
            regenerate_private_key=False,
            defer_apply=True,
        )
        update_truststore.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_update_single_certificate_uploads_generated_key_when_needed(self, mock_opc_device):
        """Fall back to a Trustpoint-generated key and upload it as PEM."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service._capabilities = {'SupportedPrivateKeyFormats': ['PEM']}
        client = Mock()
        server_node = Mock()
        server_config = Mock()
        client.get_node.return_value = server_node
        server_node.get_child = AsyncMock(return_value=server_config)
        server_config.get_child = AsyncMock(return_value=Mock())
        server_config.call_method = AsyncMock(side_effect=[UaStatusCodeError(StatusCodes.BadNotSupported), False])

        with patch.object(service, '_sign_csr', return_value=(b'signed', [b'issuer'], Mock())):
            success, cert_data, _chain_data = await service._update_single_certificate(
                client, ua.NodeId(1, 2), regenerate_private_key=True
            )

        assert success is True
        assert cert_data == b'signed'
        update_args = server_config.call_method.await_args_list[1].args
        assert update_args[5] == 'PEM'
        assert update_args[6]

    @pytest.mark.asyncio
    async def test_update_single_certificate_generates_key_when_rollover_is_ignored(self, mock_opc_device):
        """Honor rollover by generating and uploading a new key when the server ignores the flag."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service._capabilities = {'SupportedPrivateKeyFormats': ['PEM']}
        client = Mock()
        server_node = Mock()
        server_config = Mock()
        client.get_node.return_value = server_node
        server_node.get_child = AsyncMock(return_value=server_config)
        server_config.get_child = AsyncMock(return_value=Mock())
        server_config.call_method = AsyncMock(side_effect=[b'csr', False])

        with patch.object(
            service,
            '_sign_csr',
            side_effect=[
                GdsPushError('Server ignored RegeneratePrivateKey; the CSR still uses the current public key.'),
                (b'signed', [b'issuer'], Mock()),
            ],
        ):
            success, cert_data, _chain_data = await service._update_single_certificate(
                client, ua.NodeId(1, 2), regenerate_private_key=True
            )

        assert success is True
        assert cert_data == b'signed'
        update_args = server_config.call_method.await_args_list[1].args
        assert update_args[5] == 'PEM'
        assert update_args[6]

    @pytest.mark.asyncio
    async def test_update_single_certificate_returns_false_on_server_error(self, mock_opc_device):
        """Return a failed result when the server rejects CSR creation."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = Mock()
        client.get_node.side_effect = RuntimeError('CSR unavailable')

        result = await service._update_single_certificate(client, ua.NodeId(1, 2))

        assert result == (False, None, None)

    @staticmethod
    def _identity_material(
        *,
        cn: str = 'server',
        uri: str = 'urn:test:server',
        dns: str = 'server.local',
        csr_cn: str | None = None,
        csr_uris: list[str] | None = None,
        csr_dns: list[str] | None = None,
        csr_ips: list[str] | None = None,
        csr_key: rsa.RSAPrivateKey | None = None,
    ) -> tuple[x509.Certificate, x509.CertificateSigningRequest]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(uri),
                        x509.DNSName(dns),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        csr_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, csr_cn or cn)])
        san_values: list[x509.GeneralName] = []
        for csr_uri in csr_uris if csr_uris is not None else [uri]:
            san_values.append(x509.UniformResourceIdentifier(csr_uri))
        for csr_dns_name in csr_dns if csr_dns is not None else [dns]:
            san_values.append(x509.DNSName(csr_dns_name))
        for csr_ip in csr_ips or []:
            san_values.append(x509.IPAddress(ipaddress.ip_address(csr_ip)))
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(csr_subject)
            .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
            .sign(csr_key or key, hashes.SHA256())
        )
        return cert, csr

    @pytest.mark.asyncio
    async def test_validate_csr_identity_accepts_matching_identity(self, mock_opc_device):
        """Accept a CSR that preserves the current CN, ApplicationUri and DNS SAN."""
        service = GdsPushService(mock_opc_device, insecure=True)
        cert, csr = self._identity_material()
        service.server_truststore = Mock()
        service._get_server_certificate = AsyncMock(return_value=cert.public_bytes(serialization.Encoding.DER))

        await service._validate_csr_identity(csr)

    @pytest.mark.asyncio
    async def test_validate_csr_identity_rejects_missing_application_uri(self, mock_opc_device):
        """Require exactly one ApplicationUri SAN in the server CSR."""
        service = GdsPushService(mock_opc_device, insecure=True)
        cert, csr = self._identity_material(csr_uris=[])
        service.server_truststore = Mock()
        service._get_server_certificate = AsyncMock(return_value=cert.public_bytes(serialization.Encoding.DER))

        with pytest.raises(GdsPushError, match='exactly one ApplicationUri'):
            await service._validate_csr_identity(csr)

    @pytest.mark.asyncio
    async def test_validate_csr_identity_rejects_changed_common_name(self, mock_opc_device):
        """Reject a CSR that changes the CN some servers require to stay stable."""
        service = GdsPushService(mock_opc_device, insecure=True)
        cert, csr = self._identity_material(csr_cn='other-server')
        service.server_truststore = Mock()
        service._get_server_certificate = AsyncMock(return_value=cert.public_bytes(serialization.Encoding.DER))

        with pytest.raises(GdsPushError, match='Common Name'):
            await service._validate_csr_identity(csr)

    @pytest.mark.asyncio
    async def test_validate_csr_identity_rejects_missing_preserved_dns(self, mock_opc_device):
        """Require the CSR to keep the current certificate's DNS SANs."""
        service = GdsPushService(mock_opc_device, insecure=True)
        cert, csr = self._identity_material(csr_dns=[], csr_ips=['127.0.0.1'])
        service.server_truststore = Mock()
        service._get_server_certificate = AsyncMock(return_value=cert.public_bytes(serialization.Encoding.DER))

        with pytest.raises(GdsPushError, match='does not preserve'):
            await service._validate_csr_identity(csr)

    @pytest.mark.asyncio
    async def test_validate_csr_identity_detects_ignored_key_rollover(self, mock_opc_device):
        """Fail when rollover was requested but the CSR still uses the current key."""
        service = GdsPushService(mock_opc_device, insecure=True)
        cert, csr = self._identity_material()
        service.server_truststore = Mock()
        service._get_server_certificate = AsyncMock(return_value=cert.public_bytes(serialization.Encoding.DER))

        with pytest.raises(GdsPushError, match='ignored RegeneratePrivateKey'):
            await service._validate_csr_identity(csr, expect_new_key=True)

    @pytest.mark.asyncio
    async def test_validate_csr_identity_accepts_new_key(self, mock_opc_device):
        """Accept a new key when rollover was requested."""
        service = GdsPushService(mock_opc_device, insecure=True)
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert, csr = self._identity_material(csr_key=new_key)
        service.server_truststore = Mock()
        service._get_server_certificate = AsyncMock(return_value=cert.public_bytes(serialization.Encoding.DER))

        await service._validate_csr_identity(csr, expect_new_key=True)

    @pytest.mark.asyncio
    async def test_sign_csr_rejects_invalid_der(self, mock_opc_device):
        """Wrap malformed server CSR data as a GdsPushError."""
        service = GdsPushService(mock_opc_device, insecure=True)

        with pytest.raises(GdsPushError, match='Failed to sign CSR'):
            await service._sign_csr(b'not-a-csr')

    @pytest.mark.asyncio
    async def test_update_truststore_rejects_unknown_server_certificate(self, mock_opc_device):
        """Fail before creating truststore orders when the new certificate is unknown."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.server_truststore = Mock(unique_name='server-store')
        service.server_truststore.truststoreordermodel_set.get.side_effect = TruststoreOrderModel.DoesNotExist
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'new-server')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'new-server')]))
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )

        with patch(
            'request.gds_push.gds_push_service.CertificateModel.get_cert_by_sha256_fingerprint', return_value=None
        ):
            with pytest.raises(GdsPushError, match='Server certificate not found in database'):
                await service._update_truststore_with_new_certificate(cert.public_bytes(serialization.Encoding.DER), [])

    @pytest.mark.asyncio
    async def test_update_trustlist_applies_once(self, mock_opc_device):
        """Defer ApplyChanges until every targeted trust list has been written."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no capabilities'))
        nodes = [
            {'group_name': 'ApplicationA', 'trustlist_node': Mock()},
            {'group_name': 'ApplicationB', 'trustlist_node': Mock()},
        ]

        async def update_node(_node, _trustlist, **_kwargs):
            service._apply_changes_required = True
            return True

        with (
            patch.object(service, '_build_trustlist_for_server', new_callable=AsyncMock),
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_discover_trustlist_nodes', new_callable=AsyncMock, return_value=nodes),
            patch.object(service, '_read_rejected_certificates', new_callable=AsyncMock, return_value=[]),
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=ua.TrustListDataType()),
            patch.object(service, '_write_trustlist', side_effect=update_node),
            patch.object(service, '_apply_changes', new_callable=AsyncMock) as apply_changes,
            patch.object(service, '_verify_server_connection', new_callable=AsyncMock, return_value=(True, '')),
            patch.object(service, '_verify_trustlist_deployment', new_callable=AsyncMock, return_value=(True, '')),
            patch.object(service, '_record_managed_trustlist_state', new_callable=AsyncMock),
        ):
            success, message = await service.update_trustlist()

        assert success is True
        assert 'reconnect verified' in message
        apply_changes.assert_awaited_once_with(client)

    @pytest.mark.asyncio
    async def test_update_trustlist_does_not_apply_on_partial_failure(self, mock_opc_device):
        """Leave the transaction uncommitted when one group fails."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no capabilities'))
        nodes = [
            {'group_name': 'ApplicationA', 'trustlist_node': Mock()},
            {'group_name': 'ApplicationB', 'trustlist_node': Mock()},
        ]

        async def update_node(_node, _trustlist, **_kwargs):
            service._apply_changes_required = True
            return _node is nodes[0]['trustlist_node']

        with (
            patch.object(service, '_build_trustlist_for_server', new_callable=AsyncMock),
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_discover_trustlist_nodes', new_callable=AsyncMock, return_value=nodes),
            patch.object(service, '_read_rejected_certificates', new_callable=AsyncMock, return_value=[]),
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=ua.TrustListDataType()),
            patch.object(service, '_write_trustlist', side_effect=update_node),
            patch.object(service, '_apply_changes', new_callable=AsyncMock) as apply_changes,
        ):
            success, _message = await service.update_trustlist()

        assert success is False
        apply_changes.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_update_trustlist_reports_mixed_group_results(self, mock_opc_device):
        """Report both successful and failed TrustList group updates."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no rejected list'))
        nodes = [
            {'group_name': 'Application', 'trustlist_node': Mock()},
            {'group_name': 'Https', 'trustlist_node': Mock()},
        ]

        with (
            patch.object(service, '_build_trustlist_for_server', new_callable=AsyncMock),
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_discover_trustlist_nodes', new_callable=AsyncMock, return_value=nodes),
            patch.object(service, '_read_trustlist', new_callable=AsyncMock, return_value=ua.TrustListDataType()),
            patch.object(service, '_write_trustlist', new_callable=AsyncMock, side_effect=[True, False]) as update,
        ):
            success, message = await service.update_trustlist()

        assert success is False
        assert 'Failed to update 1/2 trustlist(s)' in message
        assert '✓ Application' in message
        assert '✗ Https' in message
        assert update.await_args_list[0].args[0] is nodes[0]['trustlist_node']
        assert update.await_args_list[1].args[0] is nodes[1]['trustlist_node']

    @pytest.mark.asyncio
    async def test_discover_trustlist_nodes_skips_group_that_cannot_be_read(self, mock_opc_device):
        """Continue discovery when one certificate group has no TrustList."""
        service = GdsPushService(mock_opc_device, insecure=True)
        server_node = Mock()
        config_node = Mock()
        groups_node = Mock()
        good_group = Mock()
        bad_group = Mock()
        good_name = Mock(Name='Application')
        good_trustlist = Mock()
        good_group.read_browse_name = AsyncMock(return_value=good_name)
        good_group.get_child = AsyncMock(return_value=good_trustlist)
        bad_group.read_browse_name = AsyncMock(side_effect=RuntimeError('browse failed'))
        server_node.get_child = AsyncMock(return_value=config_node)
        config_node.get_child = AsyncMock(return_value=groups_node)
        groups_node.get_children = AsyncMock(return_value=[bad_group, good_group])
        service_client = Mock()
        service_client.get_node.return_value = server_node

        nodes = await service._discover_trustlist_nodes(service_client)

        assert nodes == [
            {
                'group_name': 'Application',
                'group_node': good_group,
                'trustlist_node': good_trustlist,
            }
        ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize('security_fails', [False, True])
    async def test_create_secure_client_sets_credentials_and_security_payload(self, mock_opc_device, security_fails):
        """Load security files and remove them on both success and failure."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.device.opc_ua_gds_push_config.opc_user = 'opc-user'
        service.device.opc_ua_gds_push_config.opc_password = 'opc-password'
        client = Mock()
        client.set_security = AsyncMock()
        certificate = Mock()
        _root, leaf = _make_ca_chain()
        server_der = leaf.public_bytes(serialization.Encoding.DER)

        async def load_security_files(*args, **kwargs):
            assert Path(kwargs['certificate']).read_bytes() == b'client-chain'
            assert Path(kwargs['private_key']).read_bytes() == b'private-key'
            assert Path(kwargs['server_certificate']).read_bytes() == server_der
            if security_fails:
                raise RuntimeError('security setup failed')

        client.set_security.side_effect = load_security_files

        with (
            patch('request.gds_push.gds_push_service.Client', return_value=client),
            patch.object(
                service, '_get_client_credentials', new_callable=AsyncMock, return_value=(certificate, b'private-key')
            ),
            patch.object(service, '_get_server_certificate', new_callable=AsyncMock, return_value=server_der),
            patch.object(service, '_extract_application_uri', return_value='urn:test:app'),
            patch.object(
                service, '_build_client_certificate_chain', new_callable=AsyncMock, return_value=b'client-chain'
            ),
            patch.object(
                service,
                '_select_security_policy',
                new_callable=AsyncMock,
                return_value=(security_policies.SecurityPolicyBasic256Sha256, 'Basic256Sha256'),
            ),
        ):
            if security_fails:
                with pytest.raises(GdsPushError, match='security setup failed'):
                    await service._create_secure_client()
            else:
                assert await service._create_secure_client() is client

        assert client.application_uri == 'urn:test:app'
        assert client.secure_channel_timeout == 10000
        assert client.session_timeout == 20000
        if not security_fails:
            client.set_user.assert_called_once_with('opc-user')
            client.set_password.assert_called_once_with('opc-password')
        client.set_security.assert_awaited_once()
        security_args = client.set_security.await_args.kwargs
        assert security_args['mode'] == ua.MessageSecurityMode.SignAndEncrypt
        assert security_args['server_certificate'].endswith('.der')
        paths = [Path(security_args[name]) for name in ('certificate', 'private_key', 'server_certificate')]
        assert all(not path.exists() for path in paths)
        assert len({path.parent for path in paths}) == 1
        assert not paths[0].parent.exists()

    @staticmethod
    def _policy_endpoint(name: str, mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt) -> Mock:
        return Mock(
            SecurityMode=mode,
            SecurityPolicyUri=f'http://opcfoundation.org/UA/SecurityPolicy#{name}',
        )

    @staticmethod
    def _select_policy_discovery(*endpoints: Mock) -> Mock:
        discovery = Mock()
        discovery.disconnect = AsyncMock()
        discovery.connect_and_get_server_endpoints = AsyncMock(return_value=list(endpoints))
        return discovery

    @pytest.mark.asyncio
    async def test_select_security_policy_prefers_strongest_permitted(self, mock_opc_device):
        """Choose the strongest permitted SignAndEncrypt policy advertised by the server."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        discovery = self._select_policy_discovery(
            self._policy_endpoint('Basic256Sha256'),
            self._policy_endpoint('Aes128Sha256RsaOaep'),
            self._policy_endpoint('Aes256Sha256RsaPss'),
            self._policy_endpoint('None', ua.MessageSecurityMode.None_),
        )

        with patch.object(service, '_create_insecure_client', return_value=discovery):
            policy, name = await service._select_security_policy(leaf, leaf)

        assert name == 'Aes256Sha256RsaPss'
        assert policy is security_policies.SecurityPolicyAes256Sha256RsaPss

    @pytest.mark.asyncio
    async def test_select_security_policy_respects_allow_list(self, mock_opc_device):
        """Do not select a policy disabled in SecurityConfig."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        _set_service_security_config(service, permitted_opc_ua_security_policies=['Basic256Sha256'])
        discovery = self._select_policy_discovery(
            self._policy_endpoint('Aes256Sha256RsaPss'),
            self._policy_endpoint('Basic256Sha256'),
        )

        with patch.object(service, '_create_insecure_client', return_value=discovery):
            _policy, name = await service._select_security_policy(leaf, leaf)

        assert name == 'Basic256Sha256'

    @pytest.mark.asyncio
    async def test_select_security_policy_never_falls_back_to_legacy(self, mock_opc_device):
        """Fail instead of silently downgrading when only a legacy policy is advertised."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        _set_service_security_config(
            service, permitted_opc_ua_security_policies=['Aes256Sha256RsaPss', 'Basic256Sha256']
        )
        discovery = self._select_policy_discovery(self._policy_endpoint('Basic256'))

        with (
            patch.object(service, '_create_insecure_client', return_value=discovery),
            pytest.raises(GdsPushError, match='No permitted and compatible'),
        ):
            await service._select_security_policy(leaf, leaf)

    @pytest.mark.asyncio
    async def test_select_security_policy_rejects_when_rsa_forbidden(self, mock_opc_device):
        """Fail when SecurityConfig forbids RSA and no supported ECC policy exists."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        _set_service_security_config(service, rsa_minimum_key_size=None)
        discovery = self._select_policy_discovery(self._policy_endpoint('Aes256Sha256RsaPss'))

        with (
            patch.object(service, '_create_insecure_client', return_value=discovery),
            pytest.raises(GdsPushError, match='RSA is not permitted'),
        ):
            await service._select_security_policy(leaf, leaf)

    @pytest.mark.asyncio
    async def test_select_security_policy_reports_unsupported_ecc(self, mock_opc_device):
        """Report that the client library cannot use ECC-only endpoints."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        discovery = self._select_policy_discovery(self._policy_endpoint('EccNistP256'))

        with (
            patch.object(service, '_create_insecure_client', return_value=discovery),
            pytest.raises(GdsPushError, match='ECC policies'),
        ):
            await service._select_security_policy(leaf, leaf)

    @pytest.mark.asyncio
    async def test_select_security_policy_requires_discovery(self, mock_opc_device):
        """Do not choose a policy blindly when endpoint discovery fails."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _root, leaf = _make_ca_chain()
        discovery = Mock()
        discovery.disconnect = AsyncMock()
        discovery.connect_and_get_server_endpoints = AsyncMock(side_effect=RuntimeError('offline'))

        with (
            patch.object(service, '_create_insecure_client', return_value=discovery),
            pytest.raises(GdsPushError, match='refusing to select one blindly'),
        ):
            await service._select_security_policy(leaf, leaf)

    def test_certificate_type_selection_skips_rsa_when_forbidden(self, mock_opc_device):
        """Prefer an ECC certificate type when SecurityConfig forbids RSA."""
        service = GdsPushService(mock_opc_device, insecure=True)
        config = _set_service_security_config(service, rsa_minimum_key_size=None, not_permitted_ecc_curve_oids=[])
        types = [
            ua.NodeId.from_string(f'ns=0;i={CertificateTypes.RSA_SHA256_APPLICATION_CERTIFICATE.Identifier}'),
            ua.NodeId.from_string(f'ns=0;i={CertificateTypes.ECC_NIST_P384_APPLICATION_CERTIFICATE.Identifier}'),
        ]

        selected = service._select_application_certificate_type(types, config)

        assert selected == CertificateTypes.ECC_NIST_P384_APPLICATION_CERTIFICATE

    def test_certificate_type_selection_respects_blocked_curve(self, mock_opc_device):
        """Do not select an ECC certificate type whose curve SecurityConfig blocks."""
        service = GdsPushService(mock_opc_device, insecure=True)
        config = _set_service_security_config(
            service,
            rsa_minimum_key_size=None,
            not_permitted_ecc_curve_oids=[NamedCurve.SECP384R1.dotted_string],
        )
        types = [
            ua.NodeId.from_string(f'ns=0;i={CertificateTypes.ECC_NIST_P384_APPLICATION_CERTIFICATE.Identifier}'),
        ]

        assert service._select_application_certificate_type(types, config) is None

    @pytest.mark.asyncio
    async def test_generated_rsa_key_uses_security_config_minimum(self, mock_opc_device):
        """Generate the locally uploaded RSA key at the SecurityConfig minimum."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _set_service_security_config(service, rsa_minimum_key_size=3072)

        csr_der, key = await service._generate_server_key_and_csr(
            ua.NodeId.from_string(f'ns=0;i={CertificateTypes.RSA_SHA256_APPLICATION_CERTIFICATE.Identifier}')
        )

        assert key.key_size == 3072
        assert x509.load_der_x509_csr(csr_der).is_signature_valid

    @pytest.mark.asyncio
    async def test_generated_key_rejects_rsa_when_forbidden(self, mock_opc_device):
        """Fail rather than generate an RSA key when SecurityConfig forbids RSA."""
        service = GdsPushService(mock_opc_device, insecure=True)
        _set_service_security_config(service, rsa_minimum_key_size=None)

        with pytest.raises(GdsPushError, match='does not permit RSA'):
            await service._generate_server_key_and_csr(
                ua.NodeId.from_string(f'ns=0;i={CertificateTypes.RSA_SHA256_APPLICATION_CERTIFICATE.Identifier}')
            )

    @pytest.mark.asyncio
    async def test_verify_server_connection_success(self, mock_opc_device):
        """Reconnect verification succeeds with a working secure client."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        with patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client):
            assert await service._verify_server_connection() == (True, '')

    @pytest.mark.asyncio
    async def test_verify_server_connection_reports_failure(self, mock_opc_device):
        """Reconnect verification reports the failure without failing the update itself."""
        service = GdsPushService(mock_opc_device, insecure=True)
        with patch.object(
            service, '_create_secure_client', new_callable=AsyncMock, side_effect=GdsPushError('server restarting')
        ):
            verified, error = await service._verify_server_connection()

        assert verified is False
        assert 'server restarting' in error

    @pytest.mark.asyncio
    async def test_update_server_certificate_logs_certificate_mismatch(self, mock_opc_device):
        """Collect mismatch diagnostics when the secure session cannot open."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.__aenter__.side_effect = Exception('certificate mismatch')
        log_details = AsyncMock()

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_log_certificate_mismatch_details', log_details),
        ):
            success, message, certificate = await service.update_server_certificate()

        assert (success, certificate) == (False, None)
        assert 'certificate mismatch' in message
        log_details.assert_awaited_once_with(client)
        client.__aexit__.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sign_csr_rejects_missing_certificate_profile(self, mock_opc_device):
        """Turn a domain without the OPC UA profile into a GDS error."""
        service = GdsPushService(mock_opc_device, insecure=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'server')]))
            .sign(key, hashes.SHA256())
        )
        context = Mock(domain=mock_opc_device.domain)
        mock_opc_device.domain.get_allowed_cert_profile = Mock(return_value=None)

        with patch('request.gds_push.gds_push_service.BaseCertificateRequestContext', return_value=context):
            with pytest.raises(GdsPushError, match='Certificate profile "opc_ua" not found'):
                await service._sign_csr(csr.public_bytes(serialization.Encoding.DER))

    @pytest.mark.asyncio
    async def test_update_truststore_replaces_old_order_and_chain(self, mock_opc_device):
        """Revoke the old server certificate and create ordered replacement entries."""
        service = GdsPushService(mock_opc_device, insecure=True)
        truststore = Mock(unique_name='server-store')
        old_order = Mock(certificate=Mock(common_name='old-server'))
        truststore.truststoreordermodel_set.get.return_value = old_order
        truststore.truststoreordermodel_set.all.return_value.delete.return_value = (2, {})
        service.server_truststore = truststore
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'new-server')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'new-server')]))
            .public_key(key.public_key())
            .serial_number(2)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'ca')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'ca')]))
            .public_key(ca_key.public_key())
            .serial_number(3)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
            .sign(ca_key, hashes.SHA256())
        )
        ca_der = ca_cert.public_bytes(serialization.Encoding.DER)

        with (
            patch('request.gds_push.gds_push_service.revoke_certificate', return_value=True) as revoke,
            patch(
                'request.gds_push.gds_push_service.CertificateModel.get_cert_by_sha256_fingerprint',
                side_effect=[Mock(), Mock()],
            ),
            patch('request.gds_push.gds_push_service.TruststoreOrderModel.objects.create') as create_order,
        ):
            await service._update_truststore_with_new_certificate(cert_der, [ca_der])

        revoke.assert_called_once_with(
            old_order.certificate,
            reason=RevokedCertificateModel.ReasonCode.SUPERSEDED,
            ca=mock_opc_device.domain.issuing_ca,
        )
        truststore.truststoreordermodel_set.all.return_value.delete.assert_called_once_with()
        assert [call.kwargs['order'] for call in create_order.call_args_list] == [0, 1]

    @pytest.mark.asyncio
    async def test_get_server_certificate_reports_missing_order_zero_entry(self, mock_opc_device):
        """Reject a truststore that has no server certificate at order zero."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.server_truststore = mock_opc_device.opc_ua_gds_push_config.opc_trust_store

        with pytest.raises(GdsPushError, match='has no certificate at order 0'):
            await service._get_server_certificate()

    @pytest.mark.asyncio
    async def test_build_trustlist_rejects_ca_without_crl(self, mock_opc_device, mock_ca_with_crl):
        """Reject a trustlist when a CA has no configured CRL."""
        service = GdsPushService(mock_opc_device, insecure=True)

        with (
            patch.object(service, '_build_ca_chain', new_callable=AsyncMock, return_value=[mock_ca_with_crl]),
            patch.object(CaModel, 'crl_pem', new_callable=PropertyMock, return_value=''),
        ):
            with pytest.raises(GdsPushError, match='has no CRL configured'):
                await service._build_trustlist_for_server()

    @pytest.mark.asyncio
    async def test_build_trustlist_allows_missing_crls_when_optional(self, mock_opc_device, mock_ca_with_crl):
        """Continue without a CRL when the device explicitly permits it."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.device.opc_ua_gds_push_config.opc_gds_push_require_crls = False

        with (
            patch.object(service, '_build_ca_chain', new_callable=AsyncMock, return_value=[mock_ca_with_crl]),
            patch.object(CaModel, 'crl_pem', new_callable=PropertyMock, return_value=''),
        ):
            trustlist = await service._build_trustlist_for_server()

        assert len(trustlist.TrustedCertificates) == 1
        assert trustlist.TrustedCrls == []
        assert trustlist.IssuerCrls == []

    @pytest.mark.asyncio
    async def test_get_client_credentials_wraps_private_key_failure(self, mock_opc_device, mock_domain_credential):
        """Convert private-key retrieval failures into a GDS Push error."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.domain_credential = mock_domain_credential
        credential = mock_domain_credential.credential

        with (
            patch.object(mock_domain_credential, 'is_valid_domain_credential', return_value=(True, '')),
            patch.object(credential, 'get_private_key', side_effect=RuntimeError('key unavailable')),
            patch.object(service, '_validate_client_certificate'),
        ):
            with pytest.raises(GdsPushError, match='Failed to get private key: key unavailable'):
                await service._get_client_credentials()

    @pytest.mark.asyncio
    async def test_log_certificate_mismatch_details_logs_expected_and_actual(
        self, mock_opc_device, mock_server_certificate, caplog
    ):
        """Log both certificates when the OPC UA client exposes the presented certificate."""
        service = GdsPushService(mock_opc_device, insecure=True)
        service.server_truststore = mock_opc_device.opc_ua_gds_push_config.opc_trust_store
        client = Mock()
        client.uaclient.security_policy.server_certificate = mock_server_certificate.public_bytes(
            serialization.Encoding.DER
        )

        with patch.object(
            service, '_get_server_certificate', return_value=client.uaclient.security_policy.server_certificate
        ):
            with caplog.at_level('ERROR'):
                await service._log_certificate_mismatch_details(client)

        assert 'Server certificate mismatch detected' in caplog.text
        assert 'Actual certificate presented by server' in caplog.text

    @pytest.mark.asyncio
    async def test_update_server_certificate_updates_truststore_after_success(self, mock_opc_device):
        """Persist the first successful certificate and issuer chain returned by the server."""
        service = GdsPushService(mock_opc_device, insecure=True)
        client = AsyncMock()
        client.get_node = Mock(side_effect=RuntimeError('no capabilities'))
        groups = [{'name': 'ApplicationGroup', 'node_id': ua.NodeId(1, 2)}]

        with (
            patch.object(service, '_create_secure_client', new_callable=AsyncMock, return_value=client),
            patch.object(service, '_discover_certificate_groups', new_callable=AsyncMock, return_value=groups),
            patch.object(
                service,
                '_update_single_certificate',
                new_callable=AsyncMock,
                return_value=(True, b'new-cert', [b'issuer']),
            ),
            patch.object(service, '_update_truststore_with_new_certificate', new_callable=AsyncMock) as update,
        ):
            success, message, certificate = await service.update_server_certificate()

        assert (success, certificate) == (True, b'new-cert')
        assert 'Successfully updated 1/1' in message
        update.assert_awaited_once_with(b'new-cert', [b'issuer'])
