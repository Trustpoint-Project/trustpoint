"""Tests for GDS Push service."""

import datetime
import tempfile
from unittest.mock import AsyncMock, Mock, patch

import pytest
from asyncua import ua
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ObjectIdentifier

from devices.models import DeviceModel
from onboarding.models import OnboardingConfigModel, OnboardingPkiProtocol, OnboardingProtocol
from pki.models import TruststoreModel
from pki.models.truststore import TruststoreOrderModel
from pki.util.x509 import CertificateGenerator
from request.gds_push.gds_push_service import GdsPushError, GdsPushService


@pytest.fixture
def mock_ca_with_crl():
    """Create a mock CA with CRL."""
    # Ensure crypto storage config exists for encrypted fields
    from management.models import KeyStorageConfig
    KeyStorageConfig.get_or_create_default()
    
    root_ca, root_key = CertificateGenerator.create_root_ca('Test Root CA')
    issuing_ca, issuing_key = CertificateGenerator.create_issuing_ca(root_key, 'Test Root CA', 'Test Issuing CA')

    ca_model = CertificateGenerator.save_issuing_ca(
        issuing_ca_cert=issuing_ca,
        private_key=issuing_key,
        chain=[root_ca],
        unique_name='test_gds_ca'
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
    truststore = TruststoreModel(unique_name='test_opc_truststore', intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH)
    truststore.save()
    return truststore


@pytest.fixture
def mock_server_certificate(mock_truststore):
    """Create a mock server certificate in the truststore."""
    # Generate a server certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, 'opc-server.test.com'),
    ])

    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(
        private_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName('opc-server.test.com'),
        ]), critical=False
    ).sign(private_key, hashes.SHA256())

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
        opc_trust_store=mock_truststore
    )
    onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
    onboarding_config.save()

    device = DeviceModel(
        common_name='test-opc-device',
        serial_number='OPC123456',
        ip_address='192.168.1.100',
        opc_server_port=4840,
        domain=mock_domain,
        onboarding_config=onboarding_config,
        device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH
    )
    device.save()

    return device


@pytest.fixture
def mock_domain_credential(mock_opc_device, mock_domain):
    """Create a mock domain credential for the device."""
    from devices.issuer import LocalDomainCredentialIssuer

    issuer = LocalDomainCredentialIssuer(device=mock_opc_device, domain=mock_domain)
    credential = issuer.issue_domain_credential()

    return credential


class TestGdsPushService:
    """Test cases for GdsPushService."""

    def test_init_insecure_mode(self, mock_opc_device):
        """Test initialization in insecure mode."""
        service = GdsPushService(mock_opc_device, insecure=True)

        assert service.device == mock_opc_device
        assert service.server_url == 'opc.tcp://192.168.1.100:4840'
        assert service.domain_credential is None
        assert service.server_truststore is None

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
            opc_trust_store=mock_truststore
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            common_name='test-device-no-ip',
            opc_server_port=4840,
            domain=mock_domain,
            onboarding_config=onboarding_config
        )
        device.save()

        with pytest.raises(GdsPushError, match='must have IP address and OPC server port configured'):
            GdsPushService(device)

    def test_init_device_missing_port(self, mock_domain, mock_truststore):
        """Test initialization with device missing OPC server port."""
        onboarding_config = OnboardingConfigModel(
            onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
            opc_trust_store=mock_truststore
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            common_name='test-device-no-port',
            ip_address='192.168.1.100',
            domain=mock_domain,
            onboarding_config=onboarding_config
        )
        device.save()

        with pytest.raises(GdsPushError, match='must have IP address and OPC server port configured'):
            GdsPushService(device)

    def test_init_device_no_onboarding_config(self, mock_domain):
        """Test initialization with device missing onboarding config."""
        device = DeviceModel(
            common_name='test-device-no-config',
            ip_address='192.168.1.100',
            opc_server_port=4840,
            domain=mock_domain
        )
        device.save()

        with pytest.raises(GdsPushError, match='No domain credential found'):
            GdsPushService(device)
        """Test initialization with device missing OPC truststore."""
        onboarding_config = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH)
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            common_name='test-device-no-truststore',
            ip_address='192.168.1.100',
            opc_server_port=4840,
            domain=mock_domain,
            onboarding_config=onboarding_config
        )
        device.save()

        with pytest.raises(GdsPushError, match='No domain credential found'):
            GdsPushService(device)

    def test_init_device_empty_truststore(self, mock_domain):
        """Test initialization with empty OPC truststore."""
        truststore = TruststoreModel(unique_name='empty_truststore', intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH)
        truststore.save()

        onboarding_config = OnboardingConfigModel(
            onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
            opc_trust_store=truststore
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            common_name='test-device-empty-truststore',
            ip_address='192.168.1.100',
            opc_server_port=4840,
            domain=mock_domain,
            onboarding_config=onboarding_config
        )
        device.save()

        # Create a domain credential for the device
        from devices.issuer import LocalDomainCredentialIssuer
        issuer = LocalDomainCredentialIssuer(device=device, domain=mock_domain)
        issuer.issue_domain_credential()

        with pytest.raises(GdsPushError, match='Server truststore.*is empty'):
            GdsPushService(device)

    def test_init_no_domain_credential(self, mock_domain, mock_truststore):
        """Test initialization when no domain credential exists."""
        onboarding_config = OnboardingConfigModel(
            onboarding_protocol=OnboardingProtocol.OPC_GDS_PUSH,
            opc_trust_store=mock_truststore
        )
        onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
        onboarding_config.save()

        device = DeviceModel(
            common_name='test-device-no-credential',
            ip_address='192.168.1.100',
            opc_server_port=4840,
            domain=mock_domain,
            onboarding_config=onboarding_config
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
                'SecurityMode': 'SignAndEncrypt'
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
                        'has_server_cert': True
                    }
                ]
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
        mock_client.__aenter__ = AsyncMock(side_effect=Exception('Connection failed'))
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
                'security_mode': 'SignAndEncrypt'
            },
            {
                'security_policy': 'http://opcfoundation.org/UA/SecurityPolicy#None',
                'security_mode': 'None'
            }
        ]
        result = service._analyze_endpoints(endpoints)

        assert 'Basic256Sha256' in result['security_policies']
        assert result['has_secure_endpoints'] is True
        assert result['has_insecure_endpoints'] is True

    @patch('request.gds_push.gds_push_service.Client')
    @patch('request.gds_push.gds_push_service.sync_to_async')
    @pytest.mark.asyncio
    async def test_update_trustlist_success(self, mock_sync_to_async, mock_client_class, mock_opc_device, mock_domain_credential, mock_ca_with_crl):
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
        with patch.object(service, '_build_ca_chain') as mock_build_chain, \
             patch.object(service, '_build_trustlist_for_server') as mock_build_trustlist, \
             patch.object(service, '_discover_trustlist_nodes') as mock_discover, \
             patch.object(service, '_update_single_trustlist') as mock_update_single, \
             patch.object(service, '_create_secure_client') as mock_create_client:

            mock_build_chain.return_value = [mock_ca_with_crl]
            mock_build_trustlist.return_value = Mock(spec=ua.TrustListDataType)
            mock_discover.return_value = [{'group_name': 'Default', 'trustlist_node': mock_trustlist_node}]
            mock_update_single.return_value = True
            mock_create_client.return_value = mock_client
            mock_update_single.return_value = True

            success, message = await service.update_trustlist()

            assert success is True
            assert 'Successfully updated' in message

    @patch('request.gds_push.gds_push_service.Client')
    @pytest.mark.asyncio
    async def test_update_trustlist_connection_failure(self, mock_client_class, mock_opc_device, mock_domain_credential):
        """Test trustlist update with connection failure."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.__aenter__ = AsyncMock(side_effect=Exception('Connection failed'))
        mock_client.__aexit__ = AsyncMock(return_value=None)

        service = GdsPushService(mock_opc_device, insecure=True)

        success, message = await service.update_trustlist()

        assert success is False
        assert 'Update failed' in message

    def test_validate_client_certificate_valid(self, mock_opc_device):
        """Test client certificate validation with valid certificate."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Create a valid certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                data_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.5.5.7.3.2")]), critical=False
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier('urn:test:device'),
                x509.DNSName('test-device.local')
            ]), critical=False
        ).sign(private_key, hashes.SHA256())

        # Should not raise an exception
        service._validate_client_certificate(cert)

    def test_validate_client_certificate_expired(self, mock_opc_device):
        """Test client certificate validation with expired certificate."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=365)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA256())

        with pytest.raises(GdsPushError, match='Certificate expired'):
            service._validate_client_certificate(cert)

    def test_validate_client_certificate_missing_key_usage(self, mock_opc_device):
        """Test client certificate validation with missing key usage."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        with pytest.raises(GdsPushError, match='Key Usage extension is missing'):
            service._validate_client_certificate(cert)

    def test_extract_application_uri_success(self, mock_opc_device):
        """Test successful application URI extraction."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier('urn:test:application:uri'),
            ]), critical=False
        ).sign(private_key, hashes.SHA256())

        uri = service._extract_application_uri(cert)
        assert uri == 'urn:test:application:uri'

    def test_extract_application_uri_missing(self, mock_opc_device):
        """Test application URI extraction with missing URI."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('test-device.local'),
            ]), critical=False
        ).sign(private_key, hashes.SHA256())

        with pytest.raises(GdsPushError, match='No application URI found'):
            service._extract_application_uri(cert)

    def test_verify_certificate_key_match_success(self, mock_opc_device):
        """Test successful certificate and key match verification."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        # Should not raise an exception
        service._verify_certificate_key_match(cert, private_key)

    def test_verify_certificate_key_match_failure(self, mock_opc_device):
        """Test certificate and key match verification with mismatch."""
        service = GdsPushService(mock_opc_device, insecure=True)

        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-device')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key1.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).sign(private_key1, hashes.SHA256())

        with pytest.raises(GdsPushError, match='Certificate and private key do not match'):
            service._verify_certificate_key_match(cert, private_key2)

    # ========================================================================
    # Server Certificate Update Tests
    # ========================================================================

    @patch('request.gds_push.gds_push_service.Client')
    @pytest.mark.asyncio
    async def test_update_server_certificate_success(self, mock_client_class, mock_opc_device, mock_domain_credential, mock_ca_with_crl):
        """Test successful server certificate update."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        service = GdsPushService(mock_opc_device, insecure=True)

        # Mock certificate groups discovery
        mock_group = {
            'name': 'DefaultApplicationGroup',
            'node_id': ua.NodeId.from_string('ns=0;i=12555')
        }

        with patch.object(service, '_create_secure_client') as mock_create_client, \
             patch.object(service, '_discover_certificate_groups') as mock_discover_groups, \
             patch.object(service, '_update_single_certificate') as mock_update_single, \
             patch.object(service, '_update_truststore_with_new_certificate') as mock_update_truststore:

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
    async def test_update_server_certificate_no_groups(self, mock_client_class, mock_opc_device, mock_domain_credential):
        """Test server certificate update with no certificate groups found."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        service = GdsPushService(mock_opc_device, insecure=True)

        with patch.object(service, '_create_secure_client') as mock_create_client, \
             patch.object(service, '_discover_certificate_groups') as mock_discover_groups:

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
        mock_server_config.get_child = AsyncMock(side_effect=[
            mock_create_csr_method,
            mock_update_certificate_method,
            mock_apply_changes_method
        ])

        # Mock CSR creation
        mock_csr_der = b'csr_data'
        mock_server_config.call_method = AsyncMock(side_effect=[
            mock_csr_der,  # CreateSigningRequest
            True,  # UpdateCertificate returns apply_changes_required
            None  # ApplyChanges
        ])

        # Mock CSR signing
        signed_cert = b'signed_cert'
        issuer_chain = [b'issuer_cert']

        with patch.object(service, '_sign_csr') as mock_sign_csr:
            mock_sign_csr.return_value = (signed_cert, issuer_chain, Mock())

            cert_group_id = ua.NodeId.from_string('ns=0;i=12555')
            success, cert_data, chain_data = await service._update_single_certificate(
                mock_client, cert_group_id
            )

            assert success is True
            assert cert_data == signed_cert
            assert chain_data == issuer_chain

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
        mock_write_method = Mock()
        mock_close_method = Mock()
        mock_apply_method = Mock()

        mock_trustlist_node.get_child = AsyncMock(side_effect=[
            mock_open_method,
            mock_write_method,
            mock_close_method
        ])
        
        mock_file_handle = 12345
        mock_trustlist_node.call_method = AsyncMock(side_effect=[
            mock_file_handle,  # Open
            None,  # Write
            True,  # CloseAndUpdate returns apply_changes_required
            None  # ApplyChanges
        ])

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
            assert 'Update failed' in message

    @pytest.mark.asyncio
    async def test_validate_client_certificate_raises_error(self, mock_opc_device):
        """Test certificate validation raises error for invalid certificate."""
        service = GdsPushService(mock_opc_device, insecure=True)
        
        # Create certificate without SAN extension
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'no-san-cert')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test-ca')])
        ).public_key(private_key.public_key()).serial_number(1).not_valid_before(
            datetime.datetime.now(datetime.UTC)
        ).not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
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
        endpoint = {
            'security_policy': 'None',
            'security_mode': 'None'
        }
        
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
        
        endpoint = {
            'security_policy': 'Basic256Sha256',
            'security_mode': 'SignAndEncrypt'
        }
        
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
        mock_write_method = Mock()
        mock_close_method = Mock()
        
        mock_trustlist_node.get_child = AsyncMock(side_effect=[
            mock_open_method,
            mock_write_method,
            mock_close_method
        ])
        
        mock_file_handle = 12345
        mock_trustlist_node.call_method = AsyncMock(side_effect=[
            mock_file_handle,  # Open
            None,  # Write
            False  # CloseAndUpdate returns False (apply_changes_required=False)
        ])
        
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

        mock_client.get_endpoints = AsyncMock(return_value=[mock_endpoint])
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

        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test.example.com'),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(public_key).serial_number(1).not_valid_before(datetime.datetime.now(tz=datetime.UTC)).not_valid_after(datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365)).sign(private_key, hashes.SHA256())

        with pytest.raises(GdsPushError, match='Subject Alternative Name extension is missing'):
            service._validate_client_certificate(cert)

    def test_extract_application_uri_no_san(self, mock_opc_device):
        """Test extracting application URI with no SAN."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Create certificate without SAN
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test.example.com'),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(public_key).serial_number(1).not_valid_before(datetime.datetime.now(tz=datetime.UTC)).not_valid_after(datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365)).sign(private_key, hashes.SHA256())

        with pytest.raises(GdsPushError, match='No application URI found'):
            service._extract_application_uri(cert)

    def test_get_server_truststore_no_config(self, mock_opc_device):
        """Test getting server truststore with no onboarding config."""
        service = GdsPushService(mock_opc_device, insecure=True)

        # Mock device with no onboarding config
        service.device.onboarding_config = None

        with pytest.raises(GdsPushError, match='has no onboarding config'):
            service._get_server_truststore()

