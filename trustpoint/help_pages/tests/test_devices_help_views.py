# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Test cases for devices help views."""
import ipaddress
from cryptography import x509

from unittest.mock import Mock, patch

from django.http import Http404
from django.test import RequestFactory, TestCase
from trustpoint_core import oid

from devices.models import DeviceModel
from ..base import HelpContext
from ..devices_help_views import (
    AgentSetupProfileStrategy,
    ApplicationCertificateWithCmpDomainCredentialStrategy,
    ApplicationCertificateWithEstDomainCredentialStrategy,
    ApplicationCertificateWithRestDomainCredentialStrategy,
    AokiCmpIDevIDStrategy,
    AokiEstIDevIDStrategy,
    BaseHelpView,
    CmpRevocationStrategy,
    DeviceApplicationCertificateWithCmpDomainCredentialHelpView,
    DeviceApplicationCertificateWithEstDomainCredentialHelpView,
    DeviceNoOnboardingCmpSharedSecretHelpView,
    DeviceNoOnboardingEstUsernamePasswordHelpView,
    DeviceOnboardingDomainCredentialCmpSharedSecretHelpView,
    DeviceOnboardingDomainCredentialEstUsernamePasswordHelpView,
    NoOnboardingCmpSharedSecretStrategy,
    NoOnboardingEstUsernamePasswordStrategy,
    NoOnboardingRestUsernamePasswordStrategy,
    OnboardingDomainCredentialCmpSharedSecretStrategy,
    OnboardingDomainCredentialEstUsernamePasswordStrategy,
    OnboardingDomainCredentialRestUsernamePasswordStrategy,
    OpcUaGdsPushApplicationCertificateStrategy,
    OpcUaGdsPushApplicationCertificateHelpView,
    OpcUaGdsPushOnboardingHelpView,
    OpcUaGdsPushOnboardingStrategy,
    _agent_get_est_password,
)
from ..help_section import HelpSection, ValueRenderType


def _public_key_info() -> oid.PublicKeyInfo:
    """Return a reusable RSA public-key descriptor for help contexts."""
    return oid.PublicKeyInfo(
        public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.RSA,
        key_size=2048,
    )


def _sample_request() -> dict[str, object]:
    """Return a representative certificate profile sample request."""
    return {
        'subject': {'CN': 'Device 1'},
        'validity': {'days': 30},
        'extensions': {
            'subject_alternative_name': {
                'dns_names': ['device.example.test'],
            },
        },
    }


def _profile(unique_name: str = 'tls_server', display_name: str = 'TLS Server', alias: str | None = None) -> Mock:
    """Return a lightweight allowed certificate profile mock."""
    profile = Mock()
    profile.alias = alias
    profile.certificate_profile.unique_name = unique_name
    profile.certificate_profile.display_name = display_name
    profile.certificate_profile.profile = {'profile': unique_name}
    return profile


def _domain() -> Mock:
    """Return a lightweight domain mock."""
    domain = Mock()
    domain.unique_name = 'test-domain'
    domain.public_key_info = _public_key_info()
    domain.get_domain_credential_profile_name.return_value = 'domain_credential'
    return domain


def _device(domain: Mock, *, no_onboarding: bool = False, onboarding: bool = False) -> Mock:
    """Return a lightweight device mock with optional onboarding configs."""
    device = Mock()
    device.pk = 123
    device.common_name = 'device-1'
    device.domain = domain
    device.no_onboarding_config = None
    device.onboarding_config = None
    if no_onboarding:
        device.no_onboarding_config = Mock(cmp_shared_secret='cmp-secret', est_password='rest-secret')
    if onboarding:
        device.onboarding_config = Mock(cmp_shared_secret='cmp-secret', est_password='rest-secret')
    return device


def _help_context(
    device: Mock,
    domain: Mock | None,
    profiles: list[Mock] | None = None,
    *,
    cred_count: int = 2,
) -> HelpContext:
    """Return a realistic help context for strategy tests."""
    return HelpContext(
        device=device,
        domain=domain,
        domain_unique_name='test-domain',
        allowed_app_profiles=profiles or [],
        public_key_info=_public_key_info(),
        host_base='https://trustpoint.test:8443',
        host_cmp_path='https://trustpoint.test:8443/.well-known/cmp/p/test-domain',
        host_est_path='https://trustpoint.test:8443/.well-known/est/test-domain',
        cred_count=cred_count,
    )


def _section(heading: str = 'Patched Section') -> HelpSection:
    """Return a simple replacement for helper sections that hit unrelated database state."""
    return HelpSection(heading, [])


class BaseHelpViewTests(TestCase):
    """Test cases for BaseHelpView in devices app."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BaseHelpView()

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    def test_make_context_success(
        self, mock_filter: Mock
    ) -> None:
        """Test _make_context creates HelpContext successfully."""
        mock_queryset = Mock()
        mock_queryset.count.return_value = 2
        mock_filter.return_value = mock_queryset

        mock_domain = Mock()
        mock_domain.unique_name = 'test-domain'
        mock_domain.public_key_info = Mock()
        mock_domain.get_allowed_cert_profiles.return_value.exclude.return_value = []

        mock_device = Mock()
        mock_device.domain = mock_domain

        self.view.object = mock_device
        request = self.factory.get('/')
        self.view.request = request

        with patch('help_pages.devices_help_views.settings') as mock_settings:
            mock_settings.TP_HTTPS_PORT = '8443'
            context = self.view._make_context('192.168.1.1')

        assert context.domain == mock_domain
        assert context.domain_unique_name == 'test-domain'
        assert context.device == mock_device
        assert context.cred_count == 2
        assert context.host_base == 'https://192.168.1.1:8443'
        assert context.host_cmp_path == 'https://192.168.1.1:8443/.well-known/cmp/p/test-domain'
        assert context.host_est_path == 'https://192.168.1.1:8443/.well-known/est/test-domain'

    def test_make_context_no_domain(self) -> None:
        """Test _make_context raises Http404 when domain is missing."""
        mock_device = Mock()
        mock_device.domain = None

        self.view.object = mock_device
        self.view.request = self.factory.get('/')

        with self.assertRaises(Http404) as cm:
            self.view._make_context()

        assert 'No domain is configured for this device' in str(cm.exception)

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    def test_make_context_no_public_key_info(self, mock_filter: Mock) -> None:
        """Test _make_context raises Http404 when public_key_info is missing."""
        mock_filter.return_value.count.return_value = 0

        mock_domain = Mock()
        mock_domain.unique_name = 'test-domain'
        mock_domain.public_key_info = None

        mock_device = Mock()
        mock_device.domain = mock_domain

        self.view.object = mock_device
        self.view.request = self.factory.get('/')

        with self.assertRaises(Http404):
            self.view._make_context()

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.get'
    )
    def test_get_context_data_success(
        self, mock_get: Mock, mock_filter: Mock
    ) -> None:
        """Test get_context_data builds help page successfully."""
        mock_filter.return_value.count.return_value = 1

        mock_domain = Mock()
        mock_domain.unique_name = 'test-domain'
        mock_domain.public_key_info = Mock()
        mock_domain.get_allowed_cert_profiles.return_value.exclude.return_value = []

        mock_device = Mock()
        mock_device.domain = mock_domain

        mock_strategy = Mock()
        mock_strategy.build_sections.return_value = ([], 'Test Heading')

        mock_ip = Mock(spec=x509.IPAddress)
        mock_ip.value = ipaddress.IPv4Address("192.168.1.1")
        mock_san = Mock()
        mock_san.value = [mock_ip]
        mock_cert = Mock()
        mock_cert.extensions.get_extension_for_class.return_value = mock_san
        mock_credential = Mock()
        mock_credential.get_certificate_serializer.return_value.as_crypto.return_value = mock_cert
        mock_active_tls = Mock()
        mock_active_tls.credential = mock_credential
        mock_get.return_value = mock_active_tls

        self.view.object = mock_device
        self.view.strategy = mock_strategy
        self.view.page_category = 'devices'
        self.view.page_name = 'devices'
        request = self.factory.get('/')
        self.view.request = request

        with patch('help_pages.devices_help_views.settings') as mock_settings:
            mock_settings.TP_HTTPS_PORT = '443'
            context = self.view.get_context_data()

        assert 'help_page' in context
        assert context['help_page'].heading == 'Test Heading'
        assert context['ValueRenderType_CODE'] == ValueRenderType.CODE.value
        assert context['clm_url'] == 'devices:devices_certificate_lifecycle_management'

    def test_get_context_data_no_strategy(self) -> None:
        """Test get_context_data raises RuntimeError when strategy is not configured."""
        self.view.object = Mock()
        self.view.strategy = None

        with self.assertRaises(RuntimeError) as cm:
            self.view.get_context_data()

        assert 'No strategy configured' in str(cm.exception)


class NoOnboardingCmpSharedSecretStrategyTests(TestCase):
    """Test cases for NoOnboardingCmpSharedSecretStrategy."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.strategy = NoOnboardingCmpSharedSecretStrategy()

    @patch('help_pages.devices_help_views.build_profile_select_section')
    @patch('help_pages.devices_help_views.build_keygen_section')
    @patch('help_pages.devices_help_views.build_cmp_signer_trust_store_section')
    def test_build_sections_first_credential(
        self,
        mock_cmp_signer: Mock,
        mock_keygen: Mock,
        mock_profile: Mock,
    ) -> None:
        """Test build_sections for first credential."""
        mock_cmp_signer.return_value = Mock()
        mock_keygen.return_value = Mock()
        mock_profile.return_value = Mock()

        mock_device = Mock()
        mock_device.pk = 123
        mock_no_onboarding = Mock()
        mock_no_onboarding.cmp_shared_secret = 'test-secret'
        mock_device.no_onboarding_config = mock_no_onboarding

        mock_domain = Mock()
        mock_domain.public_key_info = 'RSA 2048'

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device
        help_context.host_cmp_path = 'https://localhost/cmp/test'
        help_context.domain = mock_domain
        help_context.cred_count = 0
        help_context.allowed_app_profiles = []  # Mock as empty list

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) >= 3  # summary, keygen, profile_select at minimum
        assert sections[0].heading == 'Summary'
        assert any('Shared-Secret' in row.key for row in sections[0].rows)
        mock_keygen.assert_called_once()
        mock_profile.assert_called_once()

    def test_build_sections_no_onboarding_config(self) -> None:
        """Test build_sections raises Http404 when no_onboarding_config is missing."""
        mock_device = Mock()
        mock_device.no_onboarding_config = None

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device

        with self.assertRaises(Http404) as cm:
            self.strategy.build_sections(help_context)

        assert 'Onboarding is configured for this device' in str(cm.exception)


class DeviceNoOnboardingCmpSharedSecretHelpViewTests(TestCase):
    """Test cases for DeviceNoOnboardingCmpSharedSecretHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = DeviceNoOnboardingCmpSharedSecretHelpView()
        assert isinstance(view.strategy, NoOnboardingCmpSharedSecretStrategy)


class NoOnboardingEstUsernamePasswordStrategyTests(TestCase):
    """Test cases for NoOnboardingEstUsernamePasswordStrategy."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.strategy = NoOnboardingEstUsernamePasswordStrategy()

    @patch('help_pages.devices_help_views.build_profile_select_section')
    @patch('help_pages.devices_help_views.build_keygen_section')
    @patch('help_pages.devices_help_views.build_tls_trust_store_section')
    def test_build_sections(
        self,
        mock_tls: Mock,
        mock_keygen: Mock,
        mock_profile: Mock,
    ) -> None:
        """Test build_sections creates all required sections."""
        mock_tls.return_value = Mock()
        mock_keygen.return_value = Mock()
        mock_profile.return_value = Mock()

        mock_device = Mock()
        mock_device.pk = 123
        mock_device.common_name = 'test-device'
        mock_no_onboarding = Mock()
        mock_no_onboarding.est_username = 'testuser'
        mock_no_onboarding.est_password = 'testpass'
        mock_device.no_onboarding_config = mock_no_onboarding

        mock_domain = Mock()
        mock_domain.public_key_info = 'RSA 2048'

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device
        help_context.host_est_path = 'https://localhost/est/test'
        help_context.domain = mock_domain
        help_context.cred_count = 0
        help_context.allowed_app_profiles = []  # Mock as empty list

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) >= 3
        assert sections[0].heading == 'Summary'
        mock_tls.assert_called_once()
        mock_keygen.assert_called_once()
        mock_profile.assert_called_once()


class DeviceNoOnboardingEstUsernamePasswordHelpViewTests(TestCase):
    """Test cases for DeviceNoOnboardingEstUsernamePasswordHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = DeviceNoOnboardingEstUsernamePasswordHelpView()
        assert isinstance(view.strategy, NoOnboardingEstUsernamePasswordStrategy)


class OnboardingDomainCredentialCmpSharedSecretStrategyTests(TestCase):
    """Test cases for OnboardingDomainCredentialCmpSharedSecretStrategy."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.strategy = OnboardingDomainCredentialCmpSharedSecretStrategy()

    @patch('help_pages.devices_help_views.build_keygen_section')
    def test_build_sections(
        self,
        mock_keygen: Mock,
    ) -> None:
        """Test build_sections creates all required sections."""
        mock_keygen.return_value = Mock()

        mock_device = Mock()
        mock_device.pk = 123
        mock_onboarding = Mock()
        mock_onboarding.cmp_shared_secret = 'test-secret'
        mock_device.onboarding_config = mock_onboarding

        mock_domain = Mock()
        mock_domain.public_key_info = 'RSA 2048'

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device
        help_context.host_cmp_path = 'https://localhost/cmp/test'
        help_context.domain = mock_domain
        help_context.cred_count = 0

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) == 3  # summary, keygen, certificate request
        assert sections[0].heading == 'Summary'
        assert sections[2].heading == 'Certificate Request for TLS Client Certificates'
        assert any('Shared-Secret' in row.key for row in sections[0].rows)
        mock_keygen.assert_called_once_with(help_context, file_name='domain-credential-key.pem')

    def test_build_sections_no_onboarding_config(self) -> None:
        """Test build_sections raises Http404 when onboarding_config is missing."""
        mock_device = Mock()
        mock_device.onboarding_config = None

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device

        with self.assertRaises(Http404) as cm:
            self.strategy.build_sections(help_context)

        assert 'Onboarding is not configured for this device' in str(cm.exception)


class DeviceOnboardingDomainCredentialCmpSharedSecretHelpViewTests(TestCase):
    """Test cases for DeviceOnboardingDomainCredentialCmpSharedSecretHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = DeviceOnboardingDomainCredentialCmpSharedSecretHelpView()
        assert isinstance(view.strategy, OnboardingDomainCredentialCmpSharedSecretStrategy)


class OnboardingDomainCredentialEstUsernamePasswordStrategyTests(TestCase):
    """Test cases for OnboardingDomainCredentialEstUsernamePasswordStrategy."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.strategy = OnboardingDomainCredentialEstUsernamePasswordStrategy()

    @patch('help_pages.devices_help_views.build_profile_select_section')
    @patch('help_pages.devices_help_views.build_keygen_section')
    @patch('help_pages.devices_help_views.build_tls_trust_store_section')
    def test_build_sections(
        self,
        mock_tls: Mock,
        mock_keygen: Mock,
        mock_profile: Mock,
    ) -> None:
        """Test build_sections creates all required sections."""
        mock_tls.return_value = Mock()
        mock_keygen.return_value = Mock()
        mock_profile.return_value = Mock()

        mock_device = Mock()
        mock_device.pk = 123
        mock_onboarding = Mock()
        mock_onboarding.est_username = 'testuser'
        mock_onboarding.est_password = 'testpass'
        mock_device.onboarding_config = mock_onboarding

        mock_domain = Mock()
        mock_domain.public_key_info = 'RSA 2048'

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device
        help_context.host_est_path = 'https://localhost/est/test'
        help_context.domain = mock_domain
        help_context.cred_count = 0

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) >= 3
        assert sections[0].heading == 'Summary'
        mock_tls.assert_called_once()
        mock_keygen.assert_called_once()


class DeviceOnboardingDomainCredentialEstUsernamePasswordHelpViewTests(TestCase):
    """Test cases for DeviceOnboardingDomainCredentialEstUsernamePasswordHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = DeviceOnboardingDomainCredentialEstUsernamePasswordHelpView()
        assert isinstance(view.strategy, OnboardingDomainCredentialEstUsernamePasswordStrategy)


class DeviceApplicationCertificateWithCmpDomainCredentialHelpViewTests(TestCase):
    """Test cases for DeviceApplicationCertificateWithCmpDomainCredentialHelpView."""

    def test_view_attributes(self) -> None:
        """Test view has correct attributes."""
        view = DeviceApplicationCertificateWithCmpDomainCredentialHelpView()
        assert view.model == DeviceModel
        assert view.template_name == 'help/help_page.html'
        assert view.page_category == 'devices'


class DeviceApplicationCertificateWithEstDomainCredentialHelpViewTests(TestCase):
    """Test cases for DeviceApplicationCertificateWithEstDomainCredentialHelpView."""

    def test_view_attributes(self) -> None:
        """Test view has correct attributes."""
        view = DeviceApplicationCertificateWithEstDomainCredentialHelpView()
        assert view.model == DeviceModel
        assert view.template_name == 'help/help_page.html'
        assert view.page_category == 'devices'


class OpcUaGdsPushOnboardingStrategyTests(TestCase):
    """Test cases for OpcUaGdsPushOnboardingStrategy."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.strategy = OpcUaGdsPushOnboardingStrategy()

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.reverse')
    def test_build_sections_with_domain_credential(
        self, mock_reverse: Mock, mock_filter: Mock
    ) -> None:
        """Test build_sections when device has domain credential."""
        mock_filter.return_value.exists.return_value = True

        mock_reverse.side_effect = lambda name, kwargs: f'/{name}/{kwargs["pk"]}/'

        mock_device = Mock()
        mock_device.pk = 123
        mock_device.domain = Mock()
        mock_device.domain.issuing_ca = None  # No CA configured
        mock_onboarding = Mock()
        mock_device.onboarding_config = mock_onboarding

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device
        help_context.domain_unique_name = 'test-domain'
        help_context.domain.public_key_info = 'RSA 2048'

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) == 4  # summary, ca_hierarchy, download, actions
        assert sections[0].heading == 'Summary'
        assert sections[1].heading == 'CA Certificates'  # No CA configured
        assert sections[2].heading == 'Download Trust Bundle'
        assert sections[3].heading == 'Available Actions'
        assert 'OPC UA GDS Push' in sections[0].rows[0].value
        assert heading == 'Help - OPC UA GDS Push Certificate Management'

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.reverse')
    def test_build_sections_without_domain_credential(
        self, mock_reverse: Mock, mock_filter: Mock
    ) -> None:
        """Test build_sections when device does not have domain credential."""
        mock_filter.return_value.exists.return_value = False

        mock_reverse.side_effect = lambda name, kwargs: f'/{name}/{kwargs["pk"]}/'

        mock_device = Mock()
        mock_device.pk = 123
        mock_device.domain = Mock()
        mock_device.domain.issuing_ca = None
        mock_onboarding = Mock()
        mock_device.onboarding_config = mock_onboarding

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device
        help_context.domain_unique_name = 'test-domain'
        help_context.domain.public_key_info = 'RSA 2048'

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) == 4
        assert sections[3].heading == 'Available Actions'
        # Should have domain credential required message
        assert 'Domain Credential Required' in sections[3].rows[1].key

    def test_build_sections_no_onboarding_config(self) -> None:
        """Test build_sections raises Http404 when onboarding_config is missing."""
        mock_device = Mock()
        mock_device.onboarding_config = None

        help_context = Mock()
        help_context.get_device_or_http_404.return_value = mock_device

        with self.assertRaises(Http404) as cm:
            self.strategy.build_sections(help_context)

        assert 'Onboarding is not configured for this device' in str(cm.exception)

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.reverse')
    @patch('help_pages.devices_help_views.x509')
    def test_build_ca_hierarchy_section_with_ca_and_crl(
        self, mock_x509: Mock, mock_reverse: Mock, mock_filter: Mock
    ) -> None:
        """Test _build_ca_hierarchy_section with CA and valid CRL."""
        mock_filter.return_value.exists.return_value = True

        # Mock CA chain
        mock_ca = Mock()
        mock_ca.unique_name = 'test-ca'
        mock_ca.crl_pem = 'valid-crl-pem'
        mock_ca.pk = 456

        mock_cert_model = Mock()
        mock_cert_serializer = Mock()
        mock_cert_crypto = Mock()
        mock_common_name = Mock()
        mock_common_name.value = b'Test CA'
        mock_cert_crypto.subject.get_attributes_for_oid.return_value = [mock_common_name]

        mock_cert_serializer.as_crypto.return_value = mock_cert_crypto
        mock_cert_model.get_certificate_serializer.return_value = mock_cert_serializer
        mock_ca.ca_certificate_model = mock_cert_model

        mock_active_crl = Mock()
        mock_active_crl.pk = 789
        mock_ca.get_active_crl.return_value = mock_active_crl

        mock_reverse.side_effect = lambda name, kwargs: f'/{name}/{kwargs["pk"]}/'

        mock_device = Mock()
        mock_device.domain = Mock()
        mock_device.domain.issuing_ca = Mock()
        mock_device.domain.issuing_ca.get_ca_chain_from_truststore.return_value = [mock_ca]

        mock_x509.load_pem_x509_crl.return_value = Mock()  # Valid CRL

        section = self.strategy._build_ca_hierarchy_section(mock_device)

        assert section.heading == 'CA Hierarchy'
        assert len(section.rows) == 1  # Only certificate chain row
        assert 'Certificate Chain' in section.rows[0].key
        assert 'Test CA' in section.rows[0].value
        assert 'CRL' in section.rows[0].value  # CRL link is present
        assert 'OK' in section.rows[0].value

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.reverse')
    @patch('help_pages.devices_help_views.x509')
    def test_build_ca_hierarchy_section_missing_crl(
        self, mock_x509: Mock, mock_reverse: Mock, mock_filter: Mock
    ) -> None:
        """Test _build_ca_hierarchy_section with missing CRL."""
        mock_filter.return_value.exists.return_value = True

        mock_ca = Mock()
        mock_ca.unique_name = 'test-ca'
        mock_ca.crl_pem = None  # Missing CRL
        mock_ca.pk = 456

        mock_cert_model = Mock()
        mock_cert_serializer = Mock()
        mock_cert_crypto = Mock()
        mock_common_name = Mock()
        mock_common_name.value = b'Test CA'
        mock_cert_crypto.subject.get_attributes_for_oid.return_value = [mock_common_name]

        mock_cert_serializer.as_crypto.return_value = mock_cert_crypto
        mock_cert_model.get_certificate_serializer.return_value = mock_cert_serializer
        mock_ca.ca_certificate_model = mock_cert_model

        mock_reverse.side_effect = lambda name, kwargs: f'/{name}/{kwargs["pk"]}/'

        mock_device = Mock()
        mock_device.domain = Mock()
        mock_device.domain.issuing_ca = Mock()
        mock_device.domain.issuing_ca.get_ca_chain_from_truststore.return_value = [mock_ca]

        section = self.strategy._build_ca_hierarchy_section(mock_device)

        assert section.heading == 'CA Hierarchy'
        assert len(section.rows) == 2  # Certificate chain + warning
        assert 'Warning' in section.rows[1].key
        assert 'CRL Missing' in section.rows[1].value

    def test_build_ca_hierarchy_section_no_ca(self) -> None:
        """Test _build_ca_hierarchy_section when no CA is configured."""
        mock_device = Mock()
        mock_device.domain = None

        section = self.strategy._build_ca_hierarchy_section(mock_device)

        assert section.heading == 'CA Certificates'
        assert 'No CA Configured' in section.rows[0].key

    @patch('help_pages.devices_help_views.reverse')
    def test_build_download_section_with_ca(self, mock_reverse: Mock) -> None:
        """Test _build_download_section when CA is configured."""
        mock_reverse.return_value = '/download/123/'

        mock_device = Mock()
        mock_device.domain = Mock()
        mock_device.domain.issuing_ca = Mock()
        mock_device.domain.issuing_ca.pk = 123

        section = self.strategy._build_download_section(mock_device)

        assert section.heading == 'Download Trust Bundle'
        assert 'Trust Bundle Download' in section.rows[0].key
        assert 'btn btn-primary' in section.rows[0].value

    def test_build_download_section_no_ca(self) -> None:
        """Test _build_download_section when no CA is configured."""
        mock_device = Mock()
        mock_device.domain = None

        section = self.strategy._build_download_section(mock_device)

        assert section.heading == 'Download Trust Bundle'
        assert 'No issuing CA configured' in section.rows[0].value


class OpcUaGdsPushApplicationCertificateHelpViewTests(TestCase):
    """Test cases for OpcUaGdsPushApplicationCertificateHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = OpcUaGdsPushApplicationCertificateHelpView()
        assert isinstance(view.strategy, OpcUaGdsPushOnboardingStrategy)
        assert view.page_name == 'devices'


class OpcUaGdsPushOnboardingHelpViewTests(TestCase):
    """Test cases for OpcUaGdsPushOnboardingHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = OpcUaGdsPushOnboardingHelpView()
        assert isinstance(view.strategy, OpcUaGdsPushOnboardingStrategy)
        assert view.page_name == 'devices'


class DeviceStrategyGeneratedContentTests(TestCase):
    """Test generated help content for device strategies without masking the strategy code."""

    @patch('help_pages.devices_help_views.JSONProfileVerifier')
    def test_no_onboarding_cmp_shared_secret_builds_profile_commands(self, mock_verifier: Mock) -> None:
        """Test CMP shared-secret sections include profile-specific commands and hidden state."""
        mock_verifier.return_value.get_sample_request.return_value = _sample_request()
        domain = _domain()
        device = _device(domain, no_onboarding=True)
        profiles = [_profile(alias='server_alias'), _profile('client_auth', 'Client Auth')]

        sections, heading = NoOnboardingCmpSharedSecretStrategy().build_sections(_help_context(device, domain, profiles))

        assert 'CMP with a shared-secret' in heading
        assert sections[0].rows[3].value == 'cmp-secret'
        assert sections[3].css_id == 'server_alias'
        assert sections[3].hidden is False
        assert sections[4].css_id == 'client_auth'
        assert sections[4].hidden is True
        assert 'server_alias/certification' in sections[3].rows[0].value
        assert '-secret pass:cmp-secret' in sections[3].rows[0].value

    @patch('help_pages.devices_help_views.JSONProfileVerifier', side_effect=ValueError('invalid profile'))
    def test_no_onboarding_cmp_shared_secret_reports_malformed_profile(self, mock_verifier: Mock) -> None:
        """Test malformed CMP profiles produce a visible error row instead of a command."""
        domain = _domain()
        device = _device(domain, no_onboarding=True)

        sections, _heading = NoOnboardingCmpSharedSecretStrategy().build_sections(
            _help_context(device, domain, [_profile()])
        )

        assert sections[3].rows[0].value_render_type == ValueRenderType.PLAIN
        assert 'Certificate Profile is malformed' in sections[3].rows[0].value
        mock_verifier.assert_called_once()

    @patch('help_pages.devices_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.devices_help_views.JSONProfileVerifier')
    def test_no_onboarding_est_username_password_builds_linux_and_windows_steps(
        self, mock_verifier: Mock, mock_tls: Mock
    ) -> None:
        """Test EST username/password help includes enrollment and platform conversion commands."""
        mock_verifier.return_value.get_sample_request.return_value = _sample_request()
        domain = _domain()
        device = _device(domain, no_onboarding=True)

        sections, heading = NoOnboardingEstUsernamePasswordStrategy().build_sections(
            _help_context(device, domain, [_profile(alias='server_alias')], cred_count=4)
        )

        assert 'EST with username and password' in heading
        assert mock_tls.called
        profile_section = sections[4]
        assert profile_section.css_id == 'server_alias'
        assert [row.key for row in profile_section.rows] == [
            'Generate CSR with OpenSSL',
            'Enroll certificate with curl',
            'Convert certificate to PEM (Linux/OpenSSL)',
            'Convert certificate to PEM (Windows, certutil & OpenSSL)',
            'Install certificate into Windows store (certutil)',
        ]
        assert '--user "device-1:rest-secret"' in profile_section.rows[1].value
        assert 'certificate-4.p7c' in profile_section.rows[1].value
        assert sections[-1].css_class == 'platform-linux'

    @patch('help_pages.devices_help_views.build_cmp_signer_trust_store_section', return_value=_section('CMP Signer'))
    @patch('help_pages.devices_help_views.JSONProfileVerifier')
    def test_application_cmp_domain_credential_builds_commands(self, mock_verifier: Mock, mock_cmp: Mock) -> None:
        """Test application CMP help builds mTLS profile commands."""
        mock_verifier.return_value.get_sample_request.return_value = _sample_request()
        domain = _domain()
        device = _device(domain, onboarding=True)

        sections, heading = ApplicationCertificateWithCmpDomainCredentialStrategy().build_sections(
            _help_context(device, domain, [_profile()], cred_count=5)
        )

        assert 'CMP with a Domain Credential' in heading
        assert mock_cmp.called
        assert sections[4].heading == 'Certificate Request for a TLS Server Certificate'
        assert '-cert domain-credential-certificate.pem' in sections[4].rows[0].value
        assert '-newkey key-5.pem' in sections[4].rows[0].value

    @patch('help_pages.devices_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.devices_help_views.JSONProfileVerifier')
    def test_application_est_domain_credential_builds_enroll_and_convert_steps(
        self, mock_verifier: Mock, mock_tls: Mock
    ) -> None:
        """Test application EST help builds CSR, mTLS curl, and conversion steps."""
        mock_verifier.return_value.get_sample_request.return_value = _sample_request()
        domain = _domain()
        device = _device(domain, onboarding=True)

        sections, heading = ApplicationCertificateWithEstDomainCredentialStrategy().build_sections(
            _help_context(device, domain, [_profile(alias='server_alias')], cred_count=6)
        )

        assert 'EST with a Domain Credential' in heading
        assert mock_tls.called
        assert sections[4].css_id == 'server_alias'
        assert 'csr-6.der' in sections[4].rows[0].value
        assert '--cert domain-credential-certificate.pem' in sections[4].rows[1].value
        assert 'server_alias/simpleenroll' in sections[4].rows[1].value
        assert 'certificate-6.pem' in sections[-1].rows[0].value

    @patch('help_pages.devices_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.devices_help_views.JSONProfileVerifier')
    def test_no_onboarding_rest_username_password_builds_json_enrollment(
        self, mock_verifier: Mock, mock_tls: Mock
    ) -> None:
        """Test REST username/password app-certificate help commands."""
        mock_verifier.return_value.get_sample_request.return_value = _sample_request()
        domain = _domain()
        device = _device(domain, no_onboarding=True)

        sections, heading = NoOnboardingRestUsernamePasswordStrategy().build_sections(
            _help_context(device, domain, [_profile()], cred_count=7)
        )

        assert 'REST with username and password' in heading
        assert mock_tls.called
        assert '/rest/test-domain/<certificate_profile>/enroll/' in sections[0].rows[0].value
        assert '--user "device-1:rest-secret"' in sections[4].rows[1].value
        assert 'certificate-7.json' in sections[4].rows[1].value
        assert 'certificate-7.pem' in sections[4].rows[2].value

    @patch('help_pages.devices_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    def test_onboarding_rest_username_password_builds_domain_credential_steps(self, mock_tls: Mock) -> None:
        """Test REST username/password domain credential help commands."""
        domain = _domain()
        device = _device(domain, onboarding=True)

        sections, heading = OnboardingDomainCredentialRestUsernamePasswordStrategy().build_sections(
            _help_context(device, domain)
        )

        assert 'Domain Credential using REST' in heading
        assert mock_tls.called
        assert '/rest/test-domain/domain_credential/enroll/' in sections[0].rows[0].value
        assert 'csr-domain-credential.pem' in sections[3].rows[0].value
        assert '--user "device-1:rest-secret"' in sections[3].rows[1].value
        assert 'domain-credential-certificate.pem' in sections[3].rows[2].value

    @patch('help_pages.devices_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.devices_help_views.JSONProfileVerifier')
    def test_application_rest_domain_credential_builds_enroll_reenroll_and_extract_steps(
        self, mock_verifier: Mock, mock_tls: Mock
    ) -> None:
        """Test REST mTLS app-certificate help commands."""
        mock_verifier.return_value.get_sample_request.return_value = _sample_request()
        domain = _domain()
        device = _device(domain, onboarding=True)

        sections, heading = ApplicationCertificateWithRestDomainCredentialStrategy().build_sections(
            _help_context(device, domain, [_profile(alias='server_alias')], cred_count=8)
        )

        assert 'REST with a Domain Credential' in heading
        assert mock_tls.called
        profile_section = sections[4]
        assert 'server_alias/enroll/' in profile_section.rows[1].value
        assert 'server_alias/reenroll/' in profile_section.rows[2].value
        assert 'previously issued certificate' in profile_section.rows[3].value
        assert 'certificate-8.pem' in profile_section.rows[4].value
        assert 'certificate-chain-8.pem' in profile_section.rows[5].value

    @patch('help_pages.devices_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.devices_help_views.JSONProfileVerifier', side_effect=ValueError('invalid profile'))
    def test_rest_malformed_profile_paths_report_plain_errors(self, mock_verifier: Mock, mock_tls: Mock) -> None:
        """Test REST strategies report malformed certificate profiles."""
        domain = _domain()
        no_onboarding_device = _device(domain, no_onboarding=True)
        onboarding_device = _device(domain, onboarding=True)

        no_onboarding_sections, _heading = NoOnboardingRestUsernamePasswordStrategy().build_sections(
            _help_context(no_onboarding_device, domain, [_profile()])
        )
        app_sections, _heading = ApplicationCertificateWithRestDomainCredentialStrategy().build_sections(
            _help_context(onboarding_device, domain, [_profile()])
        )

        assert no_onboarding_sections[4].rows[0].value_render_type == ValueRenderType.PLAIN
        assert 'Certificate Profile is malformed' in no_onboarding_sections[4].rows[0].value
        assert app_sections[4].rows[0].value_render_type == ValueRenderType.PLAIN
        assert 'Certificate Profile is malformed' in app_sections[4].rows[0].value
        assert mock_verifier.call_count == 2
        assert mock_tls.call_count == 2

    def test_strategies_raise_when_required_domain_or_config_is_missing(self) -> None:
        """Test important Http404 branches for missing domain and onboarding state."""
        domain = _domain()
        missing_domain_device = _device(domain, no_onboarding=True)
        missing_config_device = _device(domain)

        with self.assertRaises(Http404):
            NoOnboardingCmpSharedSecretStrategy().build_sections(_help_context(missing_domain_device, None))
        with self.assertRaises(Http404):
            NoOnboardingEstUsernamePasswordStrategy().build_sections(_help_context(missing_domain_device, None))
        with self.assertRaises(Http404):
            ApplicationCertificateWithCmpDomainCredentialStrategy().build_sections(
                _help_context(missing_config_device, domain)
            )
        with self.assertRaises(Http404):
            ApplicationCertificateWithEstDomainCredentialStrategy().build_sections(
                _help_context(missing_config_device, domain)
            )
        with self.assertRaises(Http404):
            NoOnboardingRestUsernamePasswordStrategy().build_sections(_help_context(missing_config_device, domain))
        with self.assertRaises(Http404):
            OnboardingDomainCredentialRestUsernamePasswordStrategy().build_sections(
                _help_context(missing_config_device, domain)
            )
        with self.assertRaises(Http404):
            ApplicationCertificateWithRestDomainCredentialStrategy().build_sections(
                _help_context(missing_config_device, domain)
            )

    @patch('help_pages.devices_help_views.CmpSharedSecretCommandBuilder.get_app_cert_self_revoke_command')
    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.reverse')
    def test_cmp_revocation_lists_credentials_and_reason_commands(
        self, mock_reverse: Mock, mock_filter: Mock, mock_revoke_command: Mock
    ) -> None:
        """Test CMP revocation help includes credentials and reason-specific commands."""
        mock_reverse.side_effect = lambda name, kwargs: f'/{name}/{kwargs["pk"]}/'
        mock_revoke_command.return_value = 'openssl cmp -cmd rr -revreason 0 -trusted full-chain-3.pem'
        app_credential = Mock()
        app_credential.id = 17
        app_credential.common_name = 'app-cert-1'
        app_credential.credential.certificate_or_error.pk = 55
        mock_filter.return_value.select_related.return_value = [app_credential]
        domain = _domain()
        device = _device(domain, no_onboarding=True)

        sections, heading = CmpRevocationStrategy().build_sections(_help_context(device, domain, cred_count=3))

        assert 'Revoke CMP Application Credential' in heading
        assert 'app-cert-1' in sections[0].rows[1].value
        assert sections[1].heading == 'Credential Files'
        assert sections[2].heading == 'Revocation Reason'
        assert any('-revreason 1' in section.rows[0].value for section in sections[3:])
        mock_revoke_command.assert_called_once_with(
            host='https://trustpoint.test:8443/.well-known/cmp/p/test-domain/revocation',
            cred_number=3,
        )

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.reverse')
    def test_cmp_revocation_without_credentials_shows_empty_state(self, mock_reverse: Mock, mock_filter: Mock) -> None:
        """Test CMP revocation help shows an empty state when no app credentials exist."""
        mock_reverse.return_value = '/certificate/55/'
        mock_filter.return_value.select_related.return_value = []
        domain = _domain()
        device = _device(domain, no_onboarding=True)

        sections, _heading = CmpRevocationStrategy().build_sections(_help_context(device, domain, cred_count=1))

        assert sections[0].rows[1].key == 'No Credentials'
        assert 'No application credentials found' in sections[0].rows[1].value

    def test_aoki_cmp_and_est_strategies_build_instruction_sections(self) -> None:
        """Test AOKI strategies generate requirement, workflow, and command sections."""
        domain = _domain()
        context = _help_context(_device(domain), domain)

        cmp_sections, cmp_heading = AokiCmpIDevIDStrategy().build_sections(context)
        est_sections, est_heading = AokiEstIDevIDStrategy().build_sections(context)

        assert cmp_heading == 'AOKI with CMP - IDevID Authentication'
        assert [section.heading for section in cmp_sections] == [
            'Device Requirements',
            'Trustpoint Requirements',
            'How AOKI with CMP Works',
            'Example Commands',
        ]
        assert '-server https://trustpoint.test:8443/.well-known/cmp/p/test-domain' in cmp_sections[3].rows[1].value
        assert est_heading == 'AOKI with EST - IDevID Authentication (mTLS)'
        assert '"protocol": "EST"' in est_sections[3].rows[1].value
        assert 'domain_credential/simpleenroll' in est_sections[3].rows[1].value

    def test_aoki_est_strategy_requires_domain_for_response_profile(self) -> None:
        """Test AOKI EST fails when no domain is available for the domain credential profile."""
        domain = _domain()

        with self.assertRaises(Http404):
            AokiEstIDevIDStrategy().build_sections(_help_context(_device(domain), None))

    @patch('help_pages.devices_help_views.reverse')
    def test_agent_setup_profile_uses_onboarding_or_no_onboarding_password(self, mock_reverse: Mock) -> None:
        """Test agent setup profile content and password-source fallback behavior."""
        mock_reverse.side_effect = lambda name, kwargs: f'/{name}/{kwargs["pk"]}/'
        domain = _domain()
        onboarding_device = _device(domain, onboarding=True)
        no_onboarding_device = _device(domain, no_onboarding=True)

        assert _agent_get_est_password(onboarding_device) == 'rest-secret'
        assert _agent_get_est_password(no_onboarding_device) == 'rest-secret'

        sections, heading = AgentSetupProfileStrategy().build_sections(_help_context(onboarding_device, domain))

        assert heading == 'Help - Issue a Domain Credential for Agent'
        assert sections[0].rows[0].value == 'https://trustpoint.test:8443/rest/test-domain/domain_credential/enroll/'
        assert 'host_ip=trustpoint.test' in sections[0].rows[3].value
        assert 'python agent.py --profile agent_setup.json' in sections[0].rows[5].value

        with self.assertRaises(Http404):
            _agent_get_est_password(_device(domain))

    @patch('help_pages.devices_help_views.reverse', return_value='/renewal/123/')
    @patch('help_pages.devices_help_views.timezone')
    def test_opc_ua_gds_renewal_settings_render_enabled_pending_and_disabled(
        self, mock_timezone: Mock, mock_reverse: Mock
    ) -> None:
        """Test OPC UA renewal settings render the important scheduling states."""
        strategy = OpcUaGdsPushApplicationCertificateStrategy()
        device = Mock(pk=123, opc_gds_push_renewal_interval=12)
        now = Mock()
        future = Mock()
        future.__gt__ = Mock(return_value=True)
        future.strftime.return_value = '2026-09-04 12:00 UTC'
        mock_timezone.now.return_value = now

        device.opc_gds_push_enable_periodic_update = True
        device.opc_gds_push_last_update_scheduled_at = future
        enabled_section = strategy._build_renewal_settings_section(device)

        future.__gt__.return_value = False
        pending_section = strategy._build_renewal_settings_section(device)

        device.opc_gds_push_enable_periodic_update = False
        device.opc_gds_push_last_update_scheduled_at = None
        disabled_section = strategy._build_renewal_settings_section(device)

        assert 'Enabled' in enabled_section.rows[0].value
        assert '2026-09-04 12:00 UTC' in enabled_section.rows[0].value
        assert 'checked' in enabled_section.rows[1].value
        assert 'Pending' in pending_section.rows[0].value
        assert 'Disabled' in disabled_section.rows[0].value
        assert 'name="opc_gds_push_renewal_interval"' in disabled_section.rows[1].value
        assert mock_reverse.called
