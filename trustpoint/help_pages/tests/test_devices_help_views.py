"""Test cases for devices help views."""

from unittest.mock import Mock, patch

from django.http import Http404
from django.test import RequestFactory, TestCase

from devices.models import DeviceModel
from ..devices_help_views import (
    BaseHelpView,
    DeviceApplicationCertificateWithCmpDomainCredentialHelpView,
    DeviceApplicationCertificateWithEstDomainCredentialHelpView,
    DeviceNoOnboardingCmpSharedSecretHelpView,
    DeviceNoOnboardingEstUsernamePasswordHelpView,
    DeviceOnboardingDomainCredentialCmpSharedSecretHelpView,
    DeviceOnboardingDomainCredentialEstUsernamePasswordHelpView,
    NoOnboardingCmpSharedSecretStrategy,
    NoOnboardingEstUsernamePasswordStrategy,
    OnboardingDomainCredentialCmpSharedSecretStrategy,
    OnboardingDomainCredentialEstUsernamePasswordStrategy,
    OpcUaGdsPushApplicationCertificateHelpView,
    OpcUaGdsPushOnboardingHelpView,
    OpcUaGdsPushOnboardingStrategy,
)
from ..help_section import ValueRenderType


class BaseHelpViewTests(TestCase):
    """Test cases for BaseHelpView in devices app."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BaseHelpView()

    @patch('help_pages.devices_help_views.IssuedCredentialModel.objects.filter')
    @patch('help_pages.devices_help_views.TlsSettings.get_first_ipv4_address')
    def test_make_context_success(self, mock_get_ip: Mock, mock_filter: Mock) -> None:
        """Test _make_context creates HelpContext successfully."""
        mock_get_ip.return_value = '192.168.1.1'
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
        request.META['SERVER_PORT'] = '8443'
        self.view.request = request

        context = self.view._make_context()

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
    @patch('help_pages.devices_help_views.TlsSettings.get_first_ipv4_address')
    def test_get_context_data_success(self, mock_get_ip: Mock, mock_filter: Mock) -> None:
        """Test get_context_data builds help page successfully."""
        mock_get_ip.return_value = '192.168.1.1'
        mock_filter.return_value.count.return_value = 1

        mock_domain = Mock()
        mock_domain.unique_name = 'test-domain'
        mock_domain.public_key_info = Mock()
        mock_domain.get_allowed_cert_profiles.return_value.exclude.return_value = []

        mock_device = Mock()
        mock_device.domain = mock_domain

        mock_strategy = Mock()
        mock_strategy.build_sections.return_value = ([], 'Test Heading')

        self.view.object = mock_device
        self.view.strategy = mock_strategy
        self.view.page_category = 'devices'
        self.view.page_name = 'devices'
        request = self.factory.get('/')
        request.META['SERVER_PORT'] = '443'
        self.view.request = request

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
