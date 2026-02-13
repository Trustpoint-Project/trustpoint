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
