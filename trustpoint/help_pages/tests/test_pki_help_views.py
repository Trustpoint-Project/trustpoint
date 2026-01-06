"""Test cases for pki help views."""

from unittest.mock import Mock, patch

from django.http import Http404
from django.test import RequestFactory, TestCase
from django.urls import reverse

from pki.models import DevIdRegistration, IssuingCaModel
from ..help_section import ValueRenderType
from ..pki_help_views import (
    BaseHelpView,
    CrlDownloadHelpView,
    OnboardingCmpIdevidRegistrationHelpView,
    OnboardingCmpIdevIdDomainCredentialStrategy,
    OnboardingEstIdevidRegistrationHelpView,
    OnboardingEstIdevIdDomainCredentialStrategy,
)


class BaseHelpViewTests(TestCase):
    """Test cases for BaseHelpView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BaseHelpView()

    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address')
    def test_make_context_success(self, mock_get_ip: Mock) -> None:
        """Test _make_context creates HelpContext successfully."""
        mock_get_ip.return_value = '192.168.1.1'

        mock_domain = Mock()
        mock_domain.unique_name = 'test-domain'
        mock_domain.public_key_info = Mock()

        mock_registration = Mock()
        mock_registration.domain = mock_domain

        self.view.object = mock_registration
        request = self.factory.get('/')
        request.META['SERVER_PORT'] = '8443'
        self.view.request = request

        context = self.view._make_context()

        assert context.domain == mock_domain
        assert context.domain_unique_name == 'test-domain'
        assert context.devid_registration == mock_registration
        assert context.host_base == 'https://192.168.1.1:8443'
        assert context.host_cmp_path == 'https://192.168.1.1:8443/.well-known/cmp/p/test-domain'
        assert context.host_est_path == 'https://192.168.1.1:8443/.well-known/est/test-domain'

    def test_make_context_no_domain(self) -> None:
        """Test _make_context raises Http404 when domain is missing."""
        mock_registration = Mock()
        mock_registration.domain = None

        self.view.object = mock_registration
        self.view.request = self.factory.get('/')

        with self.assertRaises(Http404) as cm:
            self.view._make_context()

        assert 'Failed to get domain from DevidRegistration' in str(cm.exception)

    def test_make_context_no_public_key_info(self) -> None:
        """Test _make_context raises Http404 when public_key_info is missing."""
        mock_domain = Mock()
        mock_domain.unique_name = 'test-domain'
        mock_domain.public_key_info = None

        mock_registration = Mock()
        mock_registration.domain = mock_domain

        self.view.object = mock_registration
        self.view.request = self.factory.get('/')

        with self.assertRaises(Http404):
            self.view._make_context()

    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address')
    def test_get_context_data_success(self, mock_get_ip: Mock) -> None:
        """Test get_context_data builds help page successfully."""
        mock_get_ip.return_value = '192.168.1.1'

        mock_domain = Mock()
        mock_domain.unique_name = 'test-domain'
        mock_domain.public_key_info = Mock()

        mock_registration = Mock()
        mock_registration.domain = mock_domain

        mock_strategy = Mock()
        mock_strategy.build_sections.return_value = ([], 'Test Heading')

        self.view.object = mock_registration
        self.view.strategy = mock_strategy
        self.view.page_category = 'pki'
        self.view.page_name = 'domains'
        request = self.factory.get('/')
        request.META['SERVER_PORT'] = '443'
        self.view.request = request

        context = self.view.get_context_data()

        assert 'help_page' in context
        assert context['help_page'].heading == 'Test Heading'
        assert context['ValueRenderType_CODE'] == ValueRenderType.CODE.value
        assert context['back_url'] == 'pki:domains-config'

    def test_get_context_data_no_strategy(self) -> None:
        """Test get_context_data raises RuntimeError when strategy is not configured."""
        self.view.object = Mock()
        self.view.strategy = None

        with self.assertRaises(RuntimeError) as cm:
            self.view.get_context_data()

        assert 'No strategy configured' in str(cm.exception)


class OnboardingCmpIdevIdDomainCredentialStrategyTests(TestCase):
    """Test cases for OnboardingCmpIdevIdDomainCredentialStrategy."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.strategy = OnboardingCmpIdevIdDomainCredentialStrategy()

    @patch('help_pages.pki_help_views.build_extract_files_from_p12_section')
    @patch('help_pages.pki_help_views.build_keygen_section')
    @patch('help_pages.pki_help_views.build_issuing_ca_cert_section')
    def test_build_sections(
        self,
        mock_issuing_ca: Mock,
        mock_keygen: Mock,
        mock_extract: Mock,
    ) -> None:
        """Test build_sections creates all required sections."""
        mock_issuing_ca.return_value = Mock()
        mock_keygen.return_value = Mock()
        mock_extract.return_value = Mock()

        mock_domain = Mock()
        mock_domain.public_key_info = 'RSA 2048'

        help_context = Mock()
        help_context.host_cmp_path = 'https://localhost/cmp/test'
        help_context.domain = mock_domain

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) == 5
        assert 'Help - Issue Application Certificates' in heading
        assert sections[0].heading == 'Summary'
        assert len(sections[0].rows) == 2
        mock_issuing_ca.assert_called_once()
        mock_keygen.assert_called_once()
        mock_extract.assert_called_once()


class OnboardingCmpIdevidRegistrationHelpViewTests(TestCase):
    """Test cases for OnboardingCmpIdevidRegistrationHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = OnboardingCmpIdevidRegistrationHelpView()
        assert isinstance(view.strategy, OnboardingCmpIdevIdDomainCredentialStrategy)


class OnboardingEstIdevIdDomainCredentialStrategyTests(TestCase):
    """Test cases for OnboardingEstIdevIdDomainCredentialStrategy."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.strategy = OnboardingEstIdevIdDomainCredentialStrategy()

    @patch('help_pages.pki_help_views.build_extract_files_from_p12_section')
    @patch('help_pages.pki_help_views.build_keygen_section')
    @patch('help_pages.pki_help_views.build_tls_trust_store_section')
    def test_build_sections(
        self,
        mock_tls: Mock,
        mock_keygen: Mock,
        mock_extract: Mock,
    ) -> None:
        """Test build_sections creates all required sections."""
        mock_tls.return_value = Mock()
        mock_keygen.return_value = Mock()
        mock_extract.return_value = Mock()

        mock_domain = Mock()
        mock_domain.public_key_info = 'RSA 2048'

        help_context = Mock()
        help_context.host_est_path = 'https://localhost/est/test'
        help_context.domain = mock_domain

        sections, heading = self.strategy.build_sections(help_context)

        assert len(sections) == 6
        assert 'Help - Issue Application Certificates' in heading
        assert sections[0].heading == 'Summary'
        assert sections[4].heading == 'Enroll Domain Credential'
        assert sections[5].heading == 'CA Certificate Chain'
        mock_tls.assert_called_once()
        mock_keygen.assert_called_once()
        mock_extract.assert_called_once()


class OnboardingEstIdevidRegistrationHelpViewTests(TestCase):
    """Test cases for OnboardingEstIdevidRegistrationHelpView."""

    def test_strategy_is_configured(self) -> None:
        """Test that strategy is properly configured."""
        view = OnboardingEstIdevidRegistrationHelpView()
        assert isinstance(view.strategy, OnboardingEstIdevIdDomainCredentialStrategy)


class CrlDownloadHelpViewTests(TestCase):
    """Test cases for CrlDownloadHelpView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = CrlDownloadHelpView()

    @patch('help_pages.pki_help_views.build_tls_trust_store_section')
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address')
    def test_get_context_data_with_crl(
        self, mock_get_ip: Mock, mock_tls_section: Mock
    ) -> None:
        """Test get_context_data when CRL is available."""
        from datetime import datetime

        mock_get_ip.return_value = '192.168.1.1'
        mock_tls_section.return_value = Mock(heading='TLS', rows=[])

        mock_issuing_ca = Mock(spec=IssuingCaModel)
        mock_issuing_ca.pk = 123
        mock_issuing_ca.unique_name = 'test-ca'
        mock_issuing_ca.crl_pem = 'PEM_DATA'
        mock_issuing_ca.last_crl_issued_at = datetime(2024, 1, 1, 12, 0, 0)

        self.view.object = mock_issuing_ca
        self.view.page_category = 'pki'
        self.view.page_name = 'issuing_cas'
        request = self.factory.get('/')
        request.META['SERVER_PORT'] = '443'
        self.view.request = request

        context = self.view.get_context_data()

        assert 'help_page' in context
        help_page = context['help_page']
        assert 'Download CRL for test-ca' in help_page.heading
        assert len(help_page.sections) == 5  # summary, status, tls, download, notes

        # Check CRL status section
        status_section = help_page.sections[1]
        assert status_section.heading == 'CRL Status'
        assert any('Available' in row.value for row in status_section.rows)
        assert any('2024-01-01' in row.value for row in status_section.rows)

    @patch('help_pages.pki_help_views.build_tls_trust_store_section')
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address')
    @patch('help_pages.pki_help_views.reverse')
    def test_get_context_data_without_crl(
        self, mock_reverse: Mock, mock_get_ip: Mock, mock_tls_section: Mock
    ) -> None:
        """Test get_context_data when CRL is not available."""
        mock_get_ip.return_value = '192.168.1.1'
        mock_tls_section.return_value = Mock(heading='TLS', rows=[])
        mock_reverse.side_effect = lambda name, **kwargs: f'/{name}/{kwargs.get("pk", "")}'

        mock_issuing_ca = Mock(spec=IssuingCaModel)
        mock_issuing_ca.pk = 123
        mock_issuing_ca.unique_name = 'test-ca'
        mock_issuing_ca.crl_pem = None
        mock_issuing_ca.last_crl_issued_at = None

        self.view.object = mock_issuing_ca
        self.view.page_category = 'pki'
        self.view.page_name = 'issuing_cas'
        request = self.factory.get('/')
        request.META['SERVER_PORT'] = '443'
        self.view.request = request

        context = self.view.get_context_data()

        help_page = context['help_page']
        status_section = help_page.sections[1]

        # Check that "Not Available" message is shown
        status_rows_text = ' '.join(row.value for row in status_section.rows)
        assert 'Not Available' in status_rows_text or 'Generate a CRL first' in status_rows_text

    @patch('help_pages.pki_help_views.build_tls_trust_store_section')
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address')
    def test_get_context_data_curl_commands(
        self, mock_get_ip: Mock, mock_tls_section: Mock
    ) -> None:
        """Test that curl commands are properly formatted."""
        mock_get_ip.return_value = '192.168.1.1'
        mock_tls_section.return_value = Mock(heading='TLS', rows=[])

        mock_issuing_ca = Mock(spec=IssuingCaModel)
        mock_issuing_ca.pk = 123
        mock_issuing_ca.unique_name = 'test-ca'
        mock_issuing_ca.crl_pem = 'PEM_DATA'
        mock_issuing_ca.last_crl_issued_at = Mock()

        self.view.object = mock_issuing_ca
        self.view.page_category = 'pki'
        self.view.page_name = 'issuing_cas'
        request = self.factory.get('/')
        request.META['SERVER_PORT'] = '443'
        self.view.request = request

        context = self.view.get_context_data()

        help_page = context['help_page']
        download_section = help_page.sections[3]  # Download CRL section

        # Check PEM download command
        pem_row = download_section.rows[0]
        assert 'curl' in pem_row.value
        assert 'test-ca.pem.crl' in pem_row.value
        assert '/crl/123/' in pem_row.value

        # Check DER download command
        der_row = download_section.rows[1]
        assert 'curl' in der_row.value
        assert 'test-ca.der.crl' in der_row.value
        assert 'encoding=der' in der_row.value
