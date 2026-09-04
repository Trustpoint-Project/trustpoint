# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Test cases for pki help views."""

from unittest.mock import Mock, patch

from django.http import Http404
from django.test import RequestFactory, TestCase
from trustpoint_core import oid

from pki.models import CaModel
from ..help_section import HelpSection, ValueRenderType
from ..pki_help_views import (
    BaseHelpView,
    CaDetailView,
    CaHelpView,
    CrlDownloadHelpView,
    DevIdRegistrationDetailView,
    DevIdRegistrationHelpView,
    DomainDetailView,
    DomainHelpView,
    IssuedCredentialDetailView,
    IssuedCredentialHelpView,
    OnboardingCmpIdevidRegistrationHelpView,
    OnboardingCmpIdevIdDomainCredentialStrategy,
    OnboardingEstIdevidRegistrationHelpView,
    OnboardingEstIdevIdDomainCredentialStrategy,
    OwnerCredentialDetailView,
    OwnerCredentialHelpView,
)


def _public_key_info() -> oid.PublicKeyInfo:
    """Return a reusable RSA public-key descriptor for PKI help contexts."""
    return oid.PublicKeyInfo(
        public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.RSA,
        key_size=2048,
    )


def _domain() -> Mock:
    """Return a lightweight domain mock."""
    domain = Mock()
    domain.unique_name = 'test-domain'
    domain.public_key_info = _public_key_info()
    domain.get_allowed_cert_profiles.return_value = []
    domain.issuing_ca = Mock(pk=77)
    return domain


def _device(domain: Mock) -> Mock:
    """Return a lightweight device mock."""
    device = Mock()
    device.common_name = 'device-1'
    device.domain = domain
    device.public_key_info = _public_key_info()
    return device


def _section(heading: str = 'Patched Section') -> HelpSection:
    """Return a simple section for patched shared helpers."""
    return HelpSection(heading, [])


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
        self.view.request = request

        with patch('help_pages.pki_help_views.settings') as mock_settings:
            mock_settings.TP_HTTPS_PORT = '8443'
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
        self.view.request = request

        with patch('help_pages.pki_help_views.settings') as mock_settings:
            mock_settings.TP_HTTPS_PORT = '443'
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

        mock_issuing_ca = Mock(spec=CaModel)
        mock_issuing_ca.pk = 123
        mock_issuing_ca.unique_name = 'test-ca'
        mock_issuing_ca.crl_pem = 'PEM_DATA'
        mock_issuing_ca.last_crl_issued_at = datetime(2024, 1, 1, 12, 0, 0)

        self.view.object = mock_issuing_ca
        self.view.page_category = 'pki'
        self.view.page_name = 'issuing_cas'
        request = self.factory.get('/')
        self.view.request = request

        with patch('help_pages.pki_help_views.settings') as mock_settings:
            mock_settings.TP_HTTPS_PORT = '443'
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

        mock_issuing_ca = Mock(spec=CaModel)
        mock_issuing_ca.pk = 123
        mock_issuing_ca.unique_name = 'test-ca'
        mock_issuing_ca.crl_pem = None
        mock_issuing_ca.last_crl_issued_at = None

        self.view.object = mock_issuing_ca
        self.view.page_category = 'pki'
        self.view.page_name = 'issuing_cas'
        request = self.factory.get('/')
        self.view.request = request

        with patch('help_pages.pki_help_views.settings') as mock_settings:
            mock_settings.TP_HTTPS_PORT = '443'
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

        mock_issuing_ca = Mock(spec=CaModel)
        mock_issuing_ca.pk = 123
        mock_issuing_ca.unique_name = 'test-ca'
        mock_issuing_ca.crl_pem = 'PEM_DATA'
        mock_issuing_ca.last_crl_issued_at = Mock()

        self.view.object = mock_issuing_ca
        self.view.page_category = 'pki'
        self.view.page_name = 'issuing_cas'
        request = self.factory.get('/')
        self.view.request = request

        with patch('help_pages.pki_help_views.settings') as mock_settings:
            mock_settings.TP_HTTPS_PORT = '443'
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


class PkiDetailAndHelpContextTests(TestCase):
    """Test concrete PKI detail/help context builders."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def _prepare_view(self, view: object, obj: Mock) -> object:
        view.object = obj
        view.request = self.factory.get('/', HTTP_X_FORWARDED_PORT='9443')
        return view

    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.10')
    def test_devid_registration_detail_context_contains_domain_endpoint_data(self, mock_ip: Mock) -> None:
        """Test DevID registration detail context exposes domain and host details."""
        domain = _domain()
        registration = Mock(domain=domain)
        view = self._prepare_view(DevIdRegistrationDetailView(), registration)

        context = view.get_context_data()

        assert context['devid_registration'] == registration
        assert context['domain'] == domain
        assert context['domain_unique_name'] == 'test-domain'
        assert context['host_base'] == 'https://192.0.2.10:9443'
        assert context['help_sections'] == []
        assert mock_ip.called

    @patch('help_pages.pki_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.pki_help_views.build_issuing_ca_cert_section', return_value=_section('Issuing CA'))
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.10')
    def test_devid_registration_help_context_builds_help_sections(
        self, mock_ip: Mock, mock_issuing_ca: Mock, mock_tls: Mock
    ) -> None:
        """Test DevID registration help context includes generated helper sections."""
        domain = _domain()
        view = self._prepare_view(DevIdRegistrationHelpView(), Mock(domain=domain))

        help_context = view._make_context()

        assert [section.heading for section in help_context.help_sections] == [
            'Key Generation',
            'Issuing CA',
            'TLS',
        ]
        assert 'idevid' in help_context.help_sections[0].rows[0].value
        assert mock_ip.called
        assert mock_issuing_ca.called
        assert mock_tls.called

    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.20')
    def test_domain_detail_context_contains_allowed_profiles(self, mock_ip: Mock) -> None:
        """Test domain detail context exposes allowed application profiles."""
        domain = _domain()
        allowed_profile = Mock()
        domain.get_allowed_cert_profiles.return_value = [allowed_profile]
        view = self._prepare_view(DomainDetailView(), domain)

        context = view.get_context_data()

        assert context['domain'] == domain
        assert context['allowed_app_profiles'] == [allowed_profile]
        assert context['host_base'] == 'https://192.0.2.20:9443'
        assert mock_ip.called

    @patch('help_pages.pki_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.pki_help_views.build_issuing_ca_cert_section', return_value=_section('Issuing CA'))
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.20')
    def test_domain_help_context_builds_application_certificate_sections(
        self, mock_ip: Mock, mock_issuing_ca: Mock, mock_tls: Mock
    ) -> None:
        """Test domain help context includes app-certificate guidance sections."""
        domain = _domain()
        view = self._prepare_view(DomainHelpView(), domain)

        help_context = view._make_context()

        assert [section.heading for section in help_context.help_sections] == [
            'Key Generation',
            'Issuing CA',
            'TLS',
        ]
        assert 'app_cert' in help_context.help_sections[0].rows[0].value
        assert mock_ip.called
        assert mock_issuing_ca.called
        assert mock_tls.called

    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.30')
    def test_issued_credential_detail_context_contains_device_and_credential(self, mock_ip: Mock) -> None:
        """Test issued credential detail context exposes device, domain, and credential."""
        domain = _domain()
        device = _device(domain)
        issued_credential = Mock(device=device)
        view = self._prepare_view(IssuedCredentialDetailView(), issued_credential)

        context = view.get_context_data()

        assert context['issued_credential'] == issued_credential
        assert context['device'] == device
        assert context['domain'] == domain
        assert context['host_base'] == 'https://192.0.2.30:9443'
        assert mock_ip.called

    @patch('help_pages.pki_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.pki_help_views.build_issuing_ca_cert_section', return_value=_section('Issuing CA'))
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.30')
    def test_issued_credential_help_context_builds_app_certificate_sections(
        self, mock_ip: Mock, mock_issuing_ca: Mock, mock_tls: Mock
    ) -> None:
        """Test issued credential help context includes app certificate helper sections."""
        domain = _domain()
        device = _device(domain)
        view = self._prepare_view(IssuedCredentialHelpView(), Mock(device=device))

        help_context = view._make_context()

        assert [section.heading for section in help_context.help_sections] == [
            'Key Generation',
            'Issuing CA',
            'TLS',
        ]
        assert 'app_cert' in help_context.help_sections[0].rows[0].value
        assert mock_ip.called
        assert mock_issuing_ca.called
        assert mock_tls.called

    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.40')
    def test_owner_credential_detail_context_contains_device_and_credential(self, mock_ip: Mock) -> None:
        """Test owner credential detail context exposes device, domain, and credential."""
        domain = _domain()
        device = _device(domain)
        owner_credential = Mock(device=device)
        view = self._prepare_view(OwnerCredentialDetailView(), owner_credential)

        context = view.get_context_data()

        assert context['owner_credential'] == owner_credential
        assert context['device'] == device
        assert context['domain_unique_name'] == 'test-domain'
        assert context['host_base'] == 'https://192.0.2.40:9443'
        assert mock_ip.called

    @patch('help_pages.pki_help_views.build_tls_trust_store_section', return_value=_section('TLS'))
    @patch('help_pages.pki_help_views.build_issuing_ca_cert_section', return_value=_section('Issuing CA'))
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.40')
    def test_owner_credential_help_context_builds_owner_certificate_sections(
        self, mock_ip: Mock, mock_issuing_ca: Mock, mock_tls: Mock
    ) -> None:
        """Test owner credential help context includes owner certificate helper sections."""
        domain = _domain()
        device = _device(domain)
        view = self._prepare_view(OwnerCredentialHelpView(), Mock(device=device))

        help_context = view._make_context()

        assert [section.heading for section in help_context.help_sections] == [
            'Key Generation',
            'Issuing CA',
            'TLS',
        ]
        assert 'owner_cert' in help_context.help_sections[0].rows[0].value
        assert mock_ip.called
        assert mock_issuing_ca.called
        assert mock_tls.called

    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.50')
    def test_ca_detail_context_uses_minimal_help_context(self, mock_ip: Mock) -> None:
        """Test CA detail context exposes CA and host details without domain data."""
        ca = Mock(pk=99)
        view = self._prepare_view(CaDetailView(), ca)

        context = view.get_context_data()

        assert context['ca'] == ca
        assert context['host_base'] == 'https://192.0.2.50:9443'
        assert context['help_sections'] == []
        assert mock_ip.called

    @patch('help_pages.pki_help_views.reverse')
    @patch('help_pages.pki_help_views.TlsSettings.get_first_ipv4_address', return_value='192.0.2.50')
    def test_ca_help_context_builds_certificate_download_links(self, mock_ip: Mock, mock_reverse: Mock) -> None:
        """Test CA help context includes CA certificate and chain download links."""
        mock_reverse.side_effect = lambda name, kwargs: f'/{name}/{kwargs["pk"]}/{kwargs.get("file_format", "")}'
        ca = Mock(pk=99)
        view = self._prepare_view(CaHelpView(), ca)

        help_context = view._make_context()

        section = help_context.help_sections[0]

        assert section.heading == 'CA Certificate'
        assert 'Download CA Certificate (PEM)' in section.rows[0].value
        assert 'Download CA Certificate Chain (PEM)' in section.rows[1].value
        assert mock_ip.called

    def test_detail_views_raise_for_missing_device_or_public_key_info(self) -> None:
        """Test important error paths for credential detail contexts."""
        domain = _domain()
        device = _device(domain)
        device.public_key_info = None

        issued_view = self._prepare_view(IssuedCredentialDetailView(), Mock(device=None))
        owner_view = self._prepare_view(OwnerCredentialDetailView(), Mock(device=None))
        issued_missing_key_view = self._prepare_view(IssuedCredentialDetailView(), Mock(device=device))

        with self.assertRaises(Http404):
            issued_view._make_context()
        with self.assertRaises(Http404):
            owner_view._make_context()
        with self.assertRaises(Http404):
            issued_missing_key_view._make_context()
