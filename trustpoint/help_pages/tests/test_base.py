"""Test cases for help_pages base module."""

from unittest.mock import Mock, patch

from django.http import Http404
from django.test import SimpleTestCase, TestCase
from trustpoint_core import oid

from ..base import (
    HelpContext,
    HelpPageStrategy,
    build_cmp_signer_trust_store_section,
    build_extract_files_from_p12_section,
    build_issuing_ca_cert_section,
    build_keygen_section,
    build_profile_select_section,
    build_tls_trust_store_section,
)
from ..help_section import ValueRenderType


class HelpPageStrategyTests(SimpleTestCase):
    """Test cases for HelpPageStrategy abstract base class."""

    def test_cannot_instantiate_abstract_class(self) -> None:
        """Test that HelpPageStrategy cannot be instantiated directly."""
        with self.assertRaises(TypeError):
            HelpPageStrategy()  # type: ignore[abstract]

    def test_must_implement_build_sections(self) -> None:
        """Test that subclasses must implement build_sections."""

        class IncompleteStrategy(HelpPageStrategy):
            pass

        with self.assertRaises(TypeError):
            IncompleteStrategy()  # type: ignore[abstract]


class HelpContextTests(SimpleTestCase):
    """Test cases for HelpContext dataclass."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.mock_domain = Mock()
        self.mock_public_key_info = oid.PublicKeyInfo(
            public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.RSA,
            key_size=2048,
        )

    def test_help_context_creation(self) -> None:
        """Test creating a HelpContext."""
        context = HelpContext(
            domain=self.mock_domain,
            domain_unique_name='test-domain',
            allowed_app_profiles=[],
            public_key_info=self.mock_public_key_info,
            host_base='https://localhost:443',
            host_cmp_path='https://localhost:443/.well-known/cmp/p/test-domain',
            host_est_path='https://localhost:443/.well-known/est/test-domain',
            cred_count=1,
        )

        assert context.domain == self.mock_domain
        assert context.domain_unique_name == 'test-domain'
        assert context.cred_count == 1
        assert context.device is None
        assert context.devid_registration is None

    def test_get_device_or_http_404_with_device(self) -> None:
        """Test get_device_or_http_404 returns device when present."""
        mock_device = Mock()
        context = HelpContext(
            domain=self.mock_domain,
            domain_unique_name='test-domain',
            allowed_app_profiles=[],
            public_key_info=self.mock_public_key_info,
            host_base='https://localhost:443',
            host_cmp_path='https://localhost:443/.well-known/cmp/p/test-domain',
            host_est_path='https://localhost:443/.well-known/est/test-domain',
            cred_count=1,
            device=mock_device,
        )

        result = context.get_device_or_http_404()
        assert result == mock_device

    def test_get_device_or_http_404_without_device(self) -> None:
        """Test get_device_or_http_404 raises Http404 when device is None."""
        context = HelpContext(
            domain=self.mock_domain,
            domain_unique_name='test-domain',
            allowed_app_profiles=[],
            public_key_info=self.mock_public_key_info,
            host_base='https://localhost:443',
            host_cmp_path='https://localhost:443/.well-known/cmp/p/test-domain',
            host_est_path='https://localhost:443/.well-known/est/test-domain',
            cred_count=1,
        )

        with self.assertRaises(Http404) as cm:
            context.get_device_or_http_404()

        assert 'Device not found' in str(cm.exception)

    def test_get_devid_registration_or_http_404_with_registration(self) -> None:
        """Test get_devid_registration_or_http_404 returns registration when present."""
        mock_registration = Mock()
        context = HelpContext(
            domain=self.mock_domain,
            domain_unique_name='test-domain',
            allowed_app_profiles=[],
            public_key_info=self.mock_public_key_info,
            host_base='https://localhost:443',
            host_cmp_path='https://localhost:443/.well-known/cmp/p/test-domain',
            host_est_path='https://localhost:443/.well-known/est/test-domain',
            cred_count=1,
            devid_registration=mock_registration,
        )

        result = context.get_devid_registration_or_http_404()
        assert result == mock_registration

    def test_get_devid_registration_or_http_404_without_registration(self) -> None:
        """Test get_devid_registration_or_http_404 raises Http404 when registration is None."""
        context = HelpContext(
            domain=self.mock_domain,
            domain_unique_name='test-domain',
            allowed_app_profiles=[],
            public_key_info=self.mock_public_key_info,
            host_base='https://localhost:443',
            host_cmp_path='https://localhost:443/.well-known/cmp/p/test-domain',
            host_est_path='https://localhost:443/.well-known/est/test-domain',
            cred_count=1,
        )

        with self.assertRaises(Http404) as cm:
            context.get_devid_registration_or_http_404()

        assert 'DevidRegistration not found' in str(cm.exception)

    def test_help_context_is_frozen(self) -> None:
        """Test that HelpContext is immutable."""
        context = HelpContext(
            domain=self.mock_domain,
            domain_unique_name='test-domain',
            allowed_app_profiles=[],
            public_key_info=self.mock_public_key_info,
            host_base='https://localhost:443',
            host_cmp_path='https://localhost:443/.well-known/cmp/p/test-domain',
            host_est_path='https://localhost:443/.well-known/est/test-domain',
            cred_count=1,
        )

        with self.assertRaises(AttributeError):
            context.cred_count = 2  # type: ignore[misc]


class BuildKeygenSectionTests(SimpleTestCase):
    """Test cases for build_keygen_section function."""

    def test_build_keygen_section_rsa(self) -> None:
        """Test building keygen section for RSA."""
        public_key_info = oid.PublicKeyInfo(
            public_key_algorithm_oid=oid.PublicKeyAlgorithmOid.RSA,
            key_size=2048,
        )
        context = HelpContext(
            domain=Mock(),
            domain_unique_name='test',
            allowed_app_profiles=[],
            public_key_info=public_key_info,
            host_base='https://localhost',
            host_cmp_path='https://localhost/cmp',
            host_est_path='https://localhost/est',
            cred_count=1,
        )

        section = build_keygen_section(context, 'test-key.pem')

        assert section.heading == 'Key Generation'
        assert len(section.rows) == 1
        assert section.rows[0].key == 'Generate Key-Pair'
        assert 'openssl genrsa' in section.rows[0].value
        assert 'test-key.pem' in section.rows[0].value
        assert section.rows[0].value_render_type == ValueRenderType.CODE


class BuildProfileSelectSectionTests(SimpleTestCase):
    """Test cases for build_profile_select_section function."""

    def test_build_profile_select_section_with_profiles(self) -> None:
        """Test building profile select section with profiles."""
        mock_profile1 = Mock()
        mock_profile1.alias = None
        mock_profile1.certificate_profile.unique_name = 'profile1'
        mock_profile1.certificate_profile.display_name = 'Profile 1'

        mock_profile2 = Mock()
        mock_profile2.alias = 'custom_alias'
        mock_profile2.certificate_profile.unique_name = 'profile2'
        mock_profile2.certificate_profile.display_name = 'Profile 2'

        section = build_profile_select_section([mock_profile1, mock_profile2])

        assert section.heading == 'Certificate Profile Selection'
        assert len(section.rows) == 1
        assert section.rows[0].key == 'Certificate Profile'
        assert 'select' in section.rows[0].value.lower()
        assert 'Profile 1' in section.rows[0].value
        assert 'Profile 2' in section.rows[0].value

    def test_build_profile_select_section_without_profiles(self) -> None:
        """Test building profile select section without profiles."""
        section = build_profile_select_section([])

        assert section.heading == 'Certificate Profile Selection'
        assert len(section.rows) == 1
        assert 'No application certificate profiles' in section.rows[0].value


class BuildTlsTrustStoreSectionTests(TestCase):
    """Test cases for build_tls_trust_store_section function."""

    @patch('help_pages.base.ActiveTrustpointTlsServerCredentialModel.objects.first')
    @patch('help_pages.base.reverse')
    def test_build_tls_trust_store_section_success(self, mock_reverse: Mock, mock_first: Mock) -> None:
        """Test building TLS trust store section successfully."""
        mock_tls = Mock()
        mock_credential = Mock()
        mock_root = Mock()
        mock_root.pk = 123

        mock_credential.get_last_in_chain.return_value = mock_root
        mock_tls.credential = mock_credential
        mock_first.return_value = mock_tls
        mock_reverse.return_value = '/download/123'

        section = build_tls_trust_store_section()

        assert section.heading == 'Download TLS Trust-Store'
        assert len(section.rows) == 1
        assert 'Download TLS Trust-Store' in section.rows[0].key
        assert 'btn' in section.rows[0].value

    @patch('help_pages.base.ActiveTrustpointTlsServerCredentialModel.objects.first')
    def test_build_tls_trust_store_section_no_tls(self, mock_first: Mock) -> None:
        """Test building TLS trust store section when TLS is unavailable."""
        mock_first.return_value = None

        section = build_tls_trust_store_section()

        assert section.heading == 'Download TLS Trust-Store'
        assert 'unavailable' in section.rows[0].key.lower()
        assert 'alert' in section.rows[0].value

    @patch('help_pages.base.ActiveTrustpointTlsServerCredentialModel.objects.first')
    def test_build_tls_trust_store_section_no_root(self, mock_first: Mock) -> None:
        """Test building TLS trust store section when root CA is missing."""
        mock_tls = Mock()
        mock_credential = Mock()
        mock_credential.get_last_in_chain.return_value = None
        mock_tls.credential = mock_credential
        mock_first.return_value = mock_tls

        with self.assertRaises(Http404):
            build_tls_trust_store_section()


class BuildCmpSignerTrustStoreSectionTests(SimpleTestCase):
    """Test cases for build_cmp_signer_trust_store_section function."""

    @patch('help_pages.base.reverse')
    def test_build_cmp_signer_trust_store_section_success(self, mock_reverse: Mock) -> None:
        """Test building CMP signer trust store section successfully."""
        mock_domain = Mock()
        mock_issuing_ca = Mock()
        mock_credential = Mock()
        mock_root = Mock()
        mock_root.pk = 456

        mock_credential.get_last_in_chain.return_value = mock_root
        mock_issuing_ca.credential = mock_credential
        mock_domain.issuing_ca = mock_issuing_ca
        mock_reverse.return_value = '/download/456'

        section = build_cmp_signer_trust_store_section(mock_domain)

        assert section.heading == 'Download CMP-Signer Trust-Store'
        assert len(section.rows) == 1
        assert 'Download CMP-Signer Trust-Store' in section.rows[0].key

    def test_build_cmp_signer_trust_store_section_no_issuing_ca(self) -> None:
        """Test building CMP signer trust store section without issuing CA."""
        mock_domain = Mock()
        mock_domain.issuing_ca = None

        with self.assertRaises(ValueError) as cm:
            build_cmp_signer_trust_store_section(mock_domain)

        assert 'Issuing CA not configured' in str(cm.exception)

    def test_build_cmp_signer_trust_store_section_no_root(self) -> None:
        """Test building CMP signer trust store section without root CA."""
        mock_domain = Mock()
        mock_issuing_ca = Mock()
        mock_credential = Mock()
        mock_credential.get_last_in_chain.return_value = None
        mock_issuing_ca.credential = mock_credential
        mock_domain.issuing_ca = mock_issuing_ca

        with self.assertRaises(ValueError) as cm:
            build_cmp_signer_trust_store_section(mock_domain)

        assert 'No Root CA certificate found' in str(cm.exception)


class BuildIssuingCaCertSectionTests(SimpleTestCase):
    """Test cases for build_issuing_ca_cert_section function."""

    @patch('help_pages.base.reverse')
    def test_build_issuing_ca_cert_section_success(self, mock_reverse: Mock) -> None:
        """Test building issuing CA cert section successfully."""
        mock_domain = Mock()
        mock_issuing_ca = Mock()
        mock_issuing_ca.pk = 789
        mock_domain.issuing_ca = mock_issuing_ca
        mock_reverse.return_value = '/download/789'

        section = build_issuing_ca_cert_section(mock_domain)

        assert section.heading == 'Download Issuing CA Certificate'
        assert len(section.rows) == 1
        assert 'Download Issuing CA Certificate' in section.rows[0].key

    def test_build_issuing_ca_cert_section_no_issuing_ca(self) -> None:
        """Test building issuing CA cert section without issuing CA."""
        mock_domain = Mock()
        mock_domain.issuing_ca = None

        with self.assertRaises(ValueError) as cm:
            build_issuing_ca_cert_section(mock_domain)

        assert 'Issuing CA not configured' in str(cm.exception)


class BuildExtractFilesFromP12SectionTests(SimpleTestCase):
    """Test cases for build_extract_files_from_p12_section function."""

    def test_build_extract_files_from_p12_section(self) -> None:
        """Test building extract files from P12 section."""
        section = build_extract_files_from_p12_section()

        assert section.heading == 'PKCS#12 or PFX convertion'
        assert len(section.rows) == 5

        # Check that all expected rows are present
        keys = [row.key for row in section.rows]
        assert 'Instructions' in keys
        assert 'PKCS#12 IDevID Certificate Extraction' in keys
        assert 'PKCS#12 IDevID Certificate Chain Extraction' in keys
        assert 'PKCS#12 IDevID Private Key Extraction' in keys
        assert 'Remarks' in keys

        # Check that OpenSSL commands are present
        for row in section.rows[1:4]:  # Certificate, chain, and key extraction rows
            assert 'openssl pkcs12' in row.value
            assert row.value_render_type == ValueRenderType.CODE
