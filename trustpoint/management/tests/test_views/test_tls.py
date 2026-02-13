"""Test suite for TLS views."""

from unittest.mock import Mock, patch

from django.contrib.messages import get_messages
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.test import RequestFactory, TestCase
from django.urls import reverse
from management.forms import IPv4AddressForm, TlsAddFileImportPkcs12Form, TlsAddFileImportSeparateFilesForm
from management.models import TlsSettings
from management.views.tls import (
    ActivateTlsServerView,
    GenerateTlsCertificateView,
    TlsAddFileImportPkcs12View,
    TlsAddFileImportSeparateFilesView,
    TlsAddMethodSelectView,
    TlsSettingsContextMixin,
    TlsView,
)
from pki.models import CertificateModel, CredentialModel, GeneralNameIpAddress
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.forms import StartupWizardTlsCertificateForm


class TlsSettingsContextMixinTest(TestCase):
    """Test suite for TlsSettingsContextMixin."""

    def test_page_category(self):
        """Test mixin has correct page_category."""
        mixin = TlsSettingsContextMixin()
        self.assertEqual(mixin.page_category, 'management')

    def test_page_name(self):
        """Test mixin has correct page_name."""
        mixin = TlsSettingsContextMixin()
        self.assertEqual(mixin.page_name, 'tls')

    def test_get_context_data_adds_page_info(self):
        """Test get_context_data adds page category and name."""
        # Create a view that inherits from TlsView (which includes the mixin)
        view = TlsView()
        view.request = RequestFactory().get('/tls/')

        context = view.get_context_data()

        self.assertEqual(context['page_category'], 'management')
        self.assertEqual(context['page_name'], 'tls')


class TlsViewTest(TestCase):
    """Test suite for TlsView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = TlsView()
        self.view.request = self.factory.get('/tls/')

        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(self.view.request, 'session', 'session')
        messages_storage = FallbackStorage(self.view.request)
        setattr(self.view.request, '_messages', messages_storage)

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/tls.html')

    def test_form_class(self):
        """Test correct form class is used."""
        self.assertEqual(self.view.form_class, IPv4AddressForm)

    def test_success_url(self):
        """Test success URL is set correctly."""
        self.assertEqual(str(self.view.success_url), reverse('management:tls'))

    def test_get_form_kwargs_with_existing_tls_settings(self):
        """Test get_form_kwargs includes saved IPv4 address."""
        TlsSettings.objects.create(id=1, ipv4_address='192.168.1.1')

        form_kwargs = self.view.get_form_kwargs()

        self.assertIn('initial', form_kwargs)
        self.assertEqual(form_kwargs['initial']['ipv4_address'], '192.168.1.1')

    def test_get_form_kwargs_without_tls_settings(self):
        """Test get_form_kwargs without existing TLS settings."""
        form_kwargs = self.view.get_form_kwargs()

        self.assertIn('initial', form_kwargs)

    @patch.object(TlsView, 'get_san_ips')
    def test_get_form_kwargs_uses_first_san_ip_if_no_saved_address(self, mock_get_san_ips):
        """Test get_form_kwargs uses first SAN IP when no saved address."""
        mock_get_san_ips.return_value = ['10.0.0.1', '10.0.0.2']

        form_kwargs = self.view.get_form_kwargs()

        self.assertEqual(form_kwargs['initial']['ipv4_address'], '10.0.0.1')

    def test_get_context_data_without_active_credential(self):
        """Test get_context_data when no active TLS credential exists."""
        context = self.view.get_context_data()

        self.assertIn('certificate', context)
        self.assertIsNone(context['certificate'])
        self.assertIn('san_ips', context)
        self.assertEqual(context['san_ips'], [])

    @patch('management.views.tls.TlsView.get_san_ips')
    @patch('management.views.tls.CertificateModel')
    @patch('management.views.tls.ActiveTrustpointTlsServerCredentialModel')
    def test_get_context_data_with_active_credential_and_san(
        self, mock_active_model, mock_cert_model, mock_get_san_ips
    ):
        """Test get_context_data with active TLS credential and SAN data."""
        # Mock get_san_ips to avoid database queries in get_form_kwargs
        mock_get_san_ips.return_value = ['192.168.1.1']

        # Mock the certificate with SAN extension
        mock_certificate = Mock(spec=CertificateModel)
        mock_certificate.subject_alternative_name_extension = Mock()
        mock_certificate.issuer = Mock()

        # Mock SAN model with IP addresses and DNS names
        mock_ip = Mock()
        mock_ip.value = '192.168.1.1'
        mock_dns = Mock()
        mock_dns.value = 'example.com'

        mock_san_model = Mock()
        mock_san_model.ip_addresses.all.return_value = [mock_ip]
        mock_san_model.dns_names.all.return_value = [mock_dns]
        mock_certificate.subject_alternative_name_extension.subject_alt_name = mock_san_model

        # Mock issuer attributes
        mock_attr1 = Mock()
        mock_attr1.oid = '2.5.4.6'
        mock_attr1.value = 'US'
        mock_attr2 = Mock()
        mock_attr2.oid = '2.5.4.10'
        mock_attr2.value = 'Example Corp'
        mock_attr3 = Mock()
        mock_attr3.oid = '2.5.4.3'
        mock_attr3.value = 'Test CA'

        mock_certificate.issuer.exists.return_value = True
        mock_certificate.issuer.all.return_value = [mock_attr1, mock_attr2, mock_attr3]

        # Mock credential
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.certificate = mock_certificate

        # Mock active TLS credential
        mock_active_tls = Mock()
        mock_active_tls.credential = mock_credential
        mock_active_model.objects.select_related.return_value.get.return_value = mock_active_tls

        # Mock TLS certificates queryset
        mock_cert = Mock()
        mock_cert.common_name = 'test cert'
        mock_cert.pk = 1
        mock_queryset = Mock()
        mock_queryset.count.return_value = 1
        mock_queryset.__iter__ = Mock(return_value=iter([mock_cert]))
        mock_cert_model.objects.filter.return_value = mock_queryset

        # Get context data
        context = self.view.get_context_data()

        # Verify certificate data
        self.assertEqual(context['certificate'], mock_certificate)

        # Verify SAN IPs
        self.assertIn('192.168.1.1', context['san_ips'])

        # Verify SAN DNS names
        self.assertIn('example.com', context['san_dns_names'])

        # Verify issuer details
        self.assertEqual(context['issuer_details']['country'], 'US')
        self.assertEqual(context['issuer_details']['organization'], 'Example Corp')
        self.assertEqual(context['issuer_details']['common_name'], 'Test CA')

    @patch('management.views.tls.TlsView.get_san_ips')
    @patch('management.views.tls.CertificateModel')
    @patch('management.views.tls.ActiveTrustpointTlsServerCredentialModel')
    def test_get_context_data_with_certificate_no_san(self, mock_active_model, mock_cert_model, mock_get_san_ips):
        """Test get_context_data with certificate but no SAN extension."""
        # Mock get_san_ips to avoid database queries
        mock_get_san_ips.return_value = []

        # Mock certificate without SAN extension
        mock_certificate = Mock(spec=CertificateModel)
        mock_certificate.subject_alternative_name_extension = None
        mock_certificate.issuer = Mock()
        mock_certificate.issuer.exists.return_value = False

        mock_credential = Mock(spec=CredentialModel)
        mock_credential.certificate = mock_certificate

        mock_active_tls = Mock()
        mock_active_tls.credential = mock_credential
        mock_active_model.objects.select_related.return_value.get.return_value = mock_active_tls

        mock_cert = Mock()
        mock_cert.common_name = 'test cert'
        mock_cert.pk = 1
        mock_queryset = Mock()
        mock_queryset.count.return_value = 1
        mock_queryset.__iter__ = Mock(return_value=iter([mock_cert]))
        mock_cert_model.objects.filter.return_value = mock_queryset

        context = self.view.get_context_data()

        self.assertEqual(context['certificate'], mock_certificate)
        self.assertEqual(context['san_ips'], [])
        self.assertEqual(context['san_dns_names'], [])

    def test_get_san_ips_without_active_credential(self):
        """Test get_san_ips returns empty list when no active credential."""
        result = self.view.get_san_ips()
        self.assertEqual(result, [])

    @patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'select_related')
    def test_get_san_ips_with_certificate_no_san_extension(self, mock_select_related):
        """Test get_san_ips returns empty list when certificate has no SAN extension."""
        mock_certificate = Mock(spec=CertificateModel)
        mock_certificate.subject_alternative_name_extension = None

        mock_credential = Mock(spec=CredentialModel)
        mock_credential.certificate = mock_certificate

        mock_active_tls = Mock()
        mock_active_tls.credential = mock_credential
        mock_select_related.return_value.get.return_value = mock_active_tls

        result = self.view.get_san_ips()
        self.assertEqual(result, [])

    @patch('management.views.tls.GeneralNameIpAddress')
    @patch('management.views.tls.ActiveTrustpointTlsServerCredentialModel')
    def test_get_san_ips_with_ipv4_addresses(self, mock_active_model, mock_ip_model):
        """Test get_san_ips returns IPv4 addresses from SAN extension."""
        # Mock certificate with SAN extension
        mock_san_model = Mock()
        mock_certificate = Mock(spec=CertificateModel)
        mock_certificate.subject_alternative_name_extension = Mock()
        mock_certificate.subject_alternative_name_extension.subject_alt_name = mock_san_model

        mock_credential = Mock(spec=CredentialModel)
        mock_credential.certificate = mock_certificate

        mock_active_tls = Mock()
        mock_active_tls.credential = mock_credential
        mock_active_model.objects.select_related.return_value.get.return_value = mock_active_tls

        # Mock the IP addresses query
        mock_queryset = Mock()
        mock_queryset.values_list.return_value = ['192.168.1.1', '10.0.0.1']
        mock_ip_model.objects.filter.return_value = mock_queryset

        result = self.view.get_san_ips()

        self.assertIn('192.168.1.1', result)
        self.assertIn('10.0.0.1', result)
        self.assertEqual(len(result), 2)

    @patch.object(ActiveTrustpointTlsServerCredentialModel.objects, 'select_related')
    def test_get_san_ips_handles_object_does_not_exist(self, mock_select_related):
        """Test get_san_ips handles ObjectDoesNotExist gracefully."""
        mock_select_related.return_value.get.side_effect = ActiveTrustpointTlsServerCredentialModel.DoesNotExist()

        result = self.view.get_san_ips()
        self.assertEqual(result, [])

    def test_form_valid_saves_ipv4_address(self):
        """Test form_valid saves IPv4 address to TlsSettings."""
        form = Mock(spec=IPv4AddressForm)
        form.cleaned_data = {'ipv4_address': '192.168.1.100'}

        response = self.view.form_valid(form)

        tls_settings = TlsSettings.objects.get(id=1)
        self.assertEqual(tls_settings.ipv4_address, '192.168.1.100')

        # Check success message
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('success' in str(msg).lower() for msg in messages_list))

    def test_form_invalid_shows_error(self):
        """Test form_invalid shows error message."""
        form = Mock(spec=IPv4AddressForm)

        with patch.object(self.view, 'render_to_response') as mock_render:
            self.view.form_invalid(form)

        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('invalid' in str(msg).lower() for msg in messages_list))


class TlsAddMethodSelectViewTest(TestCase):
    """Test suite for TlsAddMethodSelectView."""

    def test_template_name(self):
        """Test correct template is used."""
        view = TlsAddMethodSelectView()
        self.assertEqual(view.template_name, 'management/tls/method_select.html')

    def test_success_url(self):
        """Test success URL is set correctly."""
        view = TlsAddMethodSelectView()
        # Just verify it's a reverse_lazy object, don't try to resolve it
        self.assertIsNotNone(view.success_url)


class GenerateTlsCertificateViewTest(TestCase):
    """Test suite for GenerateTlsCertificateView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = GenerateTlsCertificateView()
        self.view.request = self.factory.get('/tls/generate/')

        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(self.view.request, 'session', 'session')
        messages_storage = FallbackStorage(self.view.request)
        setattr(self.view.request, '_messages', messages_storage)

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/tls/generate_tls.html')

    def test_form_class(self):
        """Test correct form class is used."""
        self.assertEqual(self.view.form_class, StartupWizardTlsCertificateForm)

    def test_success_url(self):
        """Test success URL is set correctly."""
        self.assertEqual(str(self.view.success_url), reverse('management:tls'))

    def test_http_method_names(self):
        """Test only GET and POST methods are allowed."""
        self.assertEqual(self.view.http_method_names, ('get', 'post'))

    @patch('management.views.tls.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    @patch('management.views.tls.TlsServerCredentialGenerator')
    @patch('management.views.tls.CredentialModel.save_credential_serializer')
    def test_form_valid_generates_credential(self, mock_save_cred, mock_generator_class, mock_get_or_create):
        """Test form_valid generates TLS server credential."""
        # Mock the generator
        mock_generator = Mock()
        mock_credential_serializer = Mock()
        mock_generator.generate_tls_server_credential.return_value = mock_credential_serializer
        mock_generator_class.return_value = mock_generator

        # Mock the saved credential with _state attribute
        mock_credential = Mock(spec=CredentialModel)
        mock_credential._state = Mock()
        mock_credential._state.db = 'default'
        mock_save_cred.return_value = mock_credential

        # Mock get_or_create
        mock_active_tls = Mock()
        mock_get_or_create.return_value = (mock_active_tls, True)

        form = Mock(spec=StartupWizardTlsCertificateForm)
        form.cleaned_data = {
            'ipv4_addresses': ['192.168.1.1'],
            'ipv6_addresses': [],
            'domain_names': ['example.com'],
        }

        response = self.view.form_valid(form)

        # Check generator was called
        mock_generator_class.assert_called_once_with(
            ipv4_addresses=['192.168.1.1'],
            ipv6_addresses=[],
            domain_names=['example.com'],
        )
        mock_generator.generate_tls_server_credential.assert_called_once()

        # Check credential was saved
        mock_save_cred.assert_called_once()

        # Check success message
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('success' in str(msg).lower() for msg in messages_list))

    @patch('management.views.tls.TlsServerCredentialGenerator')
    def test_form_valid_handles_exception(self, mock_generator_class):
        """Test form_valid handles exceptions gracefully."""
        mock_generator_class.side_effect = Exception('Test error')

        form = Mock(spec=StartupWizardTlsCertificateForm)
        form.cleaned_data = {
            'ipv4_addresses': [],
            'ipv6_addresses': [],
            'domain_names': [],
        }

        response = self.view.form_valid(form)

        # Should redirect to TLS page
        self.assertEqual(response.status_code, 302)

        # Check error message
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('error' in str(msg).lower() for msg in messages_list))


class TlsAddFileImportPkcs12ViewTest(TestCase):
    """Test suite for TlsAddFileImportPkcs12View."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = TlsAddFileImportPkcs12View()
        self.view.request = self.factory.get('/tls/import/pkcs12/')

        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(self.view.request, 'session', 'session')
        messages_storage = FallbackStorage(self.view.request)
        setattr(self.view.request, '_messages', messages_storage)

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/tls/file_import.html')

    def test_form_class(self):
        """Test correct form class is used."""
        self.assertEqual(self.view.form_class, TlsAddFileImportPkcs12Form)

    def test_success_url(self):
        """Test success URL is set correctly."""
        self.assertEqual(str(self.view.success_url), reverse('management:tls'))

    def test_form_valid_shows_success_message(self):
        """Test form_valid displays success message."""
        form = Mock(spec=TlsAddFileImportPkcs12Form)

        with patch.object(self.view, 'get_success_url', return_value='/tls/'):
            response = self.view.form_valid(form)

        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('success' in str(msg).lower() for msg in messages_list))


class TlsAddFileImportSeparateFilesViewTest(TestCase):
    """Test suite for TlsAddFileImportSeparateFilesView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = TlsAddFileImportSeparateFilesView()
        self.view.request = self.factory.get('/tls/import/separate/')

        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(self.view.request, 'session', 'session')
        messages_storage = FallbackStorage(self.view.request)
        setattr(self.view.request, '_messages', messages_storage)

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/tls/file_import.html')

    def test_form_class(self):
        """Test correct form class is used."""
        self.assertEqual(self.view.form_class, TlsAddFileImportSeparateFilesForm)

    def test_success_url(self):
        """Test success URL is set correctly."""
        self.assertEqual(str(self.view.success_url), reverse('management:tls'))

    def test_form_valid_shows_success_message(self):
        """Test form_valid displays success message."""
        form = Mock(spec=TlsAddFileImportSeparateFilesForm)

        with patch.object(self.view, 'get_success_url', return_value='/tls/'):
            response = self.view.form_valid(form)

        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('success' in str(msg).lower() for msg in messages_list))


class ActivateTlsServerViewTest(TestCase):
    """Test suite for ActivateTlsServerView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = ActivateTlsServerView()

        # Create a certificate and credential using mocks
        self.certificate = Mock(spec=CertificateModel)
        self.certificate.pk = 1
        self.certificate.id = 1

        self.credential = Mock(spec=CredentialModel)
        self.credential.id = 1

    @patch('management.views.tls.UpdateTlsCommand')
    @patch('management.views.tls.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    @patch('management.views.tls.CredentialModel.objects.get')
    def test_post_activates_credential(self, mock_cred_get, mock_get_or_create, mock_cmd_class):
        """Test POST activates TLS server credential."""
        request = self.factory.post(f'/tls/activate/{self.certificate.pk}/')
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        # Mock the credential lookup
        mock_cred_get.return_value = self.credential

        # Mock get_or_create
        mock_active_tls = Mock()
        mock_get_or_create.return_value = (mock_active_tls, True)

        # Mock the command
        mock_cmd = Mock()
        mock_cmd_class.return_value = mock_cmd

        response = self.view.post(request, pk=self.certificate.pk)

        # Check credential was looked up
        mock_cred_get.assert_called_once_with(certificate__id=self.certificate.pk)

        # Check UpdateTlsCommand was called
        mock_cmd.handle.assert_called_once()

        # Check success message
        messages_list = list(get_messages(request))
        self.assertTrue(any('activated successfully' in str(msg).lower() for msg in messages_list))

        # Check redirect
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('management:tls'))

    @patch('management.views.tls.CredentialModel.objects.get')
    def test_post_with_nonexistent_credential(self, mock_cred_get):
        """Test POST with non-existent credential ID shows error."""
        request = self.factory.post('/tls/activate/99999/')
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        # Mock credential not found
        mock_cred_get.side_effect = CredentialModel.DoesNotExist()

        response = self.view.post(request, pk=99999)

        # Check error message
        messages_list = list(get_messages(request))
        self.assertTrue(any('failed' in str(msg).lower() for msg in messages_list))

    @patch('management.views.tls.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    @patch('management.views.tls.CredentialModel.objects.get')
    def test_post_with_validation_error(self, mock_cred_get, mock_get_or_create):
        """Test POST handles ValidationError."""
        request = self.factory.post(f'/tls/activate/{self.certificate.pk}/')
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        # Mock credential lookup
        mock_cred_get.return_value = self.credential

        # Mock validation error
        mock_get_or_create.side_effect = ValidationError('Test validation error')

        response = self.view.post(request, pk=self.certificate.pk)

        # Check error message
        messages_list = list(get_messages(request))
        self.assertTrue(any('failed' in str(msg).lower() for msg in messages_list))

    @patch('management.views.tls.UpdateTlsCommand')
    @patch('management.views.tls.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    @patch('management.views.tls.CredentialModel.objects.get')
    def test_post_with_unexpected_exception(self, mock_cred_get, mock_get_or_create, mock_cmd_class):
        """Test POST handles unexpected exceptions."""
        request = self.factory.post(f'/tls/activate/{self.certificate.pk}/')
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        # Mock credential lookup
        mock_cred_get.return_value = self.credential

        # Mock get_or_create
        mock_active_tls = Mock()
        mock_get_or_create.return_value = (mock_active_tls, True)

        # Mock unexpected error
        mock_cmd_class.side_effect = Exception('Unexpected error')

        response = self.view.post(request, pk=self.certificate.pk)

        # Check error message
        messages_list = list(get_messages(request))
        self.assertTrue(any('unexpected' in str(msg).lower() for msg in messages_list))
