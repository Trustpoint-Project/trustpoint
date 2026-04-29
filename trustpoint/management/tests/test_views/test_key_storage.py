"""Test suite for key_storage views."""

from django.contrib.messages import get_messages
from django.test import RequestFactory, TestCase

from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    Pkcs11AuthSource,
    SoftwareKeyEncryptionSource,
)
from management.views.key_storage import KeyStorageConfigView


class KeyStorageConfigViewTest(TestCase):
    """Test suite for KeyStorageConfigView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = KeyStorageConfigView()
        self.view.request = self.factory.get('/key-storage/')
        
        # Enable message storage for the request
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(self.view.request, 'session', 'session')
        messages_storage = FallbackStorage(self.view.request)
        setattr(self.view.request, '_messages', messages_storage)

    def test_template_name(self):
        """Test that the correct template is used."""
        self.assertEqual(self.view.template_name, 'management/key_storage.html')

    def test_extra_context_has_page_category(self):
        """Test extra_context has correct page_category."""
        self.assertEqual(self.view.extra_context['page_category'], 'management')

    def test_extra_context_has_page_name(self):
        """Test extra_context has correct page_name."""
        self.assertEqual(self.view.extra_context['page_name'], 'key_storage')

    def test_get_context_data_with_software_config(self):
        """Test get_context_data with an active software backend profile."""
        profile = CryptoProviderProfileModel.objects.create(
            name='software',
            backend_kind=BackendKind.SOFTWARE,
            active=True,
        )
        software_config = CryptoProviderSoftwareConfigModel.objects.create(
            profile=profile,
            encryption_source=SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
            encryption_source_ref='dev',
        )

        context = self.view.get_context_data()

        self.assertEqual(context['crypto_profile'], profile)
        self.assertEqual(context['software_config'], software_config)
        self.assertTrue(context['is_software_backend'])
        self.assertIn('page_title', context)

    def test_get_context_data_with_softhsm_config(self):
        """Test get_context_data with a PKCS#11 backend profile."""
        profile = CryptoProviderProfileModel.objects.create(
            name='pkcs11',
            backend_kind=BackendKind.PKCS11,
            active=True,
        )
        pkcs11_config = CryptoProviderPkcs11ConfigModel.objects.create(
            profile=profile,
            module_path='/usr/lib/libpkcs11-proxy.so',
            token_label='test-token',
            slot_id=0,
            auth_source=Pkcs11AuthSource.FILE,
            auth_source_ref='/tmp/pin',
        )

        context = self.view.get_context_data()

        self.assertEqual(context['crypto_profile'], profile)
        self.assertEqual(context['pkcs11_config'], pkcs11_config)
        self.assertTrue(context['is_pkcs11_backend'])
        self.assertEqual(context['pkcs11_token_serial_display'], '-')
        self.assertEqual(context['pkcs11_slot_id_display'], 0)

    def test_get_context_data_with_physical_hsm_config(self):
        """Test get_context_data displays configured token serial and slot."""
        profile = CryptoProviderProfileModel.objects.create(
            name='physical-pkcs11',
            backend_kind=BackendKind.PKCS11,
            active=True,
        )
        pkcs11_config = CryptoProviderPkcs11ConfigModel.objects.create(
            profile=profile,
            module_path='/opt/vendor/libpkcs11.so',
            token_serial='serial-1',
            slot_id=1,
            auth_source=Pkcs11AuthSource.FILE,
            auth_source_ref='/tmp/pin',
        )

        context = self.view.get_context_data()

        self.assertEqual(context['pkcs11_config'], pkcs11_config)
        self.assertEqual(context['pkcs11_token_serial_display'], 'serial-1')
        self.assertEqual(context['pkcs11_slot_id_display'], 1)

    def test_get_context_data_with_hsm_but_no_config_reference(self):
        """Test get_context_data with PKCS#11 profile but missing config relation."""
        CryptoProviderProfileModel.objects.create(name='pkcs11', backend_kind=BackendKind.PKCS11, active=True)

        context = self.view.get_context_data()

        self.assertTrue(context['is_pkcs11_backend'])
        self.assertIsNone(context['pkcs11_config'])
        self.assertEqual(context['pkcs11_token_serial_display'], '-')

    def test_get_context_data_with_hsm_no_tokens_at_all(self):
        """Test get_context_data without any crypto profile."""

        context = self.view.get_context_data()

        self.assertIsNone(context['crypto_profile'])
        self.assertIsNone(context['pkcs11_config'])

    def test_get_context_data_no_config_exists(self):
        """Test get_context_data when no crypto backend profile exists."""
        context = self.view.get_context_data()

        self.assertIn('crypto_profile', context)
        self.assertIsNone(context['crypto_profile'])

        messages_list = list(get_messages(self.view.request))
        self.assertEqual(len(messages_list), 1)
        self.assertIn('No configured crypto backend profile', str(messages_list[0]))

    def test_get_context_data_preserves_parent_context(self):
        """Test get_context_data preserves context from parent class."""
        context = self.view.get_context_data(custom_key='custom_value')

        self.assertIn('custom_key', context)
        self.assertEqual(context['custom_key'], 'custom_value')

    def test_key_storage_config_view_inherits_from_template_view(self):
        """Test KeyStorageConfigView is a TemplateView."""
        from django.views.generic import TemplateView
        self.assertTrue(issubclass(KeyStorageConfigView, TemplateView))
