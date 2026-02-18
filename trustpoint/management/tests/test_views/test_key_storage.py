"""Test suite for key_storage views."""

from django.contrib.messages import get_messages
from django.test import RequestFactory, TestCase
from management.models import KeyStorageConfig, PKCS11Token
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
        """Test get_context_data with KeyStorageConfig in software storage mode."""
        config = KeyStorageConfig.objects.create(pk=1, storage_type=KeyStorageConfig.StorageType.SOFTWARE)

        context = self.view.get_context_data()

        self.assertIn('config', context)
        self.assertEqual(context['config'], config)
        self.assertIn('page_title', context)

    def test_get_context_data_with_softhsm_config(self):
        """Test get_context_data with SoftHSM storage type."""
        token = PKCS11Token.objects.create(
            label='test-token',
            slot=0,
        )
        config = KeyStorageConfig.objects.create(
            pk=1,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            hsm_config=token,
        )

        context = self.view.get_context_data()

        self.assertIn('config', context)
        self.assertEqual(context['config'], config)
        self.assertIn('hsm_config', context)
        self.assertEqual(context['hsm_config'], token)

    def test_get_context_data_with_physical_hsm_config(self):
        """Test get_context_data with physical HSM storage type."""
        token = PKCS11Token.objects.create(
            label='physical-token',
            slot=1,
        )
        config = KeyStorageConfig.objects.create(
            pk=1,
            storage_type=KeyStorageConfig.StorageType.PHYSICAL_HSM,
            hsm_config=token,
        )

        context = self.view.get_context_data()

        self.assertIn('hsm_config', context)
        self.assertEqual(context['hsm_config'], token)

    def test_get_context_data_with_hsm_but_no_config_reference(self):
        """Test get_context_data with HSM type but no hsm_config set."""
        token = PKCS11Token.objects.create(
            label='orphan-token',
            slot=2,
        )
        KeyStorageConfig.objects.create(
            pk=1,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            hsm_config=None,  # No config reference
        )

        context = self.view.get_context_data()

        # Should fall back to first token
        self.assertIn('hsm_config', context)
        self.assertEqual(context['hsm_config'], token)

    def test_get_context_data_with_hsm_no_tokens_at_all(self):
        """Test get_context_data with HSM type but no tokens in database."""
        KeyStorageConfig.objects.create(
            pk=1,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            hsm_config=None,
        )

        context = self.view.get_context_data()

        self.assertIn('hsm_config', context)
        self.assertIsNone(context['hsm_config'])

    def test_get_context_data_no_config_exists(self):
        """Test get_context_data when no KeyStorageConfig exists."""
        context = self.view.get_context_data()

        self.assertIn('config', context)
        self.assertIsNone(context['config'])

        # Check warning message was added
        messages_list = list(get_messages(self.view.request))
        self.assertEqual(len(messages_list), 1)
        self.assertIn('not found', str(messages_list[0]))

    def test_get_context_data_preserves_parent_context(self):
        """Test get_context_data preserves context from parent class."""
        KeyStorageConfig.objects.create(pk=1, storage_type=KeyStorageConfig.StorageType.SOFTWARE)

        context = self.view.get_context_data(custom_key='custom_value')

        self.assertIn('custom_key', context)
        self.assertEqual(context['custom_key'], 'custom_value')

    def test_key_storage_config_view_inherits_from_template_view(self):
        """Test KeyStorageConfigView is a TemplateView."""
        from django.views.generic import TemplateView

        self.assertTrue(issubclass(KeyStorageConfigView, TemplateView))
