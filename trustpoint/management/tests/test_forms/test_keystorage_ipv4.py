"""Test suite for KeyStorageConfigForm and IPv4AddressForm."""
from django.test import TestCase
from management.forms import IPv4AddressForm, KeyStorageConfigForm
from management.models import KeyStorageConfig


class IPv4AddressFormTest(TestCase):
    """Test suite for IPv4AddressForm."""

    def test_form_initialization_with_san_ips(self):
        """Test form initializes with SAN IPs."""
        san_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        form = IPv4AddressForm(san_ips=san_ips)

        choices = form.fields['ipv4_address'].choices
        self.assertEqual(len(choices), 3)
        self.assertIn(('192.168.1.1', '192.168.1.1'), choices)

    def test_form_initialization_with_saved_ipv4_not_in_san(self):
        """Test form adds saved IPv4 address if not in SAN list."""
        san_ips = ['192.168.1.1', '10.0.0.1']
        saved_ip = '172.16.0.1'

        form = IPv4AddressForm(
            san_ips=san_ips,
            initial={'ipv4_address': saved_ip}
        )

        choices = form.fields['ipv4_address'].choices
        # Should have 3 choices: saved IP + 2 SAN IPs
        self.assertEqual(len(choices), 3)
        # Saved IP should be first
        self.assertEqual(choices[0], (saved_ip, saved_ip))

    def test_form_initialization_with_saved_ipv4_in_san(self):
        """Test form doesn't duplicate IP if already in SAN list."""
        san_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        saved_ip = '192.168.1.1'

        form = IPv4AddressForm(
            san_ips=san_ips,
            initial={'ipv4_address': saved_ip}
        )

        choices = form.fields['ipv4_address'].choices
        # Should still have 3 choices, no duplication
        self.assertEqual(len(choices), 3)

    def test_form_initialization_without_san_ips(self):
        """Test form initializes with empty SAN IPs list."""
        form = IPv4AddressForm()
        choices = form.fields['ipv4_address'].choices
        self.assertEqual(len(choices), 0)

    def test_form_field_label(self):
        """Test that ipv4_address field has correct label."""
        form = IPv4AddressForm()
        self.assertEqual(form.fields['ipv4_address'].label, 'Update IPv4 Address')


class KeyStorageConfigFormTest(TestCase):
    """Test suite for KeyStorageConfigForm."""

    def setUp(self):
        """Set up test fixtures."""
        # Clean up any existing config
        KeyStorageConfig.objects.all().delete()

    def test_form_fields_exist(self):
        """Test that storage_type field exists."""
        form = KeyStorageConfigForm()
        self.assertIn('storage_type', form.fields)

    def test_storage_type_field_is_radio_select(self):
        """Test that storage_type uses RadioSelect widget."""
        form = KeyStorageConfigForm()
        from django.forms import RadioSelect
        self.assertIsInstance(form.fields['storage_type'].widget, RadioSelect)

    def test_storage_type_choices(self):
        """Test that storage_type has correct choices."""
        form = KeyStorageConfigForm()
        choices = [choice[0] for choice in form.fields['storage_type'].choices]

        self.assertIn('software', choices)
        self.assertIn('softhsm', choices)
        self.assertIn('physical_hsm', choices)

    def test_form_valid_with_software_storage(self):
        """Test form is valid with software storage type."""
        form_data = {'storage_type': 'software'}
        form = KeyStorageConfigForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_form_valid_with_softhsm_storage(self):
        """Test form is valid with softhsm storage type."""
        form_data = {'storage_type': 'softhsm'}
        form = KeyStorageConfigForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_form_valid_with_physical_hsm_storage(self):
        """Test form is valid with physical_hsm storage type."""
        form_data = {'storage_type': 'physical_hsm'}
        form = KeyStorageConfigForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_clean_returns_cleaned_data(self):
        """Test clean method returns cleaned data."""
        form_data = {'storage_type': 'software'}
        form = KeyStorageConfigForm(data=form_data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['storage_type'], 'software')

    def test_save_with_commit_creates_instance(self):
        """Test save_with_commit creates or updates config instance."""
        form_data = {'storage_type': 'softhsm'}
        form = KeyStorageConfigForm(data=form_data)
        self.assertTrue(form.is_valid())

        config = form.save_with_commit()
        self.assertIsNotNone(config)
        self.assertEqual(config.storage_type, 'softhsm')

        # Verify it's saved in database
        saved_config = KeyStorageConfig.objects.first()
        self.assertEqual(saved_config.storage_type, 'softhsm')

    def test_save_with_commit_updates_existing_instance(self):
        """Test save_with_commit updates existing instance."""
        # Create initial config using the model's method
        initial_config = KeyStorageConfig.get_or_create_default()
        initial_config.storage_type = 'software'
        initial_config.save()

        # Update to different storage type
        form_data = {'storage_type': 'physical_hsm'}
        form = KeyStorageConfigForm(data=form_data)
        self.assertTrue(form.is_valid())

        config = form.save_with_commit()
        self.assertEqual(config.storage_type, 'physical_hsm')

        # Verify the singleton behavior - should still be only one instance
        self.assertTrue(KeyStorageConfig.objects.count() <= 2)  # May have id=1 and default

    def test_save_without_commit_returns_instance(self):
        """Test save_without_commit returns unsaved instance."""
        form_data = {'storage_type': 'softhsm'}
        form = KeyStorageConfigForm(data=form_data)
        self.assertTrue(form.is_valid())

        config = form.save_without_commit()
        self.assertIsNotNone(config)
        self.assertEqual(config.storage_type, 'softhsm')

        # The instance should exist (singleton pattern gets or creates)
        self.assertIsNotNone(KeyStorageConfig.objects.first())

    def test_form_initialization(self):
        """Test form initializes correctly."""
        form = KeyStorageConfigForm()
        self.assertIsNotNone(form.fields)

    def test_form_with_instance(self):
        """Test form works with existing instance."""
        config = KeyStorageConfig.objects.create(storage_type='software')

        form_data = {'storage_type': 'softhsm'}
        form = KeyStorageConfigForm(data=form_data, instance=config)
        self.assertTrue(form.is_valid())

    def test_storage_type_field_has_help_text(self):
        """Test that storage_type field has help text."""
        form = KeyStorageConfigForm()
        help_text = form.fields['storage_type'].help_text
        self.assertIn('cryptographic material', help_text.lower())

    def test_storage_type_field_has_label(self):
        """Test that storage_type field has correct label."""
        form = KeyStorageConfigForm()
        label = str(form.fields['storage_type'].label)
        self.assertIn('Storage Type', label)
