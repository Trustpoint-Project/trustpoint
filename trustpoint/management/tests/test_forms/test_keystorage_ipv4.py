"""Test suite for KeyStorageConfigForm and IPv4AddressForm."""
from django.core.exceptions import ValidationError
from django.test import TestCase

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel
from crypto.models import BackendKind, CryptoProviderProfileModel
from management.forms import IPv4AddressForm, KeyStorageConfigForm


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

    def test_form_fields_exist(self):
        """Test that the read-only backend summary fields exist."""
        form = KeyStorageConfigForm()
        self.assertIn('managed_crypto_backend', form.fields)
        self.assertIn('app_secret_backend', form.fields)

    def test_backend_fields_are_disabled(self):
        """Test that backend fields are read-only after setup."""
        form = KeyStorageConfigForm()
        self.assertTrue(form.fields['managed_crypto_backend'].disabled)
        self.assertTrue(form.fields['app_secret_backend'].disabled)

    def test_backend_choices(self):
        """Test that backend fields expose the current backend enums."""
        form = KeyStorageConfigForm()
        managed_choices = [choice[0] for choice in form.fields['managed_crypto_backend'].choices]
        app_secret_choices = [choice[0] for choice in form.fields['app_secret_backend'].choices]

        self.assertIn(BackendKind.SOFTWARE, managed_choices)
        self.assertIn(BackendKind.PKCS11, managed_choices)
        self.assertIn(AppSecretBackendKind.SOFTWARE, app_secret_choices)
        self.assertIn(AppSecretBackendKind.PKCS11, app_secret_choices)

    def test_form_initializes_from_active_backends(self):
        """Test that the form summarizes the configured operational backends."""
        CryptoProviderProfileModel.objects.create(name='software', backend_kind=BackendKind.SOFTWARE, active=True)
        app_secret_backend = AppSecretBackendModel.get_singleton()
        app_secret_backend.backend_kind = AppSecretBackendKind.SOFTWARE
        app_secret_backend.save()

        form = KeyStorageConfigForm()

        self.assertEqual(form.fields['managed_crypto_backend'].initial, BackendKind.SOFTWARE)
        self.assertEqual(form.fields['app_secret_backend'].initial, AppSecretBackendKind.SOFTWARE)

    def test_form_valid_with_no_posted_changes(self):
        """Test the read-only summary form can validate without changes."""
        form = KeyStorageConfigForm(data={})
        self.assertTrue(form.is_valid())

    def test_save_with_commit_is_rejected(self):
        """Test post-setup backend mutation through management is rejected."""
        form = KeyStorageConfigForm(data={})

        with self.assertRaises(ValidationError):
            form.save_with_commit()

    def test_save_without_commit_is_rejected(self):
        """Test post-setup backend mutation through management is rejected."""
        form = KeyStorageConfigForm(data={})

        with self.assertRaises(ValidationError):
            form.save_without_commit()

    def test_form_initialization(self):
        """Test form initializes correctly."""
        form = KeyStorageConfigForm()
        self.assertIsNotNone(form.fields)

    def test_managed_backend_field_has_label(self):
        """Test that managed backend field has a useful label."""
        form = KeyStorageConfigForm()
        label = str(form.fields['managed_crypto_backend'].label)
        self.assertIn('Managed Crypto Backend', label)

    def test_app_secret_backend_field_has_label(self):
        """Test that app-secret backend field has a useful label."""
        form = KeyStorageConfigForm()
        label = str(form.fields['app_secret_backend'].label)
        self.assertIn('Application-Secret Backend', label)
