from unittest import mock

from django.test import TestCase

from management.forms import PKCS11ConfigForm
from management.models import PKCS11Token


class PKCS11ConfigFormTestCase(TestCase):
    def setUp(self):
        """Set up test environment."""
        # Clear any existing tokens
        PKCS11Token.objects.all().delete()

    def test_form_initialization_with_existing_token(self):
        """Test that the form initializes with existing token data."""
        # Create a token
        existing_token = PKCS11Token.objects.create(
            label='Trustpoint-SoftHSM',
            slot=0,
            module_path='/usr/local/lib/libpkcs11-proxy.so',
        )
        form = PKCS11ConfigForm()
        self.assertEqual(form.fields['label'].initial, existing_token.label)
        self.assertEqual(form.fields['slot'].initial, existing_token.slot)
        self.assertEqual(form.fields['module_path'].initial, existing_token.module_path)

    def test_form_initialization_without_existing_token(self):
        """Test that the form initializes with default values if no token exists."""
        form = PKCS11ConfigForm()
        self.assertIsNone(form.fields['label'].initial)
        self.assertIsNone(form.fields['slot'].initial)
        self.assertEqual(form.fields['module_path'].initial, '/usr/local/lib/libpkcs11-proxy.so')

    def test_clean_with_softhsm(self):
        """Test that the form sets default values for SoftHSM."""
        form = PKCS11ConfigForm(data={'hsm_type': 'softhsm'})
        self.assertTrue(form.is_valid())
        cleaned_data = form.clean()
        self.assertEqual(cleaned_data['label'], 'Trustpoint-SoftHSM')
        self.assertEqual(cleaned_data['slot'], 0)
        self.assertEqual(cleaned_data['module_path'], '/usr/local/lib/libpkcs11-proxy.so')

    def test_clean_label_unique(self):
        """Test that the form always uses the SoftHSM label."""
        form = PKCS11ConfigForm(data={'hsm_type': 'softhsm', 'label': 'SomeOtherLabel'})
        self.assertTrue(form.is_valid())
        cleaned_data = form.clean()
        self.assertEqual(cleaned_data['label'], 'Trustpoint-SoftHSM')

    @mock.patch('management.models.PKCS11Token.objects.get_or_create')
    def test_save_token_config_create(self, mock_get_or_create):
        """Test that the form creates a new token configuration."""
        new_token = PKCS11Token(
            label='Trustpoint-SoftHSM',
            slot=0,
            module_path='/usr/local/lib/libpkcs11-proxy.so',
        )
        mock_get_or_create.return_value = (new_token, True)

        form = PKCS11ConfigForm(
            data={
                'hsm_type': 'softhsm',
                'label': 'NewToken',  # This will be ignored
                'slot': 3,  # This will be overridden
                'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            }
        )
        self.assertTrue(form.is_valid())
        result = form.save_token_config()

        # Check that get_or_create was called with the correct parameters
        mock_get_or_create.assert_called_once_with(
            label='Trustpoint-SoftHSM',
            defaults={
                'hsm_type': 'softhsm',
                'slot': 0,
                'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            }
        )
        self.assertEqual(result, new_token)

    @mock.patch('management.models.PKCS11Token.objects.get_or_create')
    def test_save_token_config_update_softhsm(self, mock_get_or_create):
        """Test that the form updates an existing SoftHSM token configuration."""
        # Create a token with the expected SoftHSM label
        softhsm_token = PKCS11Token(
            label='Trustpoint-SoftHSM',
            slot=0,
            module_path='/usr/local/lib/libpkcs11-proxy.so',
        )
        mock_get_or_create.return_value = (softhsm_token, False)

        form = PKCS11ConfigForm(
            data={
                'hsm_type': 'softhsm',
                'slot': 2,  # This will be overridden to 0 for SoftHSM
                'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            }
        )
        self.assertTrue(form.is_valid())
        token = form.save_token_config()

        # For SoftHSM, the form enforces specific default values
        self.assertEqual(token.label, 'Trustpoint-SoftHSM')
        self.assertEqual(token.slot, 0)  # SoftHSM always uses slot 0
        self.assertEqual(token.module_path, '/usr/local/lib/libpkcs11-proxy.so')

        # Verify the method was called with the correct parameters
        mock_get_or_create.assert_called_once_with(
            label='Trustpoint-SoftHSM',
            defaults={
                'hsm_type': 'softhsm',
                'slot': 0,
                'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            }
        )
