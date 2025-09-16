from unittest import mock

from django.test import TestCase

from settings.forms import PKCS11ConfigForm
from settings.models import PKCS11Token


class PKCS11ConfigFormTestCase(TestCase):
    def setUp(self):
        """Set up a PKCS11Token instance for testing."""
        self.token = PKCS11Token.objects.create(
            hsm_type='softhsm',
            label='TestToken',
            slot=1,
            module_path='/usr/local/lib/libpkcs11-proxy.so',
        )

    def test_form_initialization_with_existing_token(self):
        """Test that the form initializes with existing token data."""
        form = PKCS11ConfigForm()
        self.assertEqual(form.fields['hsm_type'].initial, self.token.hsm_type)
        self.assertEqual(form.fields['label'].initial, self.token.label)
        self.assertEqual(form.fields['slot'].initial, self.token.slot)
        self.assertEqual(form.fields['module_path'].initial, self.token.module_path)

    def test_form_initialization_without_existing_token(self):
        """Test that the form initializes with default values if no token exists."""
        PKCS11Token.objects.all().delete()
        form = PKCS11ConfigForm()
        self.assertEqual(form.fields['hsm_type'].initial, 'softhsm')
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

    def test_clean_with_physical_hsm(self):
        """Test that the form raises an error for unsupported physical HSM."""
        form = PKCS11ConfigForm(data={'hsm_type': 'physical'})
        self.assertFalse(form.is_valid())
        self.assertIn('Physical HSM is not yet supported.', form.errors['__all__'])

    def test_clean_label_unique(self):
        """Test that the form validates unique labels."""
        # Create a token with a duplicate label
        PKCS11Token.objects.create(
            hsm_type='softhsm',
            label='DuplicateToken',
            slot=2,
            module_path='/usr/local/lib/libpkcs11-proxy.so',
        )

        # Attempt to create a new token with the same label
        form = PKCS11ConfigForm(data={'hsm_type': 'softhsm', 'label': 'DuplicateToken'})
        self.assertTrue(form.is_valid())  # SoftHSM always uses 'Trustpoint-SoftHSM'

        # Attempt to create a new token with a different hsm_type
        form = PKCS11ConfigForm(data={'hsm_type': 'physical', 'label': 'DuplicateToken'})
        self.assertFalse(form.is_valid())
        self.assertIn('A token with this label already exists.', form.errors['label'])

        @mock.patch('settings.models.PKCS11Token.objects.get_or_create')
        def test_save_token_config_create(self, mock_get_or_create):
            """Test that the form creates a new token configuration."""
            new_token = PKCS11Token(
                hsm_type='softhsm',
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

    @mock.patch('settings.models.PKCS11Token.objects.get_or_create')
    def test_save_token_config_update_softhsm(self, mock_get_or_create):
        """Test that the form updates an existing SoftHSM token configuration."""
        # Create a token with the expected SoftHSM label
        softhsm_token = PKCS11Token(
            hsm_type='softhsm',
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
