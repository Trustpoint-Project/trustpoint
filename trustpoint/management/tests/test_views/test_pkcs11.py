from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from management.forms import PKCS11ConfigForm


class PKCS11ConfigFormTestCase(TestCase):
    def setUp(self):
        """Set up test data and authenticate the test client."""
        self.valid_data = {
            'hsm_type': 'softhsm',
            'label': 'TestToken',
            'slot': 1,
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
        }
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    def test_form_valid_data(self):
        """Test that the form is valid with valid data."""
        form = PKCS11ConfigForm(data=self.valid_data)
        self.assertTrue(form.is_valid())

    def test_form_invalid_data(self):
        """Test that the form is invalid with invalid data."""
        invalid_data = self.valid_data.copy()
        invalid_data['slot'] = -1
        form = PKCS11ConfigForm(data=invalid_data)
        self.assertFalse(form.is_valid())
        self.assertIn('slot', form.errors)

    @mock.patch('management.forms.PKCS11Token.objects.get_or_create')
    def test_save_token_config(self, mock_get_or_create):
        """Test that save_token_config saves the token configuration."""
        mock_token = mock.Mock()
        mock_get_or_create.return_value = (mock_token, True)
        form = PKCS11ConfigForm(data=self.valid_data)
        self.assertTrue(form.is_valid())
        token = form.save_token_config()
        self.assertEqual(token, mock_token)
        mock_get_or_create.assert_called_once_with(
            label='Trustpoint-SoftHSM',  # Cleaned data for softhsm
            defaults={
                'hsm_type': 'softhsm',
                'slot': 0,
                'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            }
        )

    def test_clean_sets_defaults_for_softhsm(self):
        """Test that clean sets defaults for softhsm."""
        data = {'hsm_type': 'softhsm'}
        form = PKCS11ConfigForm(data=data)
        self.assertTrue(form.is_valid())
        cleaned_data = form.cleaned_data
        self.assertEqual(cleaned_data['label'], 'Trustpoint-SoftHSM')
        self.assertEqual(cleaned_data['slot'], 0)
        self.assertEqual(cleaned_data['module_path'], '/usr/local/lib/libpkcs11-proxy.so')
