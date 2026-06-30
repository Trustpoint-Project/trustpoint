from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import TestCase

from management.forms import PKCS11ConfigForm


class PKCS11ConfigFormTestCase(TestCase):
    def setUp(self):
        """Set up test data and authenticate the test client."""
        self.valid_data = {
            'hsm_type': 'softhsm',
            'label': 'TestToken',
            'slot': 1,
            'module_path': '/usr/lib/libpkcs11-proxy.so',
        }
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    def test_form_valid_data(self):
        """Test that the form is valid with valid data."""
        form = PKCS11ConfigForm(data=self.valid_data)
        self.assertTrue(form.is_valid())

    def test_form_ignores_posted_mutations(self):
        """Test that posted values do not mutate the disabled summary fields."""
        form = PKCS11ConfigForm(data=self.valid_data)
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['token_label'], '')
        self.assertIsNone(form.cleaned_data['slot_id'])
        self.assertEqual(form.cleaned_data['module_path'], '')

    def test_save_token_config(self):
        """Test that save_token_config rejects post-setup mutation."""
        form = PKCS11ConfigForm(data=self.valid_data)
        self.assertTrue(form.is_valid())

        with self.assertRaises(ValidationError):
            form.save_token_config()

    def test_read_only_fields_exist(self):
        """Test that the form exposes the configured backend summary fields."""
        form = PKCS11ConfigForm(data={})

        self.assertIn('token_label', form.fields)
        self.assertIn('slot_id', form.fields)
        self.assertIn('module_path', form.fields)
        self.assertIn('auth_source_ref', form.fields)
