from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from settings.forms import PKCS11ConfigForm


class PKCS11ConfigViewTestCase(TestCase):
    def setUp(self):
        """Set up test data and authenticate the test client."""
        self.url = reverse('settings:pkcs11')
        self.valid_data = {
            'hsm_type': 'softhsm',
            'label': 'TestToken',
            'slot': 1,
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
        }
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    def test_get_request_renders_form(self):
        """Test that a GET request renders the form."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'settings/pkcs11.html')
        self.assertIsInstance(response.context['form'], PKCS11ConfigForm)

    @mock.patch('settings.forms.PKCS11ConfigForm.save_token_config')
    def test_post_request_valid_data(self, mock_save_token_config):
        """Test that a POST request with valid data saves the token configuration."""
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)  # Redirect on success
        self.assertRedirects(response, self.url)
        mock_save_token_config.assert_called_once()
        messages = list(response.wsgi_request._messages)
        self.assertIn('Token configuration saved successfully.', [str(msg) for msg in messages])

    @mock.patch('settings.forms.PKCS11ConfigForm.save_token_config')
    def test_post_request_save_failure(self, mock_save_token_config):
        """Test that a POST request with valid data but save failure shows an error."""
        mock_save_token_config.side_effect = Exception('Save failed')
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 200)  # Form redisplayed on error
        self.assertTemplateUsed(response, 'settings/pkcs11.html')
        messages = list(response.wsgi_request._messages)
        self.assertIn('Failed to save token configuration', [str(msg) for msg in messages])

    def test_post_request_invalid_data(self):
        """Test that a POST request with invalid data redisplays the form with errors."""
        invalid_data = {'hsm_type': 'invalid_type'}  # Missing required fields
        response = self.client.post(self.url, data=invalid_data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'settings/pkcs11.html')
        self.assertFalse(response.context['form'].is_valid())
        messages = list(response.wsgi_request._messages)
        self.assertIn('Please correct the errors below.', [str(msg) for msg in messages])

    def test_context_data_includes_page_title(self):
        """Test that the context data includes the page title."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('page_title', response.context)
        self.assertEqual(response.context['page_title'], 'PKCS#11 Configuration')
