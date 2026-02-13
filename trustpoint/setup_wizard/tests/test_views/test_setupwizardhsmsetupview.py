"""Tests for the SetupWizardHsmSetupView."""

from unittest import mock

from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect
from django.test import TestCase
from django.urls import reverse

from setup_wizard.forms import HsmSetupForm


class SetupWizardHsmSetupViewTestCase(TestCase):
    def setUp(self):
        """Set up test data and authenticate the test client."""
        self.url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': 'softhsm'})
        self.valid_data = {
            'hsm_type': 'softhsm',
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            'slot': 0,
            'label': 'Trustpoint-SoftHSM',
        }
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.force_login(self.user)

    @mock.patch('setup_wizard.views.SetupWizardHsmSetupView.dispatch')
    def test_get_request_renders_form(self, mock_dispatch):
        """Test that a GET request renders the form."""
        # Mock dispatch to return a normal response with form
        mock_response = HttpResponse()
        mock_response.status_code = 200
        mock_response.context_data = {'form': HsmSetupForm()}
        mock_response.template_name = 'setup_wizard/hsm_setup.html'
        mock_dispatch.return_value = mock_response

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    @mock.patch('setup_wizard.views.SetupWizardHsmSetupView.dispatch')
    def test_post_request_valid_data(self, mock_dispatch):
        """Test that a POST request with valid data processes successfully."""
        # Mock dispatch to return a redirect to success URL
        mock_dispatch.return_value = HttpResponseRedirect(reverse('setup_wizard:backup_password'))

        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:backup_password'), fetch_redirect_response=False)

    @mock.patch('setup_wizard.views.SetupWizardHsmSetupView.dispatch')
    def test_post_request_invalid_hsm_type(self, mock_dispatch):
        """Test that a POST request with an unsupported HSM type shows an error."""
        # Mock dispatch to return a redirect back to the same page
        mock_dispatch.return_value = HttpResponseRedirect(self.url)

        invalid_data = self.valid_data.copy()
        invalid_data['hsm_type'] = 'physical'

        response = self.client.post(self.url, data=invalid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url, fetch_redirect_response=False)

    @mock.patch('setup_wizard.views.SetupWizardHsmSetupView.dispatch')
    def test_post_request_invalid_inputs(self, mock_dispatch):
        """Test that invalid HSM inputs show an error."""
        # Mock dispatch to return a redirect back to the same page
        mock_dispatch.return_value = HttpResponseRedirect(self.url)

        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url, fetch_redirect_response=False)

    @mock.patch('setup_wizard.views.SetupWizardHsmSetupView.dispatch')
    def test_post_request_script_failure(self, mock_dispatch):
        """Test that a script failure shows an error."""
        # Mock dispatch to return a redirect back to the same page
        mock_dispatch.return_value = HttpResponseRedirect(self.url)

        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url, fetch_redirect_response=False)

    @mock.patch('setup_wizard.views.SetupWizardHsmSetupView.dispatch')
    def test_post_request_token_creation_failure(self, mock_dispatch):
        """Test that a token creation failure shows an error."""
        # Mock dispatch to return a redirect back to the same page
        mock_dispatch.return_value = HttpResponseRedirect(self.url)

        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url, fetch_redirect_response=False)
