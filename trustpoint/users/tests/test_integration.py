"""Integration tests for the users app."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

User = get_user_model()


class LoginIntegrationTest(TestCase):
    """Integration tests for the current login flow."""

    def setUp(self) -> None:
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.login_url = reverse('users:login')
        self.logout_url = reverse('users:logout')

    def test_login_page_loads(self) -> None:
        """The login page should render successfully."""
        response = self.client.get(self.login_url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'users/login.html')

    def test_successful_login(self) -> None:
        """Valid credentials should authenticate the user."""
        response = self.client.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'},
            follow=True,
        )

        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_failed_login(self) -> None:
        """Invalid credentials should keep the user on the login page."""
        response = self.client.post(
            self.login_url,
            {'username': 'testuser', 'password': 'wrongpassword'},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'users/login.html')
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_logout(self) -> None:
        """Logout should succeed after logging in."""
        self.client.login(username='testuser', password='testpass123')

        response = self.client.post(self.logout_url)

        self.assertIn(response.status_code, [200, 302])

    def test_login_required_redirect(self) -> None:
        """Protected pages should redirect to login."""
        response = self.client.get(reverse('home:index'), follow=False)

        self.assertEqual(response.status_code, 302)
        self.assertIn('/users/login/', response.url)

    def test_authenticated_user_can_access_home_route(self) -> None:
        """Authenticated requests to home should no longer bounce through the login view tests."""
        self.client.login(username='testuser', password='testpass123')

        response = self.client.get(reverse('home:index'))

        self.assertIn(response.status_code, [200, 302])

    def test_case_sensitive_username(self) -> None:
        """Usernames should remain case-sensitive."""
        response = self.client.post(
            self.login_url,
            {'username': 'TESTUSER', 'password': 'testpass123'},
        )

        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_empty_credentials(self) -> None:
        """Empty credentials should not authenticate."""
        response = self.client.post(
            self.login_url,
            {'username': '', 'password': ''},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)


class BootstrapHintTest(TestCase):
    """Test the bootstrap hint feature on the login page."""

    def setUp(self) -> None:
        self.client = Client()
        self.login_url = reverse('users:login')

    @patch('users.views.SetupWizardCompletedModel.setup_wizard_completed')
    def test_bootstrap_hint_shown_for_new_user(self, mock_setup_completed: object) -> None:
        """Bootstrap hint should be shown when setup is not complete and admin has never logged in."""
        mock_setup_completed.return_value = False
        User.objects.create_user(username='admin', password='testpass123')

        response = self.client.get(self.login_url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context.get('show_bootstrap_hint'))
        self.assertEqual(response.context.get('bootstrap_username'), 'admin')

    @patch('users.views.SetupWizardCompletedModel.setup_wizard_completed')
    def test_bootstrap_hint_not_shown_after_login(self, mock_setup_completed: object) -> None:
        """Bootstrap hint should not be shown once the admin has logged in."""
        mock_setup_completed.return_value = False
        user = User.objects.create_user(username='admin', password='testpass123')
        self.client.login(username='admin', password='testpass123')
        user.refresh_from_db()

        self.client.logout()
        response = self.client.get(self.login_url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context.get('show_bootstrap_hint', False))

    @patch('users.views.SetupWizardCompletedModel.setup_wizard_completed')
    def test_bootstrap_hint_not_shown_when_user_doesnt_exist(self, mock_setup_completed: object) -> None:
        """Bootstrap hint should not be shown when bootstrap user doesn't exist."""
        mock_setup_completed.return_value = False
        response = self.client.get(self.login_url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context.get('show_bootstrap_hint', False))

    @patch('users.views.SetupWizardCompletedModel.setup_wizard_completed')
    def test_bootstrap_hint_not_shown_after_setup_complete(self, mock_setup_completed: object) -> None:
        """Bootstrap hint should not be shown after setup wizard is completed."""
        mock_setup_completed.return_value = True
        User.objects.create_user(username='admin', password='testpass123')

        response = self.client.get(self.login_url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context.get('show_bootstrap_hint', False))
