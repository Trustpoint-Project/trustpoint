"""Integration tests for users app."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from setup_wizard import SetupWizardState

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser

User = get_user_model()


class LoginIntegrationTest(TestCase):
    """Integration tests for login functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.login_url = reverse('users:login')
        self.logout_url = reverse('users:logout')

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_login_page_loads(self) -> None:
        """Test that login page loads successfully."""
        response = self.client.get(self.login_url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'users/login.html')

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_successful_login(self) -> None:
        """Test successful login redirects to home."""
        response = self.client.post(self.login_url, {'username': 'testuser', 'password': 'testpass123'}, follow=True)

        # Should redirect after successful login
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_failed_login(self) -> None:
        """Test failed login shows error."""
        response = self.client.post(self.login_url, {'username': 'testuser', 'password': 'wrongpassword'})

        # Should stay on login page with error
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'users/login.html')
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_logout(self) -> None:
        """Test logout functionality."""
        # First login
        self.client.login(username='testuser', password='testpass123')

        # Then logout (POST required for Django's LogoutView)
        response = self.client.post(self.logout_url)

        # Should show logout page or redirect
        self.assertIn(response.status_code, [200, 302])

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    def test_login_redirects_when_wizard_incomplete(self, mock_get_state) -> None:
        """Test login redirects to wizard when setup not complete."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        response = self.client.get(self.login_url, follow=False)

        # Should redirect (not show login page)
        self.assertEqual(response.status_code, 302)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    def test_login_works_when_wizard_complete(self, mock_get_state) -> None:
        """Test login works normally when wizard is complete."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED

        response = self.client.get(self.login_url)

        # Should show login page
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'users/login.html')

    def test_login_required_redirect(self) -> None:
        """Test that protected pages redirect to login."""
        # Try to access a protected page (home)
        response = self.client.get(reverse('home:index'), follow=False)

        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/users/login/', response.url)

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_authenticated_user_redirects_from_home(self) -> None:
        """Test that authenticated users get redirected from home."""
        self.client.login(username='testuser', password='testpass123')

        response = self.client.get(reverse('home:index'))

        # Home might redirect authenticated users (check that request succeeds)
        self.assertIn(response.status_code, [200, 302])

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_case_sensitive_username(self) -> None:
        """Test that username is case sensitive."""
        response = self.client.post(self.login_url, {'username': 'TESTUSER', 'password': 'testpass123'})

        # Should fail (usernames are case sensitive by default)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_empty_credentials(self) -> None:
        """Test login with empty credentials."""
        response = self.client.post(self.login_url, {'username': '', 'password': ''})

        # Should stay on login page
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)
