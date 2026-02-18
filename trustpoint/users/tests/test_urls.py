"""Tests for users URL configuration."""

from __future__ import annotations

from django.test import SimpleTestCase
from django.urls import resolve, reverse

from users.views import TrustpointLoginView


class UsersUrlsTest(SimpleTestCase):
    """Test suite for users URL configuration."""

    def test_login_url_resolves(self) -> None:
        """Test that login URL resolves to correct view."""
        url = reverse('users:login')
        self.assertEqual(url, '/users/login/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'users:login')
        self.assertEqual(resolver.func.view_class, TrustpointLoginView)

    def test_logout_url_resolves(self) -> None:
        """Test that logout URL resolves to correct view."""
        url = reverse('users:logout')
        self.assertEqual(url, '/users/logout/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'users:logout')
        # LogoutView is a standard Django view
        self.assertIn('LogoutView', str(resolver.func.view_class))

    def test_login_url_name(self) -> None:
        """Test that login URL has correct name."""
        url = reverse('users:login')
        resolver = resolve(url)
        self.assertEqual(resolver.url_name, 'login')

    def test_logout_url_name(self) -> None:
        """Test that logout URL has correct name."""
        url = reverse('users:logout')
        resolver = resolve(url)
        self.assertEqual(resolver.url_name, 'logout')

    def test_app_name(self) -> None:
        """Test that app name is correctly set."""
        url = reverse('users:login')
        resolver = resolve(url)
        self.assertEqual(resolver.app_name, 'users')
