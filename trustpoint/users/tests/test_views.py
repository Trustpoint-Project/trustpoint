# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for users views."""

from __future__ import annotations

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, TestCase
from django.urls import reverse

from users.form import TrustpointPasswordChangeForm, TrustpointUserProfileForm
from users.models import BuiltinRole
from users.views import TrustpointLoginView

User = get_user_model()


class TrustpointProfileViewTest(TestCase):
    """Test suite for the dedicated user profile view."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.profile_url = reverse('users:profile')
        self.user = User.objects.create_user(username='profileuser', password='testpass123')

    def test_get_requires_login(self) -> None:
        """Authenticated access is required for the profile page."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/users/login/', response.url)

    def test_user_can_open_another_profile_with_manage_users_permission(self) -> None:
        """A user with manage-users permission can edit another user's profile."""
        other_user = User.objects.create_user(username='otheruser', password='testpass123')
        permission = Permission.objects.get(codename='manage_users')
        self.user.user_permissions.add(permission)
        self.client.force_login(self.user)

        response = self.client.get(reverse('users:user-profile', kwargs={'pk': other_user.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, other_user.username)
        self.assertContains(response, 'Account Security')
        self.assertNotContains(response, 'Current password')

    def test_manager_can_require_another_user_to_change_password(self) -> None:
        """A user manager can require another user to change password at next login."""
        other_user = User.objects.create_user(username='otheruser', password='testpass123')
        permission = Permission.objects.get(codename='manage_users')
        self.user.user_permissions.add(permission)
        self.client.force_login(self.user)
        other_profile_url = reverse('users:user-profile', kwargs={'pk': other_user.pk})

        response = self.client.post(other_profile_url, {'form_name': 'require_password_change'})

        self.assertRedirects(response, other_profile_url)
        other_user.refresh_from_db()
        self.assertTrue(other_user.must_change_password)

    def test_user_cannot_open_another_profile_without_manage_users_permission(self) -> None:
        """A regular user cannot edit another user's profile."""
        other_user = User.objects.create_user(username='otheruser', password='testpass123')
        self.client.force_login(self.user)

        response = self.client.get(reverse('users:user-profile', kwargs={'pk': other_user.pk}))

        self.assertEqual(response.status_code, 403)

    def test_get_renders_profile_page_for_authenticated_user(self) -> None:
        """The authenticated user can open their profile page."""
        self.client.force_login(self.user)

        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile')
        self.assertContains(response, self.user.username)
        self.assertContains(response, 'Registration date')
        self.assertContains(response, 'Account Security')
        self.assertContains(response, 'Current password')

    def test_get_uses_saved_user_theme(self) -> None:
        """The base page exposes the persisted theme to the theme script."""
        self.user.theme = User.ThemeChoices.LIGHT
        self.user.save(update_fields=['theme'])
        self.client.force_login(self.user)

        response = self.client.get(self.profile_url)

        self.assertContains(response, 'data-bs-theme="light"')
        self.assertContains(response, 'data-user-theme="light"')

    def test_profile_avatar_uses_name_initials(self) -> None:
        """The sidebar avatar uses both name initials when available."""
        self.user.first_name = 'Ada'
        self.user.last_name = 'Lovelace'
        self.user.save(update_fields=['first_name', 'last_name'])
        self.client.force_login(self.user)

        response = self.client.get(self.profile_url)

        self.assertContains(response, 'AL')

    def test_profile_avatar_falls_back_to_username_initial(self) -> None:
        """The sidebar avatar falls back to the username when names are absent."""
        self.client.force_login(self.user)

        response = self.client.get(self.profile_url)

        self.assertContains(response, 'P')

    def test_role_and_organization_are_read_only_without_manage_users_permission(self) -> None:
        """Users without permission can view, but cannot edit, role and organization."""
        form = TrustpointUserProfileForm(instance=self.user, user=self.user)

        self.assertIn('role', form.fields)
        self.assertIn('organization', form.fields)
        self.assertTrue(form.fields['role'].disabled)
        self.assertTrue(form.fields['organization'].disabled)

    def test_sole_admin_cannot_change_role(self) -> None:
        """The only Admin user cannot change their role from the profile page."""
        admin_group = Group.objects.create(name=BuiltinRole.ADMIN.value)
        admin_user = User.objects.create_user(username='admin', password='testpass123', role=admin_group)
        permission = Permission.objects.get(codename='manage_users')
        admin_user.user_permissions.add(permission)

        form = TrustpointUserProfileForm(instance=admin_user, user=admin_user)

        self.assertTrue(form.fields['role'].disabled)

    def test_registration_date_is_read_only(self) -> None:
        """The registration date is displayed but cannot be changed through the form."""
        form = TrustpointUserProfileForm(instance=self.user, user=self.user)

        self.assertEqual(form.fields['date_joined'].label, 'Registration date')
        self.assertTrue(form.fields['date_joined'].disabled)

    def test_password_change_requires_current_password_and_confirmation(self) -> None:
        """A valid password change verifies the current password and confirmation."""
        self.client.force_login(self.user)

        response = self.client.post(
            self.profile_url,
            {
                'form_name': 'password_change',
                'old_password': 'testpass123',
                'new_password1': 'NewTestPass456!',
                'new_password2': 'NewTestPass456!',
            },
        )

        self.assertRedirects(response, self.profile_url)
        self.assertTrue(self.client.login(username='profileuser', password='NewTestPass456!'))

    def test_password_change_rejects_incorrect_current_password(self) -> None:
        """An incorrect current password prevents a password change."""
        self.client.force_login(self.user)

        response = self.client.post(
            self.profile_url,
            {
                'form_name': 'password_change',
                'old_password': 'wrong-password',
                'new_password1': 'NewTestPass456!',
                'new_password2': 'NewTestPass456!',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Your old password was entered incorrectly.')
        self.assertTrue(self.client.login(username='profileuser', password='testpass123'))

    def test_password_change_rejects_mismatched_passwords(self) -> None:
        """A password change requires matching new-password fields."""
        form = TrustpointPasswordChangeForm(
            user=self.user,
            data={
                'old_password': 'testpass123',
                'new_password1': 'NewTestPass456!',
                'new_password2': 'DifferentPass456!',
            },
        )

        self.assertFalse(form.is_valid())
        self.assertIn('The two password fields didn’t match.', form.errors['new_password2'])

    def test_password_change_rejects_current_password_as_new_password(self) -> None:
        """A password change requires the new password to differ from the current one."""
        form = TrustpointPasswordChangeForm(
            user=self.user,
            data={
                'old_password': 'testpass123',
                'new_password1': 'testpass123',
                'new_password2': 'testpass123',
            },
        )

        self.assertFalse(form.is_valid())
        self.assertIn('The new password must differ from the current password.', form.errors['new_password1'])

    def test_user_can_require_password_change_on_next_login(self) -> None:
        """The Account Security action marks the account for the next login."""
        self.client.force_login(self.user)

        response = self.client.post(self.profile_url, {'form_name': 'require_password_change'})

        self.assertRedirects(response, self.profile_url)
        self.user.refresh_from_db()
        self.assertTrue(self.user.must_change_password)
        self.assertTrue(self.client.session.get('password_change_current_session'))

    def test_required_password_change_redirects_and_clears_flag(self) -> None:
        """A flagged user is forced to change the password and the flag is cleared."""
        self.user.must_change_password = True
        self.user.save(update_fields=['must_change_password'])
        self.client.force_login(self.user)

        response = self.client.get(self.profile_url)
        self.assertRedirects(response, reverse('users:password-change-required'))

        response = self.client.post(
            reverse('users:password-change-required'),
            {
                'old_password': 'testpass123',
                'new_password1': 'NewTestPass456!',
                'new_password2': 'NewTestPass456!',
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/')
        self.user.refresh_from_db()
        self.assertFalse(self.user.must_change_password)
        self.assertTrue(self.client.login(username='profileuser', password='NewTestPass456!'))

    def test_theme_field_is_connected_to_frontend_theme_handler(self) -> None:
        """The profile theme selector is marked for the shared theme handler."""
        form = TrustpointUserProfileForm(instance=self.user, user=self.user)

        self.assertEqual(form.fields['theme'].widget.attrs['data-theme-selector'], 'true')


class TrustpointLoginViewTest(TestCase):
    """Test suite for the simplified login view."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.login_url = reverse('users:login')
        self.user = User.objects.create_user(username='testuser', password='testpass123')

    def _attach_messages(self, request) -> None:
        request.session = self.client.session
        request._messages = FallbackStorage(request)

    def test_http_method_names(self) -> None:
        """Only GET and POST should be allowed."""
        self.assertEqual(TrustpointLoginView.http_method_names, ('get', 'post'))

    @patch('users.views.messages.get_messages')
    def test_get_clears_messages_and_renders_login(self, mock_get_messages: Mock) -> None:
        """GET should drain messages before rendering the login page."""
        mock_get_messages.return_value = []
        request = self.factory.get(self.login_url)
        request.user = Mock()
        self._attach_messages(request)

        view = TrustpointLoginView()
        view.setup(request)

        response = view.get(request)

        mock_get_messages.assert_called_once_with(request)
        self.assertEqual(response.status_code, 200)

    @patch('users.views.messages.get_messages')
    @patch('users.views.LoginView.post')
    def test_post_clears_messages_and_delegates(self, mock_super_post: Mock, mock_get_messages: Mock) -> None:
        """POST should drain messages and then delegate to Django's LoginView."""
        mock_get_messages.return_value = []
        mock_super_post.return_value = Mock(status_code=302)

        request = self.factory.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'},
        )
        request.user = Mock()
        self._attach_messages(request)

        view = TrustpointLoginView()
        view.setup(request)

        response = view.post(request)

        mock_get_messages.assert_called_once_with(request)
        mock_super_post.assert_called_once()
        self.assertEqual(response.status_code, 302)
