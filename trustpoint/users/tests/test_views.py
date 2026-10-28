# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for users views."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import Mock, patch

from django.contrib.auth import BACKEND_SESSION_KEY, get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.messages.storage.fallback import FallbackStorage
from django.template import Context, Template
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from management.models import PasswordPolicy
from users.form import TrustpointPasswordChangeForm, TrustpointUserProfileForm
from users.models import BuiltinRole, UserOTPDevice, UserOTPRecoveryCode
from users.views import OTP_LOGIN_TIMEOUT, PENDING_OTP_SESSION_KEY, TrustpointLoginView

User = get_user_model()


class TrustpointProfileViewTest(TestCase):
    """Test suite for the dedicated user profile view."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.profile_url = reverse('users:profile')
        self.password_change_url = reverse('users:profile_password')
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

    def test_manager_can_set_another_users_password(self) -> None:
        """A user manager can set a human user's password without their current password."""
        other_user = User.objects.create_user(username='otheruser', password='testpass123')
        permission = Permission.objects.get(codename='manage_users')
        self.user.user_permissions.add(permission)
        self.client.force_login(self.user)
        password_url = reverse('users:user-profile-password', kwargs={'pk': other_user.pk})

        response = self.client.get(password_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, other_user.username)
        self.assertNotContains(response, 'Current password')

        response = self.client.post(
            password_url,
            {'new_password1': 'ManagerSetPass456!', 'new_password2': 'ManagerSetPass456!'},
        )

        self.assertRedirects(response, reverse('users:user-profile', kwargs={'pk': other_user.pk}))
        other_user.refresh_from_db()
        self.assertTrue(other_user.check_password('ManagerSetPass456!'))

    def test_user_without_manage_permission_cannot_set_another_users_password(self) -> None:
        """A regular user cannot open the manager password-reset view."""
        other_user = User.objects.create_user(username='otheruser', password='testpass123')
        self.client.force_login(self.user)

        response = self.client.get(reverse('users:user-profile-password', kwargs={'pk': other_user.pk}))

        self.assertEqual(response.status_code, 403)

    def test_get_renders_profile_page_for_authenticated_user(self) -> None:
        """The authenticated user can open their profile page."""
        self.client.force_login(self.user)

        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile')
        self.assertContains(response, self.user.username)
        self.assertContains(response, 'Registration date')
        self.assertContains(response, 'Last login')
        self.assertContains(response, 'Account Security')
        self.assertContains(response, 'Change Password')
        self.assertContains(response, 'User Interface')
        self.assertContains(response, 'Standard View')
        self.assertContains(response, 'Simplified View')

    def test_view_mode_defaults_to_standard(self) -> None:
        """New users use the standard dashboard view by default."""
        self.assertEqual(self.user.view_mode, User.ViewModeChoices.STANDARD)

        form = TrustpointUserProfileForm(instance=self.user, user=self.user)

        self.assertEqual(form.initial['view_mode'], User.ViewModeChoices.STANDARD)

    def test_saving_simplified_view_mode_redirects_to_user_dashboard(self) -> None:
        """Saving Simplified View applies it immediately for the current user."""
        self.client.force_login(self.user)

        response = self.client.post(
            self.profile_url,
            {
                'form_name': 'profile',
                'first_name': '',
                'last_name': '',
                'email': '',
                'language': 'en',
                'timezone': 'UTC',
                'date_format': '6',
                'theme': 'dark',
                'view_mode': User.ViewModeChoices.SIMPLIFIED,
            },
        )

        self.assertRedirects(response, reverse('home:index'), fetch_redirect_response=False)
        self.user.refresh_from_db()
        self.assertEqual(self.user.view_mode, User.ViewModeChoices.SIMPLIFIED)

        dashboard_response = self.client.get(reverse('home:index'))
        self.assertRedirects(dashboard_response, reverse('home:simplified_overview'), fetch_redirect_response=False)

    def test_login_routes_simplified_user_to_simplified_view(self) -> None:
        """Login enters the user-aware dashboard selector for simplified users."""
        self.user.view_mode = User.ViewModeChoices.SIMPLIFIED
        self.user.save(update_fields=['view_mode'])

        response = self.client.post(
            reverse('users:login'),
            {'username': 'profileuser', 'password': 'testpass123'},
        )

        self.assertRedirects(response, reverse('home:index'), fetch_redirect_response=False)
        dashboard_response = self.client.get(reverse('home:index'))
        self.assertRedirects(dashboard_response, reverse('home:simplified_overview'), fetch_redirect_response=False)

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

    def test_last_login_is_read_only(self) -> None:
        """The last login timestamp is displayed but cannot be edited."""
        form = TrustpointUserProfileForm(instance=self.user, user=self.user)

        self.assertEqual(form.fields['last_login'].label, 'Last login')
        self.assertTrue(form.fields['last_login'].disabled)

    def test_password_change_requires_current_password_and_confirmation(self) -> None:
        """A valid password change verifies the current password and confirmation."""
        self.client.force_login(self.user)

        response = self.client.post(
            self.password_change_url,
            {
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
            self.password_change_url,
            {
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

    def test_regular_user_cannot_require_password_change_on_self(self) -> None:
        """Only user managers can require an account to change its password."""
        self.client.force_login(self.user)

        response = self.client.post(self.profile_url, {'form_name': 'require_password_change'})

        self.assertEqual(response.status_code, 403)
        self.user.refresh_from_db()
        self.assertFalse(self.user.must_change_password)

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

    def test_date_format_is_applied_to_local_datetime_filter(self) -> None:
        """The selected user date format is used by shared datetime templates."""
        self.user.date_format = User.DateFormatChoices.DD_MM_YYYY_24
        self.user.timezone = 'UTC'
        self.user.save(update_fields=['date_format', 'timezone'])
        from management.i18n_context import reset_current_user, set_current_user

        user_token = set_current_user(self.user)
        try:
            template = Template('{% load internationalization_tags %}{{ value|local_datetime }}')
            rendered = template.render(Context({'value': datetime(2025, 12, 31, 13, 45)}))
        finally:
            reset_current_user(user_token)

        self.assertEqual(rendered, '31/12/2025 13:45')


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


@override_settings(TRUSTPOINT_IS_OPERATIONAL=True, TRUSTPOINT_IS_BOOTSTRAP=False)
class TrustpointOTPLoginSecurityTest(TestCase):
    """Protect password-to-OTP state transitions and web-login account boundaries."""

    def setUp(self) -> None:
        self.login_url = reverse('users:login')
        self.otp_url = reverse('users:otp')
        self.user = User.objects.create_user(username='otp-user', password='StrongPass123!')
        self.policy = PasswordPolicy.objects.create(require_otp=True)

    def start_otp_login(self) -> None:
        """Submit a correct password and assert that authentication is still pending."""
        response = self.client.post(
            self.login_url,
            {'username': self.user.username, 'password': 'StrongPass123!'},
        )
        self.assertRedirects(response, self.otp_url, fetch_redirect_response=False)
        assert PENDING_OTP_SESSION_KEY in self.client.session
        assert '_auth_user_id' not in self.client.session

    def confirmed_device(self) -> UserOTPDevice:
        """Create an already-enrolled authenticator suitable for login-flow tests."""
        return UserOTPDevice.objects.create(user=self.user, confirmed=True, last_t=0)

    def test_password_login_creates_anonymous_pending_state_and_enrollment_device(self) -> None:
        """A password alone must not authenticate when OTP is required."""
        self.start_otp_login()

        device = UserOTPDevice.objects.get(user=self.user)
        assert not device.confirmed
        pending = self.client.session[PENDING_OTP_SESSION_KEY]
        assert pending['user_id'] == self.user.pk
        assert pending['device_id'] == device.pk
        assert pending['enrolling'] is True

    def test_expired_pending_otp_state_is_rejected_and_removed(self) -> None:
        """Password proof cannot be replayed after the five-minute OTP window."""
        self.confirmed_device()
        self.start_otp_login()
        session = self.client.session
        pending = session[PENDING_OTP_SESSION_KEY]
        pending['issued_at'] -= OTP_LOGIN_TIMEOUT
        session[PENDING_OTP_SESSION_KEY] = pending
        session.save()

        response = self.client.get(self.otp_url)

        self.assertRedirects(response, self.login_url, fetch_redirect_response=False)
        assert PENDING_OTP_SESSION_KEY not in self.client.session
        assert '_auth_user_id' not in self.client.session

    def test_tampered_password_auth_hash_is_rejected(self) -> None:
        """Changing the pending session cannot manufacture valid password proof."""
        self.confirmed_device()
        self.start_otp_login()
        session = self.client.session
        pending = session[PENDING_OTP_SESSION_KEY]
        pending['auth_hash'] = '0' * 64
        session[PENDING_OTP_SESSION_KEY] = pending
        session.save()

        response = self.client.get(self.otp_url)

        self.assertRedirects(response, self.login_url, fetch_redirect_response=False)
        assert PENDING_OTP_SESSION_KEY not in self.client.session

    def test_tampered_device_id_cannot_use_another_users_authenticator(self) -> None:
        """The pending device must belong to the password-verified user."""
        self.confirmed_device()
        other = User.objects.create_user(username='other-otp-user', password='OtherPass123!')
        other_device = UserOTPDevice.objects.create(user=other, confirmed=True, last_t=0)
        self.start_otp_login()
        session = self.client.session
        pending = session[PENDING_OTP_SESSION_KEY]
        pending['device_id'] = other_device.pk
        session[PENDING_OTP_SESSION_KEY] = pending
        session.save()

        response = self.client.get(self.otp_url)

        self.assertRedirects(response, self.login_url, fetch_redirect_response=False)
        assert PENDING_OTP_SESSION_KEY not in self.client.session

    @patch('users.models.UserOTPDevice.verify_token', side_effect=[False, True])
    def test_failed_otp_keeps_pending_state_then_success_authenticates(self, _verify_token: Mock) -> None:
        """A failed code must not consume password proof; a subsequent valid code completes login."""
        self.confirmed_device()
        self.start_otp_login()
        expected_backend = self.client.session[PENDING_OTP_SESSION_KEY]['backend']

        failed = self.client.post(self.otp_url, {'token': '000000'})
        assert failed.status_code == 200
        self.assertContains(failed, 'Invalid or already used code')
        assert PENDING_OTP_SESSION_KEY in self.client.session
        assert '_auth_user_id' not in self.client.session

        successful = self.client.post(self.otp_url, {'token': '000001'})
        assert successful.status_code == 302
        assert PENDING_OTP_SESSION_KEY not in self.client.session
        assert self.client.session[BACKEND_SESSION_KEY] == expected_backend
        assert int(self.client.session['_auth_user_id']) == self.user.pk

    @patch('users.models.UserOTPDevice.verify_token', return_value=True)
    def test_manipulated_external_next_url_is_not_followed_after_otp(self, _verify_token: Mock) -> None:
        """OTP completion must not turn manipulated session state into an open redirect."""
        self.confirmed_device()
        self.start_otp_login()
        session = self.client.session
        pending = session[PENDING_OTP_SESSION_KEY]
        pending['next'] = 'https://evil.example/phishing'
        session[PENDING_OTP_SESSION_KEY] = pending
        session.save()

        response = self.client.post(self.otp_url, {'token': '123456'})

        assert response.status_code == 302
        assert response.url == reverse('home:index')

    def test_service_account_password_cannot_sign_in_to_web_interface(self) -> None:
        """Interactive login remains unavailable to service accounts even with a correct password."""
        service = User.objects.create_user(
            username='service-user',
            password='ServicePass123!',
            account_type=User.AccountType.SERVICE,
        )

        response = self.client.post(
            self.login_url,
            {'username': service.username, 'password': 'ServicePass123!'},
        )

        assert response.status_code == 200
        self.assertContains(response, 'Service accounts cannot sign in')
        assert '_auth_user_id' not in self.client.session


@override_settings(TRUSTPOINT_IS_OPERATIONAL=True, TRUSTPOINT_IS_BOOTSTRAP=False)
class UserOTPRecoveryCodeTest(TestCase):
    """Verify single-use persistence and reset behavior for recovery credentials."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(username='recovery-user', password='StrongPass123!')
        self.device = UserOTPDevice.objects.create(user=self.user, confirmed=True, last_t=0)

    def test_recovery_code_is_consumed_exactly_once(self) -> None:
        """A used recovery code is persisted as consumed and cannot be replayed."""
        code = self.device.generate_recovery_codes()[0]

        assert self.device.verify_token(code)
        recovery = UserOTPRecoveryCode.objects.get(
            device=self.device,
            code_hash__isnull=False,
            used_at__isnull=False,
        )
        assert recovery.used_at is not None
        assert not self.device.verify_token(code)
        assert UserOTPRecoveryCode.objects.filter(device=self.device, used_at__isnull=False).count() == 1

    def test_reset_otp_deletes_device_and_recovery_codes(self) -> None:
        """Resetting an authenticator removes both the device and all recovery-code records."""
        self.device.generate_recovery_codes()
        recovery_ids = list(self.device.recovery_codes.values_list('pk', flat=True))
        self.client.force_login(self.user)

        response = self.client.post(reverse('users:profile_reset_otp'))

        self.assertRedirects(response, reverse('users:profile'), fetch_redirect_response=False)
        assert not UserOTPDevice.objects.filter(pk=self.device.pk).exists()
        assert not UserOTPRecoveryCode.objects.filter(pk__in=recovery_ids).exists()
