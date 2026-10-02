# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the consolidated password policy."""

import gzip
from datetime import timedelta

import pytest
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from management.forms import MAX_PASSWORD_LIST_BYTES, AccountSecurityConfigForm, PasswordPolicyForm
from management.models import AccountSecurityConfig, PasswordPolicy
from management.password_validation import PasswordPolicyValidator
from users.models import TrustpointUser

MINIMUM_LENGTH = 12
HTTP_OK = 200
HTTP_REDIRECT = 302
PASSWORD_POLICY_MINIMUM_LENGTH = 14
PASSWORD_EXPIRY_DAYS = 60
API_CREDENTIAL_EXPIRY_DAYS = 120
IDLE_TIMEOUT_MINUTES = 45
FAILED_LOGIN_ATTEMPTS = 7
UPDATED_API_EXPIRY_DAYS = 90
UPDATED_IDLE_TIMEOUT_MINUTES = 60
UPDATED_FAILED_LOGIN_ATTEMPTS = 5
INITIAL_PASSWORD_MINIMUM_LENGTH = 10
CUSTOM_LIST_FILENAME = 'custom.txt'


@override_settings(TRUSTPOINT_IS_OPERATIONAL=True, TRUSTPOINT_IS_BOOTSTRAP=False)
class PasswordPolicyValidatorTest(TestCase):
    """Check each password rule against the saved singleton policy."""

    def setUp(self) -> None:
        """Create a default policy for each independent validation case."""
        self.policy = PasswordPolicy.objects.create()
        self.validator = PasswordPolicyValidator()

    def assert_rejected(self, password: str, user: TrustpointUser | None = None) -> None:
        """Assert that the active policy rejects the supplied password."""
        with pytest.raises(ValidationError):
            self.validator.validate(password, user)

    def test_minimum_length_is_configurable(self) -> None:
        """Enforce the configured minimum length."""
        self.policy.minimum_length = MINIMUM_LENGTH
        self.policy.save()

        self.assert_rejected('Short!')

    def test_similarity_can_be_disabled_and_threshold_is_used(self) -> None:
        """Honor the similarity toggle and configured threshold."""
        user = TrustpointUser(username='alice')
        self.policy.user_similarity_enabled = False
        self.policy.minimum_length = 5
        self.policy.reject_common_passwords = False
        self.policy.save()
        self.validator.validate('alice123!', user)

        self.policy.user_similarity_enabled = True
        self.policy.max_similarity = 0.1
        self.policy.save()
        self.assert_rejected('alice123!', user)

    def test_common_password_validation_can_be_disabled(self) -> None:
        """Honor the common-password toggle."""
        self.policy.reject_common_passwords = True
        self.policy.save()
        self.assert_rejected('password')

        self.policy.reject_common_passwords = False
        self.policy.save()
        self.validator.validate('password')

    def test_custom_common_password_list_is_used(self) -> None:
        """Validate against the uploaded common-password list."""
        self.policy.common_password_list_data = b'customsecret\n'
        self.policy.common_password_list_name = CUSTOM_LIST_FILENAME
        self.policy.save()

        self.assert_rejected('customsecret')

    def test_numeric_only_password_validation_can_be_disabled(self) -> None:
        """Reject numeric-only passwords unless that rule is disabled."""
        self.policy.reject_common_passwords = False
        self.policy.save()
        self.assert_rejected('12345678')

        self.policy.reject_numeric_passwords = False
        self.policy.reject_common_passwords = False
        self.policy.save()
        self.validator.validate('12345678')

    def test_previous_password_reuse_is_configurable(self) -> None:
        """Prevent reuse of the immediately preceding password when enabled."""
        user = TrustpointUser(username='alice', previous_password=make_password('PriorPass!'))
        self.assert_rejected('PriorPass!', user)

        self.policy.prevent_password_reuse = False
        self.policy.save()
        self.validator.validate('PriorPass!', user)

    def test_password_expiry_and_empty_value(self) -> None:
        """Expire old passwords and treat an empty expiry value as unlimited."""
        self.policy.password_expiry_days = 30
        self.policy.save()
        assert self.policy.password_expired(timezone.now() - timedelta(days=31))
        assert not self.policy.password_expired(timezone.now())

        self.policy.password_expiry_days = None
        assert not self.policy.password_expired(timezone.now() - timedelta(days=365))

    @override_settings(TRUSTPOINT_IS_OPERATIONAL=True, TRUSTPOINT_IS_BOOTSTRAP=False)
    def test_otp_requirement_uses_password_policy(self) -> None:
        """Read the global OTP requirement from PasswordPolicy."""
        self.policy.require_otp = True
        self.policy.save()

        assert PasswordPolicy.is_otp_required()


class PasswordPolicyFormOwnershipTest(SimpleTestCase):
    """Keep password settings and non-password settings on their respective forms."""

    def test_account_security_form_only_exposes_non_password_settings(self) -> None:
        """Limit Account Security to API credentials, sessions, and login protection."""
        non_password_fields = {'api_credential_expiry_days', 'idle_timeout_minutes', 'failed_login_attempts'}
        assert set(AccountSecurityConfigForm.Meta.fields) == non_password_fields
        assert set(AccountSecurityConfigForm().fields) == non_password_fields

    def test_password_form_exposes_password_and_otp_settings(self) -> None:
        """Expose all password and OTP controls in one form."""
        fields = set(PasswordPolicyForm().fields)
        password_fields = {
            'minimum_length', 'prevent_password_reuse', 'password_expiry_days', 'user_similarity_enabled',
            'max_similarity', 'reject_common_passwords', 'common_password_list', 'reject_numeric_passwords',
            'require_otp',
        }
        assert password_fields.issubset(fields)

    def test_account_security_model_no_longer_has_password_fields(self) -> None:
        """Ensure password policy fields are absent from AccountSecurityConfig."""
        assert not hasattr(AccountSecurityConfig, 'password_minimum_length')
        assert not hasattr(AccountSecurityConfig, 'password_similarity')
        assert not hasattr(AccountSecurityConfig, 'password_common')
        assert not hasattr(AccountSecurityConfig, 'password_numeric')
        assert not hasattr(AccountSecurityConfig, 'password_prevent_reuse')
        assert not hasattr(AccountSecurityConfig, 'password_expiry_days')


class PasswordPolicyCustomListTest(TestCase):
    """Exercise validation and persistence of administrator-supplied common-password lists."""

    def setUp(self) -> None:
        self.policy = PasswordPolicy.objects.create()

    def make_form(
        self,
        upload: SimpleUploadedFile | None = None,
        *,
        restore_default_list: bool = False,
    ) -> PasswordPolicyForm:
        """Build a minimally valid bound form around a password-list operation."""
        data = {
            'minimum_length': '8',
            'max_similarity': '0.7',
        }
        if restore_default_list:
            data['restore_default_list'] = 'on'
        files = {'common_password_list': upload} if upload is not None else None
        return PasswordPolicyForm(data=data, files=files, instance=self.policy)

    def test_plaintext_list_is_persisted_exactly(self) -> None:
        """Store validated UTF-8 bytes and the original filename."""
        upload = SimpleUploadedFile('custom.txt', b'alpha\nbeta\n', content_type='text/plain')
        form = self.make_form(upload)

        assert form.is_valid(), form.errors
        form.save()

        self.policy.refresh_from_db()
        assert bytes(self.policy.common_password_list_data) == b'alpha\nbeta\n'
        assert self.policy.common_password_list_name == 'custom.txt'

    def test_gzip_list_is_validated_and_persisted_compressed(self) -> None:
        """Validate gzip contents while preserving the compressed database representation."""
        compressed = gzip.compress(b'compressedsecret\n')
        upload = SimpleUploadedFile('custom.gz', compressed, content_type='application/gzip')
        form = self.make_form(upload)

        assert form.is_valid(), form.errors
        form.save()

        self.policy.refresh_from_db()
        assert bytes(self.policy.common_password_list_data) == compressed
        assert self.policy.common_password_list_name == 'custom.gz'

    def test_malformed_gzip_is_rejected(self) -> None:
        """Reject files with gzip magic that cannot actually be decompressed."""
        form = self.make_form(SimpleUploadedFile('broken.gz', b'\x1f\x8bnot-a-gzip-stream'))

        assert not form.is_valid()
        assert form.errors.as_data()['common_password_list'][0].code == 'invalid_gzip'

    def test_invalid_utf8_and_empty_lists_are_rejected(self) -> None:
        """Password-list parsing requires non-empty UTF-8 text."""
        cases = [
            ('invalid.txt', b'\xff\xfe', 'invalid_encoding'),
            ('empty.txt', b'\n \n\t\n', 'empty_list'),
        ]
        for filename, content, error_code in cases:
            with self.subTest(filename=filename):
                form = self.make_form(SimpleUploadedFile(filename, content))

                assert not form.is_valid()
                assert form.errors.as_data()['common_password_list'][0].code == error_code

    def test_non_lowercase_or_control_character_entries_are_rejected(self) -> None:
        """Reject entries that violate the normalized lowercase printable format."""
        for content in (b'Password\n', b'valid\x00value\n'):
            with self.subTest(content=content):
                form = self.make_form(SimpleUploadedFile('custom.txt', content))

                assert not form.is_valid()
                assert form.errors.as_data()['common_password_list'][0].code == 'invalid_password_list'

    def test_decompressed_size_limit_is_enforced(self) -> None:
        """A small gzip upload may not expand beyond the configured 10 MiB limit."""
        compressed = gzip.compress(b'a' * (MAX_PASSWORD_LIST_BYTES + 1))
        form = self.make_form(SimpleUploadedFile('oversized.gz', compressed))

        assert not form.is_valid()
        assert form.errors.as_data()['common_password_list'][0].code == 'file_too_large'

    def test_upload_and_restore_default_are_mutually_exclusive(self) -> None:
        """Reject ambiguous requests that both replace and clear the custom list."""
        form = self.make_form(
            SimpleUploadedFile('custom.txt', b'alpha\n'),
            restore_default_list=True,
        )

        assert not form.is_valid()
        assert 'common_password_list' in form.errors

    def test_restore_default_clears_custom_list_without_changing_other_policy_fields(self) -> None:
        """Restoring Django's list clears only the stored custom-list fields."""
        self.policy.minimum_length = 19
        self.policy.common_password_list_data = b'custom\n'
        self.policy.common_password_list_name = 'old.txt'
        self.policy.save()
        form = PasswordPolicyForm(
            data={'minimum_length': '19', 'max_similarity': '0.7', 'restore_default_list': 'on'},
            instance=self.policy,
        )

        assert form.is_valid(), form.errors
        form.save()

        self.policy.refresh_from_db()
        assert self.policy.minimum_length == 19
        assert self.policy.uses_default_common_password_list
        assert self.policy.common_password_list_name == ''


class PasswordPolicyPageViewTest(TestCase):
    """Verify settings pages render and save only their owned configuration."""

    def setUp(self) -> None:
        """Create an authenticated settings administrator and both configurations."""
        self.user = TrustpointUser.objects.create_user(username='policy-admin')
        TrustpointUser.objects.filter(pk=self.user.pk).update(is_superuser=True, is_staff=True)
        self.user.refresh_from_db()
        self.client.force_login(self.user)
        self.account_security = AccountSecurityConfig.objects.create(
            pk=1,
            api_credential_expiry_days=API_CREDENTIAL_EXPIRY_DAYS,
            idle_timeout_minutes=IDLE_TIMEOUT_MINUTES,
            failed_login_attempts=FAILED_LOGIN_ATTEMPTS,
        )
        self.password_policy = PasswordPolicy.objects.create(minimum_length=INITIAL_PASSWORD_MINIMUM_LENGTH)

    def test_password_policy_page_has_password_and_otp_controls(self) -> None:
        """Render all password and OTP controls on Password + OTP."""
        response = self.client.get(reverse('management:password_policy'))

        assert response.status_code == HTTP_OK
        for label in (
            'Minimum password length',
            'Reject entirely numeric passwords',
            'Prevent reuse of the previous password',
            'Expire passwords after this many days',
            'Maximum similarity',
            'Upload a custom common-password list',
            'Require OTP',
        ):
            self.assertContains(response, label)

    def test_account_security_page_has_only_non_password_controls(self) -> None:
        """Render non-password controls without password-policy fields."""
        response = self.client.get(reverse('management:settings-account-security'))

        assert response.status_code == HTTP_OK
        self.assertContains(response, 'Expire API credentials after this many days')
        self.assertContains(response, 'Idle session duration in minutes')
        self.assertContains(response, 'Block after this many failed login attempts')
        self.assertNotContains(response, 'Minimum password length')
        self.assertNotContains(response, 'Password expiry')

    def test_password_policy_save_does_not_change_account_security(self) -> None:
        """Save password settings without changing API, session, or login limits."""
        response = self.client.post(
            reverse('management:password_policy'),
            {
                'minimum_length': str(PASSWORD_POLICY_MINIMUM_LENGTH),
                'password_expiry_days': str(PASSWORD_EXPIRY_DAYS),
                'user_similarity_enabled': 'on',
                'max_similarity': '0.65',
                'reject_common_passwords': 'on',
                'reject_numeric_passwords': 'on',
                'require_otp': 'on',
            },
        )

        assert response.status_code == HTTP_REDIRECT
        self.password_policy.refresh_from_db()
        self.account_security.refresh_from_db()
        assert self.password_policy.minimum_length == PASSWORD_POLICY_MINIMUM_LENGTH
        assert self.password_policy.password_expiry_days == PASSWORD_EXPIRY_DAYS
        assert self.password_policy.require_otp
        assert self.account_security.api_credential_expiry_days == API_CREDENTIAL_EXPIRY_DAYS
        assert self.account_security.idle_timeout_minutes == IDLE_TIMEOUT_MINUTES
        assert self.account_security.failed_login_attempts == FAILED_LOGIN_ATTEMPTS

    def test_account_security_save_does_not_change_password_policy(self) -> None:
        """Save Account Security without changing PasswordPolicy."""
        response = self.client.post(
            reverse('management:settings-account-security'),
            {
                'api_credential_expiry_days': str(UPDATED_API_EXPIRY_DAYS),
                'idle_timeout_minutes': str(UPDATED_IDLE_TIMEOUT_MINUTES),
                'failed_login_attempts': str(UPDATED_FAILED_LOGIN_ATTEMPTS),
            },
        )

        assert response.status_code == HTTP_REDIRECT
        self.password_policy.refresh_from_db()
        self.account_security.refresh_from_db()
        assert self.account_security.api_credential_expiry_days == UPDATED_API_EXPIRY_DAYS
        assert self.account_security.idle_timeout_minutes == UPDATED_IDLE_TIMEOUT_MINUTES
        assert self.account_security.failed_login_attempts == UPDATED_FAILED_LOGIN_ATTEMPTS
        assert self.password_policy.minimum_length == INITIAL_PASSWORD_MINIMUM_LENGTH
