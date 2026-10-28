# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Apply the saved password policy through Django's built-in validators."""

from __future__ import annotations

import gzip
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import (
    CommonPasswordValidator,
    MinimumLengthValidator,
    NumericPasswordValidator,
    UserAttributeSimilarityValidator,
    password_validators_help_texts,
    validate_password,
)
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from management.models import PasswordPolicy

if TYPE_CHECKING:
    from users.models import TrustpointUser


class StoredCommonPasswordValidator(CommonPasswordValidator):
    """Use Django's common-password check with list contents loaded from the database."""

    def __init__(self, password_list_data: bytes) -> None:
        """Decode the validated upload without requiring a filesystem copy."""
        if password_list_data.startswith(b'\x1f\x8b'):
            password_list_data = gzip.decompress(password_list_data)
        self.passwords = {line.strip() for line in password_list_data.decode('utf-8').splitlines()}


class PasswordPolicyValidator:
    """Read the current policy for each check so saved changes apply across workers."""

    @staticmethod
    def _get_policy() -> PasswordPolicy:
        if settings.TRUSTPOINT_IS_BOOTSTRAP or not settings.TRUSTPOINT_IS_OPERATIONAL:
            return PasswordPolicy()
        return PasswordPolicy.objects.filter(pk=PasswordPolicy.SINGLETON_ID).first() or PasswordPolicy()

    @staticmethod
    def _get_validators(policy: PasswordPolicy) -> list[Any]:
        validators: list[Any] = []
        if policy.user_similarity_enabled:
            validators.append(UserAttributeSimilarityValidator(max_similarity=policy.max_similarity))
        validators.append(MinimumLengthValidator(min_length=policy.minimum_length))
        if policy.reject_common_passwords:
            validators.append(
                StoredCommonPasswordValidator(bytes(policy.common_password_list_data))
                if not policy.uses_default_common_password_list
                else CommonPasswordValidator()
            )
        if policy.reject_numeric_passwords:
            validators.append(NumericPasswordValidator())
        return validators

    def validate(self, password: str, user: TrustpointUser | None = None) -> None:
        """Apply the selected validators, preserving Django's validation errors and their order."""
        policy = self._get_policy()
        validate_password(password, user=user, password_validators=self._get_validators(policy))
        previous_password = getattr(user, 'previous_password', '') if user is not None else ''
        if (
            policy.prevent_password_reuse
            and previous_password
            and check_password(password, previous_password)
        ):
            raise ValidationError(_('You cannot reuse your immediately previous password.'))

    def get_help_text(self) -> str:
        """Describe the currently enforced policy in Django's password forms."""
        policy = self._get_policy()
        return ' '.join(password_validators_help_texts(self._get_validators(policy)))
