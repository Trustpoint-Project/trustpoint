# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Apply the saved password policy through Django's built-in validators."""

from __future__ import annotations

import gzip
from typing import TYPE_CHECKING, Any

from django.contrib.auth.password_validation import (
    CommonPasswordValidator,
    MinimumLengthValidator,
    NumericPasswordValidator,
    UserAttributeSimilarityValidator,
    password_validators_help_texts,
    validate_password,
)

from management.models import PasswordPolicy

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser


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
    def _get_validators() -> list[Any]:
        policy = PasswordPolicy.objects.filter(pk=PasswordPolicy.SINGLETON_ID).first() or PasswordPolicy()
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

    def validate(self, password: str, user: AbstractBaseUser | None = None) -> None:
        """Apply the selected validators, preserving Django's validation errors and their order."""
        validate_password(password, user=user, password_validators=self._get_validators())

    def get_help_text(self) -> str:
        """Describe the currently enforced policy in Django's password forms."""
        return ' '.join(password_validators_help_texts(self._get_validators()))
