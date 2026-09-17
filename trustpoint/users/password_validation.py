# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Database-backed password validation."""

from django.contrib.auth import password_validation
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from management.models import AccountSecurityConfig


class ConfigurablePasswordValidator:
    """Apply Django's standard validators according to runtime policy."""

    def validate(self, password: str, user: object | None = None) -> None:
        """Validate a password using the active account-security policy."""
        config = AccountSecurityConfig.get()
        validators = []
        if config.password_similarity:
            validators.append(password_validation.UserAttributeSimilarityValidator())
        validators.append(password_validation.MinimumLengthValidator(config.password_minimum_length))
        if config.password_common:
            validators.append(password_validation.CommonPasswordValidator())
        if config.password_numeric:
            validators.append(password_validation.NumericPasswordValidator())
        for validator in validators:
            validator.validate(password, user)
        if (
            config.password_prevent_reuse
            and user is not None
            and getattr(user, 'previous_password', '')
            and check_password(password, user.previous_password)
        ):
            raise ValidationError(_('You cannot reuse your immediately previous password.'))

    def get_help_text(self) -> str:
        """Return the validator's help text."""
        return ''
