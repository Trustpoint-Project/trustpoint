# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Password policy settings matching Django's built-in password validators."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, ClassVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class PasswordPolicy(models.Model):
    """Store the global password policy with Django's default validator settings."""

    SINGLETON_ID: ClassVar[int] = 1

    require_otp = models.BooleanField(
        default=False,
        verbose_name=_('Require OTP'),
        help_text=_('Require an authenticator code for every password login. Users without OTP must set it up first.'),
    )

    minimum_length = models.PositiveIntegerField(
        default=8,
        help_text=_('Minimum number of characters in a password.'),
    )
    prevent_password_reuse = models.BooleanField(
        default=True,
        help_text=_('Require a new password to differ from the immediately preceding password.'),
    )
    password_expiry_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text=_('Leave empty to keep passwords valid indefinitely.'),
    )

    user_similarity_enabled = models.BooleanField(
        default=True,
        help_text=_('Reject passwords that are too similar to the user information checked by Django.'),
    )
    max_similarity = models.FloatField(
        default=0.7,
        validators=[MinValueValidator(0.1), MaxValueValidator(1.0)],
        help_text=_('Similarity threshold from 0.1 to 1.0. Lower values make the check stricter.'),
    )

    reject_common_passwords = models.BooleanField(
        default=True,
        help_text=_('Reject passwords found in the common-password list.'),
    )
    common_password_list_data = models.BinaryField(
        blank=True,
        default=bytes,
        help_text=_('Custom common-password list contents in plain text or gzip format, included in database backups.'),
    )
    common_password_list_name = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text=_('Original filename of the custom common-password list.'),
    )
    reject_numeric_passwords = models.BooleanField(
        default=True,
        help_text=_('Reject passwords that consist entirely of digits.'),
    )
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata."""

        verbose_name = _('Password Policy')
        verbose_name_plural = _('Password Policies')

    def __str__(self) -> str:
        """Return a readable name for the policy."""
        return 'Password Policy'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Persist the global policy under the fixed primary key ``1``."""
        self.pk = self.SINGLETON_ID
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validate numeric policy values independently of form constraints."""
        super().clean()
        if self.minimum_length < 1:
            raise ValidationError({'minimum_length': _('The minimum password length must be positive.')})
        if self.password_expiry_days is not None and self.password_expiry_days < 1:
            raise ValidationError({'password_expiry_days': _('This value must be positive.')})

    def password_expired(self, changed_at: datetime | None) -> bool:
        """Return whether the password has expired under this policy."""
        return bool(
            self.password_expiry_days
            and changed_at
            and timezone.now() >= changed_at + timedelta(days=self.password_expiry_days)
        )

    @property
    def uses_default_common_password_list(self) -> bool:
        """Return whether the policy selects Django's bundled default."""
        return not self.common_password_list_data

    @classmethod
    def is_otp_required(cls) -> bool:
        """Apply OTP policy only after initial setup, without querying bootstrap storage."""
        return (
            settings.TRUSTPOINT_IS_OPERATIONAL and not settings.TRUSTPOINT_IS_BOOTSTRAP
            and cls.objects.filter(pk=cls.SINGLETON_ID, require_otp=True).exists()
        )

    @classmethod
    def get_current(cls) -> PasswordPolicy:
        """Return the global policy, creating it with Django's default validator settings if needed."""
        policy, _ = cls.objects.get_or_create(pk=cls.SINGLETON_ID)
        return policy
