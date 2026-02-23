"""Backup Options Model."""
from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _


class BackupOptions(models.Model):
    """A singleton model (we always operate with pk=1) for backup settings.

    We store host/port/user/local_storage, plus either a password or an SSH key.
    """
    class AuthMethod(models.TextChoices):
        """Authentication methods for backup options."""
        PASSWORD = 'password', 'Password'
        SSH_KEY   = 'ssh_key',  'SSH Key'

    enable_sftp_storage = models.BooleanField(default=False, verbose_name=_('Use SFTP storage'))

    host = models.CharField(max_length=255, verbose_name=_('Host'), blank=True)
    port = models.PositiveIntegerField(default=2222, verbose_name=_('Port'), blank=True)
    user = models.CharField(max_length=128, verbose_name=_('Username'), blank=True)

    auth_method = models.CharField(
        max_length=10,
        choices=AuthMethod.choices,
        default=AuthMethod.PASSWORD,
        verbose_name=_('Authentication Method')
    )

    # TODO (Dome): Storing passwords in plain text  # noqa: FIX002
    password = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Password'),
        help_text=_('Plain-text password for SFTP.')
    )

    private_key = models.TextField(
        blank=True,
        verbose_name=_('SSH Private Key (PEM format)'),
        help_text=_('Paste the private key here (PEM).')
    )

    key_passphrase = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Key Passphrase'),
        help_text=_('Passphrase for the private key, if any.')
    )

    remote_directory = models.CharField(
        max_length=512,
        blank=True,
        default='/upload/trustpoint/',
        verbose_name=_('Remote Directory'),
        help_text=_('Remote directory (e.g. /backups/) where files should be uploaded. '
                  'Trailing slash is optional.'),
    )

    class Meta:
        """Meta options for the BackupOptions model."""
        verbose_name = 'Backup Option'

    def __str__(self) -> str:
        """Return a string representation of the backup options."""
        return f'{self.user}@{self.host}:{self.port} ({self.auth_method})'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Ensure only one instance exists (singleton pattern)."""
        self.full_clean()

        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Prevent the creation of more than one instance."""
        if BackupOptions.objects.exists() and not self.pk:
            msg = 'Only one BackupOptions instance is allowed.'
            raise ValidationError(msg)

        return super().clean()
