"""Models concerning the Trustpoint settings."""

import os
from typing import Any
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _
from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityConfig(models.Model):
    """Security Configuration model"""

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes"""

        DEV = '0', _('Testing env')
        LOW = '1', _('Basic')
        MEDIUM = '2', _('Medium')
        HIGH = '3', _('High')
        HIGHEST = '4', _('Highest')

    security_mode = models.CharField(max_length=6, choices=SecurityModeChoices.choices, default=SecurityModeChoices.LOW)

    auto_gen_pki = models.BooleanField(default=False)
    auto_gen_pki_key_algorithm = models.CharField(
        max_length=24, choices=AutoGenPkiKeyAlgorithm, default=AutoGenPkiKeyAlgorithm.RSA2048
    )

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.security_mode}'


class BackupRecord(models.Model):
    objects: models.Manager['BackupRecord']
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    items = models.CharField(
        max_length=255,
        help_text='Comma separated list of backed up items (e.g. Database, Application Config, Apache Config)'
    )
    backup_file = models.FileField(upload_to=getattr(settings, 'BACKUP_FILE_PATH'))

    def __str__(self) -> str:
        return self.name

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        self.backup_file.delete(save=False)
        return super().delete(*args, **kwargs)
