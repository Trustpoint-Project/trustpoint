"""Models concerning the Trustpoint settings."""

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityConfig(models.Model):
    """Security Configuration model."""

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes."""

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
        """Output as string."""
        return f'{self.security_mode}'


class AppVersion(models.Model):
    objects: models.Manager['AppVersion']

    version = models.CharField(max_length=17)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'App Version'

    def __str__(self) -> str:
        return f'{self.version} @ {self.last_updated.isoformat()}'


class BackupOptions(models.Model):
    """A singleton model (we always operate with pk=1) for backup settings.
    We store host/port/user/local_storage, plus either a password or an SSH key.
    """

    class AuthMethod(models.TextChoices):
        PASSWORD = 'password', 'Password'
        SSH_KEY   = 'ssh_key',  'SSH Key'

    host = models.CharField(max_length=255, verbose_name=_('Host'))
    port = models.PositiveIntegerField(default=2222, verbose_name=_('Port'))
    user = models.CharField(max_length=128, verbose_name=_('Username'))
    local_storage = models.BooleanField(default=True, verbose_name=_('Use local storage'))

    auth_method = models.CharField(
        max_length=10,
        choices=AuthMethod.choices,
        verbose_name=_('Authentication Method')
    )

    password = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Password'),
        help_text=_('Plain‐text password for SFTP.')
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

    def __str__(self) -> str:
        return f'{self.user}@{self.host}:{self.port} ({self.auth_method})'
