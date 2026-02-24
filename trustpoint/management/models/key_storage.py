"""Key Storage Model."""
from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _


class KeyStorageConfig(models.Model):
    """Configuration model for cryptographic material storage."""

    class StorageType(models.TextChoices):
        """Types of cryptographic storage."""
        SOFTWARE = 'software', _('Software (No Encryption)')
        SOFTHSM = 'softhsm', _('SoftHSM Container')
        PHYSICAL_HSM = 'physical_hsm', _('Physical HSM')

    storage_type = models.CharField(
        max_length=12,
        choices=StorageType.choices,
        default=StorageType.SOFTWARE,
        verbose_name=_('Storage Type'),
        help_text=_('Type of storage for cryptographic material')
    )

    hsm_config = models.OneToOneField(
        'PKCS11Token',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='crypto_storage_config',
        verbose_name=_('HSM Configuration'),
        help_text=_('Associated HSM token configuration (SoftHSM or Physical HSM)')
    )

    last_updated = models.DateTimeField(
        auto_now=True,
        verbose_name=_('Last Updated')
    )

    class Meta:
        """Meta options for the KeyStorageConfig model."""
        verbose_name = _('Crypto Storage Configuration')
        verbose_name_plural = _('Crypto Storage Configurations')

    def __str__(self) -> str:
        """Return a string representation of the storage configuration."""
        status = 'Active' if self.hsm_config is not None else 'Inactive'
        return f'{self.get_storage_type_display()} ({status})'

    @classmethod
    def get_config(cls) -> KeyStorageConfig:
        """Get the crypto storage configuration (singleton).

        Returns:
            KeyStorageConfig: The configuration instance

        Raises:
            cls.DoesNotExist: If no configuration exists
        """
        return cls.objects.get(pk=1)

    @classmethod
    def get_or_create_default(cls) -> KeyStorageConfig:
        """Get the configuration or create a default one.

        Returns:
            KeyStorageConfig: The configuration instance
        """
        config, _ = cls.objects.get_or_create(
            pk=1,
            defaults={
                'storage_type': cls.StorageType.SOFTWARE
            }
        )
        return config
