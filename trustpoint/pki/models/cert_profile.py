"""Module for certificate profile related models."""

from django.db import models
from django_stubs_ext.db.models import TypedModelMeta

from pki.models.domain import DomainModel


class CertificateProfileModel(models.Model):
    """Model representing a certificate profile."""

    unique_name = models.CharField(max_length=255, unique=True)
    profile_json = models.JSONField()

    class Meta(TypedModelMeta):
        """Meta information."""

    def __str__(self) -> str:
        """String representation of the CertificateProfileModel."""
        return self.unique_name


class DomainAllowedCertificateProfileModel(models.Model):
    """Model representing allowed certificate profiles for a domain."""

    domain = models.ForeignKey(
        DomainModel,
        on_delete=models.CASCADE,
        related_name='certificate_profiles'
    )
    certificate_profile = models.ForeignKey(
        CertificateProfileModel,
        on_delete=models.CASCADE,
        related_name='domains'
    )
    # Domain-specific alias for the certificate profile name
    alias = models.CharField(max_length=255, default='')

    class Meta(TypedModelMeta):
        """Meta information."""
        unique_together = ('domain', 'certificate_profile')

    def __str__(self) -> str:
        """String representation of the DomainAllowedCertificateProfileModel."""
        name_str = f'{self.domain.unique_name} - {self.certificate_profile.unique_name}'
        if self.alias:
            name_str += f' (alias: {self.alias})'
        return name_str


class DeviceAllowedCertificateProfileModel(models.Model):
    """Model representing allowed certificate profiles for a device."""

    device = models.ForeignKey(
        'devices.DeviceModel',
        on_delete=models.CASCADE,
        related_name='certificate_profiles'
    )
    certificate_profile = models.ForeignKey(
        CertificateProfileModel,
        on_delete=models.CASCADE,
        related_name='devices'
    )
    # Device-specific alias for the certificate profile name
    alias = models.CharField(max_length=255, default='')

    class Meta(TypedModelMeta):
        """Meta information."""
        unique_together = ('device', 'certificate_profile')

    def __str__(self) -> str:
        """String representation of the DeviceAllowedCertificateProfileModel."""
        name_str = f'{self.device} - {self.certificate_profile.unique_name}'
        if self.alias:
            name_str += f' (alias: {self.alias})'
        return name_str
