"""Module for certificate profile related models."""

from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta


class CertificateProfileModel(models.Model):
    """Model representing a certificate profile."""

    unique_name = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255, blank=True, default='')
    profile_json = models.JSONField()

    created_at = models.DateTimeField(verbose_name=_('Created-At'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated-At'), auto_now=True)
    is_default = models.BooleanField(default=False)

    class Meta(TypedModelMeta):
        """Meta information."""

    def __str__(self) -> str:
        """String representation of the CertificateProfileModel."""
        return self.unique_name
