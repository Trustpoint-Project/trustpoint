"""Organization Model."""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _


class OrganizationModel(models.Model):
    """Organization Model."""

    name = models.CharField(_('Organization Name'), max_length=100, blank=True, default='')

    organization = models.CharField(_('Organization (O)'), max_length=255, default='trustpoint')
    organization_unit = models.CharField(_('Organization Unit (OU)'), max_length=255, blank=True, default='')
    country = models.CharField(_('Country (C)'), max_length=2, default='DE')
    state = models.CharField(_('State/Province (ST)'), max_length=255, blank=True, default='')
    locality = models.CharField(_('Locality/City (L)'), max_length=255, blank=True, default='')

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)

    class Meta:
        """Meta options for the Organization model."""

        verbose_name = 'Organization Model'

    def __str__(self) -> str:
        """Human-readable representation of the Organization model instance.

        Returns:
            str:
                Human-readable representation of the Organization model instance.
        """
        return self.name
