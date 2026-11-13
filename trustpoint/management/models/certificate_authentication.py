# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Stored certificate authentication preference for the management CA."""

from django.db import models
from django.utils.translation import gettext_lazy as _


def default_user_certificate_profile() -> int | None:
    """Use the installed user client profile for new authentication configurations."""
    from pki.models import CertificateProfileModel  # noqa: PLC0415

    return CertificateProfileModel.objects.filter(unique_name='user_client').values_list('pk', flat=True).first()


class CertificateAuthenticationConfig(models.Model):
    """Keep the enabled preference tied to the management issuing CA."""

    issuing_ca = models.OneToOneField(
        'pki.CaModel',
        on_delete=models.CASCADE,
        related_name='user_authentication_config',
    )
    enabled = models.BooleanField(default=False, verbose_name=_('Enable certificate authentication'))
    certificate_profile = models.ForeignKey(
        'pki.CertificateProfileModel',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        default=default_user_certificate_profile,
        verbose_name=_('Default user certificate profile'),
    )

    class Meta:
        """Model metadata."""

        verbose_name = _('Certificate authentication configuration')
        verbose_name_plural = _('Certificate authentication configurations')

    def __str__(self) -> str:
        """Identify the management CA associated with this preference."""
        return f'Certificate authentication for {self.issuing_ca}'
