# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Stored certificate authentication preference for the management CA."""

from django.db import models
from django.utils.translation import gettext_lazy as _


class CertificateAuthenticationConfig(models.Model):
    """Keep the enabled preference tied to the management issuing CA."""

    issuing_ca = models.OneToOneField(
        'pki.CaModel',
        on_delete=models.CASCADE,
        related_name='user_authentication_config',
    )
    enabled = models.BooleanField(default=False, verbose_name=_('Enable certificate authentication'))

    class Meta:
        """Model metadata."""

        verbose_name = _('Certificate authentication configuration')
        verbose_name_plural = _('Certificate authentication configurations')

    def __str__(self) -> str:
        """Identify the management CA associated with this preference."""
        return f'Certificate authentication for {self.issuing_ca}'
