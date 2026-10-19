# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Model for SCEP server configuration."""

from django.db import models


class ScepServerConfigModel(models.Model):
    """SCEP-specific server configuration associated with a PKI domain."""

    domain = models.OneToOneField(
        'pki.DomainModel',
        on_delete=models.CASCADE,
        related_name='scep_config',
    )

    server_credential = models.ForeignKey(
        'pki.CredentialModel',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='+',
    )

    def __str__(self) -> str:
        """Return a string representation of the SCEP server configuration."""
        return super().__str__()
