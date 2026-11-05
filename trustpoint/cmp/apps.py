# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""The Django CMP Application Configuration."""

from django.apps import AppConfig
from django.db.models.signals import post_migrate


class CmpConfig(AppConfig):
    """Cmp Configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cmp'

    def ready(self) -> None:
        """Initialize confirmation cleanup after database migrations finish."""
        from cmp.confirmation import initialize_confirmation_expiry  # noqa: PLC0415

        post_migrate.connect(
            initialize_confirmation_expiry,
            sender=self,
            dispatch_uid='cmp.initialize_confirmation_expiry',
        )
