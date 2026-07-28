# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Configuration for the PKI app."""

from django.apps import AppConfig


class PkiConfig(AppConfig):
    """Configuration for the PKI app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self) -> None:
        """PKI app initialization."""
        import pki.signals as _  # noqa: F401, PLC0415
