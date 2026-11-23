# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""The Django agents application configuration."""

from django.apps import AppConfig


class AgentsConfig(AppConfig):
    """Agents application configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'agents'
    verbose_name = 'Agents'

    def ready(self) -> None:
        """Register deployment checks."""
        from agents import checks  # noqa: F401, PLC0415
