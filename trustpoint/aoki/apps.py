# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django application configuration for the AOKI app."""

from django.apps import AppConfig


class AokiConfig(AppConfig):
    """Configuration for the AOKI app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'aoki'
