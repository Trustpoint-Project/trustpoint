# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django application configuration."""

from django.apps import AppConfig


class SharedConfig(AppConfig):
    """Shared application configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'shared'
