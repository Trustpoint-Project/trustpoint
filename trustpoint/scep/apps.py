# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""The Django SCEP application configuration."""

from django.apps import AppConfig


class ScepConfig(AppConfig):
    """SCEP configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scep'
