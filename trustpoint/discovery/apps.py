# Copyright (c) The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Configuration for the discovery application."""

from django.apps import AppConfig


class DiscoveryConfig(AppConfig):
    """Configuration class for the discovery app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'discovery'
