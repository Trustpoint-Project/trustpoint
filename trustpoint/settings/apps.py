"""Django Settings apps."""

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class SettingsConfig(AppConfig):
    """Settings application configuration."""
    name = 'settings'
    default_auto_field = 'django.db.models.BigAutoField'
