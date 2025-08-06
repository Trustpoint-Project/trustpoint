"""Django Management apps."""

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class ManagementConfig(AppConfig):
    """Management application configuration."""
    name = 'management'
    default_auto_field = 'django.db.models.BigAutoField'
