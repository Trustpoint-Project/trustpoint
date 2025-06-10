"""Django Settings apps."""

import logging
import sys

from django.apps import AppConfig
from django.core.management import call_command

logger = logging.getLogger(__name__)


class SettingsConfig(AppConfig):
    """Settings application configuration."""
    name = 'settings'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self) -> None:
        """Settings app initialization."""
        # Only call updateversion if we are not doing:
        if any(cmd in sys.argv for cmd in ['makemigrations', 'migrate', 'reset_db']):
            return
        call_command('updateversion')
