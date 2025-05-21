"""Django Settings apps."""

import logging
from typing import Any

from django.apps import AppConfig
from django.core.management import call_command
from django.db.backends.signals import connection_created

logger = logging.getLogger(__name__)


class SettingsConfig(AppConfig):
    """Settings application configuration."""
    name = 'settings'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self) -> None:
        """Settings app initialization."""
        # if 'makemigrations' in sys.argv or 'reset_db' in sys.argv or 'migrate' in sys.argv:
        #     return
        # Signal to run after database connection is established
        connection_created.connect(self.on_connection_created)

    def on_connection_created(self, sender: Any, connection: Any, **_kwargs: Any) -> None:
        """Execute update_app_version after a database connection is created."""
        call_command('updateversion')
