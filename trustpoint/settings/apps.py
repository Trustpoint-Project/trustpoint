"""Django Settings apps."""

import logging
from typing import Any

from django.apps import AppConfig
from django.conf import settings as django_settings
from django.db.backends.signals import connection_created
from django.db.models.signals import post_migrate

logger = logging.getLogger(__name__)


class SettingsConfig(AppConfig):
    """Settings application configuration."""
    name = 'settings'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self) -> None:
        """Settings app initialization."""
        # Signal to run after database migrations
        post_migrate.connect(self.update_app_version, sender=self)

        # Signal to run after database connection is established
        connection_created.connect(self.on_connection_created)

    def on_connection_created(self, sender: Any, connection: Any, **_kwargs: Any) -> None:
        """Execute update_app_version after a database connection is created."""
        self.update_app_version(sender=self)

    def update_app_version(self, sender: Any, **kwargs: Any) -> None:
        """Update app version if pyproject.toml is different than verison in db."""
        from .models import AppVersion
        current = django_settings.APP_VERSION

        qs = AppVersion.objects.all()
        if not qs.exists():
            AppVersion.objects.create(version=current)
        else:
            obj = qs.first()
            if obj and obj.version != current:
                old_version= obj.version
                obj.version = current
                obj.save()
                msg = f'Trustpoint Version updated from {old_version} to {current}.'
                logger.info(msg)
