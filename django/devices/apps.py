"""Django application configuration."""

from django.apps import AppConfig


class DevicesConfig(AppConfig):
    """Devices application configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'devices'
