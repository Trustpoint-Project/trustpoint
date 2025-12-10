"""Django application configuration."""

from django.apps import AppConfig


class DevicesConfig(AppConfig):
    """Devices application configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'devices'

    def ready(self) -> None:
        """Devices app initialization."""
        import devices.signals  # noqa: F401, PLC0415
