"""Django application configuration for Workflow 2."""

from django.apps import AppConfig


class Workflows2Config(AppConfig):
    """Register Workflow 2 startup hooks."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'workflows2'

    def ready(self) -> None:
        """Register built-in events and signal integrations."""
        from .events.builtin import register_builtin_events  # noqa: PLC0415

        register_builtin_events()

        # Register signal integrations (v1)
        from .integrations import devices  # noqa: F401, PLC0415
