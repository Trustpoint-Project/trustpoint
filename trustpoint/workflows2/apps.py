from django.apps import AppConfig


class Workflows2Config(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "workflows2"

    def ready(self) -> None:
        from .events.builtin import register_builtin_events

        register_builtin_events()

        # Register signal integrations (v1)
        from .integrations import devices  # noqa: F401
