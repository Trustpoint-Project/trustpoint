from django.apps import AppConfig


class Workflows2Config(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "workflows2"

    def ready(self) -> None:
        # Register signal integrations (v1)
        from .integrations import devices  # noqa: F401
