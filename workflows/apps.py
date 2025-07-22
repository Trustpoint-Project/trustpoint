from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    """AppConfig for the workflows application."""

    name = 'workflows'

    def ready(self) -> None:
        """Import signal handlers to register them on startup."""
        # we import purely for side effects (signal registration)
        import workflows.signals  # noqa: F401
