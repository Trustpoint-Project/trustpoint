"""Django application configuration for the ``workflows`` app."""

from __future__ import annotations

from importlib import import_module

from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    """Application configuration for the ``workflows`` app."""

    name = 'workflows'

    def ready(self) -> None:
        """Register context strategies and executors.

        Called by Django when the application registry is fully populated.
        """
        # Register step executors (authoritative mapping of type -> executor).
        from workflows.services.executors import register_executors  # noqa: PLC0415

        register_executors()

        # Import context strategies for side effects (they register themselves).
        import_module('workflows.context.strategy.certificate_request')
        import_module('workflows.context.strategy.device_action')
