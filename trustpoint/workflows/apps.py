"""Django application configuration for the ``workflows`` app."""

from importlib import import_module

from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    """Application configuration for the ``workflows`` app."""

    name = 'workflows'

    def ready(self) -> None:
        """Register signal handlers and executors.

        Called by Django when the application registry is fully populated.
        Imports modules for their side effects so that handlers and executors
        are registered with the framework.
        """
        # Import for side effects: module-level code performs registrations.
        import_module('workflows.services.executors')
        import_module('workflows.context.strategy.certificate_request')
        import_module('workflows.context.strategy.device_action')
