# workflows/apps.py

from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    name = 'workflows'

    def ready(self) -> None:
        # Import each service module so that its @register_handler decorators run.
        import workflows.services.certificate_request  # noqa: F401
        # import workflows.services.device_created
        # import workflows.services.certificate_issued
        # import workflows.services.device_deleted
        # (Any other modules with handlers)
