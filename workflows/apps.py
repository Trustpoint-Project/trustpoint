from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    """AppConfig for the workflows application."""

    name = 'workflows'

    def ready(self) -> None:
        """Import signal handlers to register them on startup."""
        from workflows.services.certificate_request import CertificateRequestHandler
        from workflows.services.trigger_dispatcher import TriggerDispatcher

        TriggerDispatcher.register(
            'certificate_request',
            CertificateRequestHandler()
        )
