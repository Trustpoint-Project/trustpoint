from django.apps import AppConfig


class WorkflowsConfig(AppConfig):
    """AppConfig for the workflows application."""

    name = 'workflows'

    def ready(self) -> None:
        """Import signal handlers to register them on startup."""
        from workflows.services.certificate_request import CertificateRequestHandler
        from workflows.services.handler_lookup import register_handler

        # Register the certificate request handler under a stable name
        register_handler('certificate_request', CertificateRequestHandler())
