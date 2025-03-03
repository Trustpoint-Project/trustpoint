"""Configuration for the PKI app."""

from django.apps import AppConfig


class PkiConfig(AppConfig):
    """Configuration for the PKI app."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self) -> None:
        """Import signals for the PKI app."""
        from pki.signals.issuing_ca import (
            delete_related_credential_certificate_chain_order_records,  # noqa: F401
            delete_related_credential_record,  # noqa: F401
        )
