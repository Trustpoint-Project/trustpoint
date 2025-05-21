"""Configuration for the PKI app."""

from django.apps import AppConfig


class PkiConfig(AppConfig):
    """Configuration for the PKI app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self) -> None:
        """PKI app initialization."""
