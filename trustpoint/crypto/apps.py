"""Application configuration for the new crypto backend."""

from django.apps import AppConfig


class CryptoConfig(AppConfig):
    """Register the crypto app for Django."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'crypto'
