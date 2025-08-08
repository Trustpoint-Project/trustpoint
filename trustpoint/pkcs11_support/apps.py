"""The Django EST Application Configuration."""

from django.apps import AppConfig


class Pkcs11Config(AppConfig):
    """Pkcs#11 Configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pkcs11_support'
