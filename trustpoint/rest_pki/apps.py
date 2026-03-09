"""The Django REST PKI Application Configuration."""

from django.apps import AppConfig


class RestPkiConfig(AppConfig):
    """REST PKI Configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'rest_pki'
