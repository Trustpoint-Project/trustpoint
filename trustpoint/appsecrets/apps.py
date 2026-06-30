"""App configuration for the application-secret subsystem."""

from django.apps import AppConfig


class AppSecretsConfig(AppConfig):
    """Django app config for Trustpoint application secrets."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'appsecrets'
    verbose_name = 'Application Secrets'

