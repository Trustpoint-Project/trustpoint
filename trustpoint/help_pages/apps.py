"""Configures the help_pages application and its settings for inclusion in the Django project."""

from django.apps import AppConfig


class HelpPagesConfig(AppConfig):
    """Help pages application configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'help_pages'
