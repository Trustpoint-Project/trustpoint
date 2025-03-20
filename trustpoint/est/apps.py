"""The Django EST Application Configuration."""

from django.apps import AppConfig


class EstConfig(AppConfig):
    """EST Configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'est'