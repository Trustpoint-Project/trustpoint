"""Configures the Home application and its settings for inclusion in the Django project."""

from django.apps import AppConfig


class HomeConfig(AppConfig):
    """Configures the Home application, including its name and other settings for Django."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'home'
