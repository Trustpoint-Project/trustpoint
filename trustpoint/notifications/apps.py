"""Configures the Notifications application and its settings for inclusion in the Django project."""

from django.apps import AppConfig


class NotificationsConfig(AppConfig):
    """Configures the Notifications application, including its name and other settings for Django."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'notifications'
