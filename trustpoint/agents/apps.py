"""The Django agents application configuration."""

from django.apps import AppConfig


class AgentsConfig(AppConfig):
    """Agents application configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'agents'
    verbose_name = 'Agents'
