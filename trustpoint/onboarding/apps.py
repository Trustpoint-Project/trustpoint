"""This module defines the configuration for the Onboarding app."""

from django.apps import AppConfig


class OnboardingConfig(AppConfig):
    """Configuration class for the Onboarding app."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'onboarding'
