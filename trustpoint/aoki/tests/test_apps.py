"""Tests for AOKI Django app configuration."""

import pytest
from django.apps import apps


class TestAokiConfig:
    """Tests for AokiConfig."""

    def test_app_config_exists(self):
        """Test that the AOKI app configuration is properly registered."""
        app_config = apps.get_app_config('aoki')
        assert app_config is not None
        assert app_config.name == 'aoki'

    def test_app_config_default_auto_field(self):
        """Test that the default auto field is set correctly."""
        app_config = apps.get_app_config('aoki')
        assert app_config.default_auto_field == 'django.db.models.BigAutoField'

    def test_app_config_verbose_name(self):
        """Test that app has a name."""
        app_config = apps.get_app_config('aoki')
        assert hasattr(app_config, 'name')
        assert app_config.name == 'aoki'
