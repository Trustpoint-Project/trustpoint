"""Tests for AOKI URL configuration."""

from django.urls import resolve, reverse


class TestAokiUrls:
    """Tests for AOKI URL patterns."""

    def test_aoki_init_url_resolves(self):
        """Test that the AOKI init URL resolves correctly."""
        url = reverse('aoki:aoki_init')
        assert url == '/aoki/init/'

        resolver = resolve('/aoki/init/')
        assert resolver.view_name == 'aoki:aoki_init'
        assert resolver.namespace == 'aoki'
        assert resolver.url_name == 'aoki_init'

    def test_aoki_init_url_resolver(self):
        """Test that URL resolver correctly identifies the view."""
        from aoki.views import AokiInitializationRequestView

        resolver = resolve('/aoki/init/')
        assert resolver.func.view_class == AokiInitializationRequestView
