"""Tests for the url module."""

from django.contrib import admin
from django.urls import resolve, reverse
from home.views import IndexView
from pki.views.issuing_cas import CrlDownloadView


class TestUrls:
    """Test cases for the main `urls.py` of the project."""

    def test_admin_url_resolves(self, settings):
        """Test that the admin panel URL resolves correctly to the admin site."""
        if settings.DEBUG:
            url = reverse('admin:index')
            resolver = resolve(url)
            assert resolver.func == admin.site.index

    def test_users_url_included(self):
        """Test that the 'users/' URL pattern is included and resolves to the correct namespace."""
        url = reverse('users:login')
        assert resolve(url).namespace == 'users'

    def test_home_index_url_resolves(self):
        """Test that the home index URL resolves to the correct view."""
        url = reverse('home:index')
        resolver = resolve(url)
        assert resolver.func.view_class == IndexView

    def test_crl_download_url_resolves(self):
        """Test that the CRL download URL pattern resolves to `CrlDownloadView`."""
        url = reverse('crl-download', kwargs={'pk': 1})
        resolver = resolve(url)
        assert resolver.func.view_class == CrlDownloadView

    def test_setup_wizard_url_included(self):
        """Test that the 'setup-wizard/' URL pattern is included and resolves correctly."""
        url = reverse('setup_wizard:initial')
        assert resolve(url).namespace == 'setup_wizard'

    def test_devices_url_included(self):
        """Test that the 'devices/' URL pattern is included and resolves correctly."""
        url = reverse('devices:devices')
        assert resolve(url).namespace == 'devices'


    def test_est_url_included(self):
        """Test that the 'est/' URL pattern is included and resolves correctly."""
        url = reverse('est:ca-certs-post', kwargs={'domain': 'test-domain', 'certtemplate': 'template'})
        assert resolve(url).namespace == 'est'

    def test_cmp_url_included(self):
        """Test that the 'cmp/' URL pattern is included and resolves to the correct namespace."""
        url = reverse('cmp:initialization', kwargs={'domain': 'test-domain'})
        assert resolve(url).namespace == 'cmp'

    def test_jsi18n_url_resolves(self):
        """Test that the JavaScript Catalog (jsi18n) URL resolves correctly."""
        url = reverse('javascript-catalog')
        resolver = resolve(url)
        assert resolver.func.view_class.__name__ == 'JavaScriptCatalog'
