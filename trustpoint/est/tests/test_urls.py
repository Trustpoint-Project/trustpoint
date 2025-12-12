"""Comprehensive tests for EST urls.py module."""

import pytest
from django.urls import resolve, reverse

from est import views

# EST URLs are mounted at /.well-known/est/ in the main urls.py
EST_PREFIX = '/.well-known/est/'


class TestEstUrlPatterns:
    """Test EST URL pattern resolution and reverse URL lookup."""

    def test_app_name(self):
        """Test that the app_name is correctly set."""
        from est import urls
        assert urls.app_name == 'est'

    def test_simple_enrollment_default_url(self):
        """Test simpleenroll default URL pattern resolution."""
        url = EST_PREFIX + 'simpleenroll'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleEnrollmentDefaultView
        assert resolved.url_name == 'simple-enrollment-default'
        assert resolved.app_name == 'est'

    def test_simple_enrollment_default_url_with_trailing_slash(self):
        """Test simpleenroll default URL with trailing slash."""
        url = EST_PREFIX + 'simpleenroll/'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleEnrollmentDefaultView
        assert resolved.url_name == 'simple-enrollment-default'

    def test_simple_enrollment_with_domain_url(self):
        """Test simpleenroll URL with domain parameter."""
        url = EST_PREFIX + 'test_domain/simpleenroll'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleEnrollmentView
        assert resolved.url_name == 'simple-enrollment-post'
        assert resolved.kwargs['domain'] == 'test_domain'
        assert 'certtemplate' not in resolved.kwargs

    def test_simple_enrollment_with_domain_and_template_url(self):
        """Test simpleenroll URL with domain and certtemplate parameters."""
        url = EST_PREFIX + 'test_domain/tls_client/simpleenroll'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleEnrollmentView
        assert resolved.url_name == 'simple-enrollment-post'
        assert resolved.kwargs['domain'] == 'test_domain'
        assert resolved.kwargs['certtemplate'] == 'tls_client'

    def test_simple_enrollment_with_domain_and_template_trailing_slash(self):
        """Test simpleenroll URL with trailing slash."""
        url = EST_PREFIX + 'test_domain/tls_client/simpleenroll/'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleEnrollmentView
        assert resolved.url_name == 'simple-enrollment-post'

    def test_simple_reenrollment_with_domain_url(self):
        """Test simplereenroll URL with domain parameter."""
        url = EST_PREFIX + 'test_domain/simplereenroll'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleReEnrollmentView
        assert resolved.url_name == 'simple-reenrollment-post'
        assert resolved.kwargs['domain'] == 'test_domain'
        assert 'certtemplate' not in resolved.kwargs

    def test_simple_reenrollment_with_domain_and_template_url(self):
        """Test simplereenroll URL with domain and certtemplate parameters."""
        url = EST_PREFIX + 'test_domain/tls_client/simplereenroll'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleReEnrollmentView
        assert resolved.url_name == 'simple-reenrollment-post'
        assert resolved.kwargs['domain'] == 'test_domain'
        assert resolved.kwargs['certtemplate'] == 'tls_client'

    def test_simple_reenrollment_with_domain_and_template_trailing_slash(self):
        """Test simplereenroll URL with trailing slash."""
        url = EST_PREFIX + 'test_domain/tls_client/simplereenroll/'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleReEnrollmentView
        assert resolved.url_name == 'simple-reenrollment-post'

    def test_cacerts_url_with_domain(self):
        """Test cacerts URL with domain parameter."""
        url = EST_PREFIX + 'test_domain/cacerts/'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstCACertsView
        assert resolved.url_name == 'ca-certs-post'
        assert resolved.kwargs['domain'] == 'test_domain'
        assert 'certtemplate' not in resolved.kwargs

    def test_cacerts_url_with_domain_and_template(self):
        """Test cacerts URL with domain and certtemplate parameters."""
        url = EST_PREFIX + 'test_domain/tls_client/cacerts/'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstCACertsView
        assert resolved.url_name == 'ca-certs-post'
        assert resolved.kwargs['domain'] == 'test_domain'
        assert resolved.kwargs['certtemplate'] == 'tls_client'

    def test_csrattrs_url(self):
        """Test csrattrs URL with domain and certtemplate."""
        url = EST_PREFIX + 'test_domain/tls_client/csrattrs/'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstCsrAttrsView
        assert resolved.url_name == 'csrattrs'
        assert resolved.kwargs['domain'] == 'test_domain'
        assert resolved.kwargs['certtemplate'] == 'tls_client'

    def test_url_pattern_with_special_characters_in_domain(self):
        """Test URL patterns with special characters in domain name."""
        url = EST_PREFIX + 'test-domain_123/simpleenroll'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleEnrollmentView
        assert resolved.kwargs['domain'] == 'test-domain_123'

    def test_url_pattern_with_special_characters_in_certtemplate(self):
        """Test URL patterns with special characters in certtemplate."""
        url = EST_PREFIX + 'test_domain/tls_client-v2/simpleenroll'
        resolved = resolve(url)
        assert resolved.func.view_class == views.EstSimpleEnrollmentView
        assert resolved.kwargs['certtemplate'] == 'tls_client-v2'

    def test_reverse_simple_enrollment_default(self):
        """Test reverse URL lookup for simple enrollment default."""
        url = reverse('est:simple-enrollment-default')
        # Reverse returns without trailing slash for optional trailing slash patterns
        assert url == EST_PREFIX + 'simpleenroll' or url == EST_PREFIX + 'simpleenroll/'

    def test_reverse_simple_enrollment_with_params(self):
        """Test reverse URL lookup for simple enrollment with parameters."""
        url = reverse('est:simple-enrollment-post', kwargs={'domain': 'test_domain', 'certtemplate': 'tls_client'})
        assert 'test_domain' in url
        assert 'tls_client' in url
        assert 'simpleenroll' in url

    def test_reverse_simple_reenrollment_with_params(self):
        """Test reverse URL lookup for simple reenrollment with parameters."""
        url = reverse('est:simple-reenrollment-post', kwargs={'domain': 'test_domain', 'certtemplate': 'tls_client'})
        assert 'test_domain' in url
        assert 'tls_client' in url
        assert 'simplereenroll' in url

    def test_reverse_cacerts_with_params(self):
        """Test reverse URL lookup for cacerts with parameters."""
        url = reverse('est:ca-certs-post', kwargs={'domain': 'test_domain', 'certtemplate': 'tls_client'})
        assert 'test_domain' in url
        assert 'tls_client' in url
        assert 'cacerts' in url

    def test_reverse_csrattrs(self):
        """Test reverse URL lookup for csrattrs."""
        url = reverse('est:csrattrs', kwargs={'domain': 'test_domain', 'certtemplate': 'tls_client'})
        assert url == EST_PREFIX + 'test_domain/tls_client/csrattrs/'

    def test_urlpatterns_list_length(self):
        """Test that urlpatterns contains expected number of patterns."""
        from est import urls
        # Should have 6 URL patterns (including duplicate csrattrs)
        assert len(urls.urlpatterns) == 6

    def test_urlpatterns_all_have_names(self):
        """Test that all URL patterns have names."""
        from est import urls
        for pattern in urls.urlpatterns:
            assert hasattr(pattern, 'name')
            assert pattern.name is not None

    def test_optional_certtemplate_in_enrollment(self):
        """Test that certtemplate is optional in enrollment URL."""
        # Without certtemplate
        url = EST_PREFIX + 'test_domain/simpleenroll'
        resolved = resolve(url)
        assert resolved.kwargs['domain'] == 'test_domain'
        assert 'certtemplate' not in resolved.kwargs or resolved.kwargs.get('certtemplate') is None

    def test_optional_certtemplate_in_reenrollment(self):
        """Test that certtemplate is optional in reenrollment URL."""
        # Without certtemplate
        url = EST_PREFIX + 'test_domain/simplereenroll'
        resolved = resolve(url)
        assert resolved.kwargs['domain'] == 'test_domain'
        assert 'certtemplate' not in resolved.kwargs or resolved.kwargs.get('certtemplate') is None

    def test_optional_certtemplate_in_cacerts(self):
        """Test that certtemplate is optional in cacerts URL."""
        # Without certtemplate
        url = EST_PREFIX + 'test_domain/cacerts/'
        resolved = resolve(url)
        assert resolved.kwargs['domain'] == 'test_domain'
        assert 'certtemplate' not in resolved.kwargs or resolved.kwargs.get('certtemplate') is None
