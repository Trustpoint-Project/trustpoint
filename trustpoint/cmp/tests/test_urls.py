"""Tests for CMP URL configuration."""

import pytest
from django.urls import resolve, reverse


class TestCmpUrls:
    """Tests for CMP URL patterns."""

    def test_initialization_wellknown_url_resolves(self):
        """Test that the CMP initialization wellknown URL resolves correctly."""
        url = reverse('cmp:initialization_wellknown', kwargs={'domain_name': 'test_domain'})
        assert url == '/.well-known/cmp/initialization/test_domain'
        
        resolver = resolve('/.well-known/cmp/initialization/test_domain')
        assert resolver.view_name == 'cmp:initialization_wellknown'
        assert resolver.namespace == 'cmp'
        assert resolver.url_name == 'initialization_wellknown'
        assert resolver.kwargs['domain_name'] == 'test_domain'

    def test_initialization_wellknown_slash_url_resolves(self):
        """Test that the CMP initialization wellknown URL with trailing slash resolves."""
        url = reverse('cmp:initialization_wellknown_slash', kwargs={'domain_name': 'test_domain'})
        assert url == '/.well-known/cmp/initialization/test_domain/'
        
        resolver = resolve('/.well-known/cmp/initialization/test_domain/')
        assert resolver.view_name == 'cmp:initialization_wellknown_slash'

    def test_initialization_profile_url_resolves(self):
        """Test that the CMP initialization with profile URL resolves correctly."""
        url = reverse('cmp:initialization_profile', 
                     kwargs={'domain_name': 'test_domain', 'certificate_profile': 'tls_client'})
        assert url == '/.well-known/cmp/p/test_domain/tls_client/initialization'
        
        resolver = resolve('/.well-known/cmp/p/test_domain/tls_client/initialization')
        assert resolver.view_name == 'cmp:initialization_profile'
        assert resolver.kwargs['domain_name'] == 'test_domain'
        assert resolver.kwargs['certificate_profile'] == 'tls_client'

    def test_initialization_url_resolves(self):
        """Test that the CMP initialization URL resolves correctly."""
        url = reverse('cmp:initialization', kwargs={'domain_name': 'test_domain'})
        assert url == '/.well-known/cmp/p/test_domain/initialization'
        
        resolver = resolve('/.well-known/cmp/p/test_domain/initialization')
        assert resolver.view_name == 'cmp:initialization'
        assert resolver.kwargs['domain_name'] == 'test_domain'

    def test_certification_template_url_resolves(self):
        """Test that the CMP certification with template URL resolves correctly."""
        url = reverse('cmp:certification_template',
                     kwargs={'domain_name': 'test_domain', 'certificate_profile': 'tls_server'})
        assert url == '/.well-known/cmp/p/test_domain/tls_server/certification'
        
        resolver = resolve('/.well-known/cmp/p/test_domain/tls_server/certification')
        assert resolver.view_name == 'cmp:certification_template'
        assert resolver.kwargs['domain_name'] == 'test_domain'
        assert resolver.kwargs['certificate_profile'] == 'tls_server'

    def test_certification_url_resolves(self):
        """Test that the CMP certification URL resolves correctly."""
        url = reverse('cmp:certification', kwargs={'domain_name': 'test_domain'})
        assert url == '/.well-known/cmp/p/test_domain/certification'
        
        resolver = resolve('/.well-known/cmp/p/test_domain/certification')
        assert resolver.view_name == 'cmp:certification'
        assert resolver.kwargs['domain_name'] == 'test_domain'

    def test_certification_slash_url_resolves(self):
        """Test that the CMP certification URL with trailing slash resolves."""
        url = reverse('cmp:certification_slash', kwargs={'domain_name': 'test_domain'})
        assert url == '/.well-known/cmp/p/test_domain/certification/'
        
        resolver = resolve('/.well-known/cmp/p/test_domain/certification/')
        assert resolver.view_name == 'cmp:certification_slash'

    def test_initialization_view_class(self):
        """Test that URL resolver correctly identifies the initialization view."""
        from cmp.views import CmpInitializationRequestView
        
        resolver = resolve('/.well-known/cmp/initialization/test_domain')
        assert resolver.func.view_class == CmpInitializationRequestView

    def test_certification_view_class(self):
        """Test that URL resolver correctly identifies the certification view."""
        from cmp.views import CmpCertificationRequestView
        
        resolver = resolve('/.well-known/cmp/p/test_domain/certification')
        assert resolver.func.view_class == CmpCertificationRequestView
