"""Tests for CMP URL configuration."""

from django.urls import resolve, reverse


class TestCmpUrls:
    """Tests for CMP URL patterns."""

    def test_initialization_old_url_resolves(self):
        """Test that the CMP initialization old demo URL resolves correctly."""
        url = reverse('cmp:initialization_old', kwargs={'domain': 'test_domain'})
        assert url == '/.well-known/cmp/initialization/test_domain'

        resolver = resolve('/.well-known/cmp/initialization/test_domain')
        assert resolver.view_name == 'cmp:initialization_old'
        assert resolver.namespace == 'cmp'
        assert resolver.url_name == 'initialization_old'
        assert resolver.kwargs['domain'] == 'test_domain'

    def test_initialization_old_slash_url_resolves(self):
        """Test that the CMP initialization old demo URL with trailing slash resolves."""
        url = reverse('cmp:initialization_old_slash', kwargs={'domain': 'test_domain'})
        assert url == '/.well-known/cmp/initialization/test_domain/'

        resolver = resolve('/.well-known/cmp/initialization/test_domain/')
        assert resolver.view_name == 'cmp:initialization_old_slash'

    def test_initialization_profile_url_resolves(self):
        """Test that the CMP initialization with profile and operation URL resolves correctly."""
        url = reverse(
            'cmp:req_domain_profile_op',
            kwargs={'domain': 'test_domain', 'cert_profile': 'tls_client', 'operation': 'initialization'},
        )
        assert url == '/.well-known/cmp/p/test_domain/tls_client/initialization'

        resolver = resolve('/.well-known/cmp/p/test_domain/tls_client/initialization')
        assert resolver.view_name == 'cmp:req_domain_profile_op'
        assert resolver.kwargs['domain'] == 'test_domain'
        assert resolver.kwargs['cert_profile'] == 'tls_client'
        assert resolver.kwargs['operation'] == 'initialization'

    def test_initialization_url_resolves(self):
        """Test that the CMP initialization URL resolves correctly."""
        url = reverse(
            'cmp:req_domain_profile_or_op',
            kwargs={'domain': 'test_domain', 'cert_profile_or_operation': 'initialization'},
        )
        assert url == '/.well-known/cmp/p/test_domain/initialization'

        resolver = resolve('/.well-known/cmp/p/test_domain/initialization')
        assert resolver.view_name == 'cmp:req_domain_profile_or_op'
        assert resolver.kwargs['domain'] == 'test_domain'

    def test_certification_template_url_resolves(self):
        """Test that the CMP certification with template URL resolves correctly."""
        url = reverse(
            'cmp:req_domain_profile_op',
            kwargs={'domain': 'test_domain', 'cert_profile': 'tls_server', 'operation': 'certification'},
        )
        assert url == '/.well-known/cmp/p/test_domain/tls_server/certification'

        resolver = resolve('/.well-known/cmp/p/test_domain/tls_server/certification')
        assert resolver.view_name == 'cmp:req_domain_profile_op'
        assert resolver.kwargs['domain'] == 'test_domain'
        assert resolver.kwargs['cert_profile'] == 'tls_server'
        assert resolver.kwargs['operation'] == 'certification'

    def test_certification_url_resolves(self):
        """Test that the CMP certification URL resolves correctly."""
        url = reverse(
            'cmp:req_domain_profile_or_op',
            kwargs={'domain': 'test_domain', 'cert_profile_or_operation': 'certification'},
        )
        assert url == '/.well-known/cmp/p/test_domain/certification'

        resolver = resolve('/.well-known/cmp/p/test_domain/certification')
        assert resolver.view_name == 'cmp:req_domain_profile_or_op'
        assert resolver.kwargs['domain'] == 'test_domain'
        assert 'cert_profile' not in resolver.kwargs or resolver.kwargs['cert_profile'] is None
        assert resolver.kwargs['cert_profile_or_operation'] == 'certification'

    def test_certification_slash_url_resolves(self):
        """Test that the CMP certification URL with trailing slash resolves."""
        url = reverse(
            'cmp:req_domain_profile_or_op_slash',
            kwargs={'domain': 'test_domain', 'cert_profile_or_operation': 'certification'},
        )
        assert url == '/.well-known/cmp/p/test_domain/certification/'

        resolver = resolve('/.well-known/cmp/p/test_domain/certification/')
        assert resolver.view_name == 'cmp:req_domain_profile_or_op_slash'

    def test_initialization_view_class(self):
        """Test that URL resolver correctly identifies the initialization view."""
        from cmp.views import CmpRequestView

        resolver = resolve('/.well-known/cmp/initialization/test_domain')
        assert resolver.func.view_class == CmpRequestView

    def test_certification_view_class(self):
        """Test that URL resolver correctly identifies the certification view."""
        from cmp.views import CmpRequestView

        resolver = resolve('/.well-known/cmp/p/test_domain/certification')
        assert resolver.func.view_class == CmpRequestView
