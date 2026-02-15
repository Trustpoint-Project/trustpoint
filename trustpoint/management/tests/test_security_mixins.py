"""Test suite for security mixins."""

from django.contrib import messages
from django.http import HttpResponse
from django.test import RequestFactory, TestCase
from django.views import View
from management.models import SecurityConfig
from management.security.features import AutoGenPkiFeature, SecurityFeature
from management.security.mixins import SecurityLevelMixin, SecurityLevelMixinRedirect


class MockSecurityFeature(SecurityFeature):
    """Mock security feature for testing."""

    verbose_name = 'Mock Feature'
    db_field_name = 'mock_feature'
    value = 'mock_feature_value'  # For error message

    def enable(self, **kwargs: object) -> None:
        """Mock enable method."""
        pass

    def disable(self, **kwargs: object) -> None:
        """Mock disable method."""
        pass

    def is_enabled(self) -> bool:
        """Mock is_enabled method."""
        return True


class SecurityLevelMixinTest(TestCase):
    """Test suite for SecurityLevelMixin."""

    def setUp(self):
        """Set up test fixtures."""
        self.security_config = SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.LOW,
            auto_gen_pki=False,
        )
        self.factory = RequestFactory()

    def test_init_creates_security_manager(self):
        """Test __init__ creates a SecurityManager instance."""
        mixin = SecurityLevelMixin()
        self.assertIsNotNone(mixin.sec)

    def test_init_with_security_feature(self):
        """Test __init__ accepts security_feature parameter."""
        feature = MockSecurityFeature()
        mixin = SecurityLevelMixin(security_feature=feature)
        self.assertEqual(mixin.security_feature, feature)

    def test_init_without_security_feature(self):
        """Test __init__ works without security_feature parameter."""
        mixin = SecurityLevelMixin()
        self.assertIsNone(mixin.security_feature)

    def test_get_security_level_returns_current_level(self):
        """Test get_security_level returns the current security mode."""
        mixin = SecurityLevelMixin()
        self.assertEqual(mixin.get_security_level(), SecurityConfig.SecurityModeChoices.LOW)

    def test_get_security_level_with_different_modes(self):
        """Test get_security_level with different security modes."""
        mixin = SecurityLevelMixin()

        for mode in SecurityConfig.SecurityModeChoices:
            self.security_config.security_mode = mode
            self.security_config.save()
            self.assertEqual(mixin.get_security_level(), mode)

    def test_mixin_can_be_used_with_view_class(self):
        """Test SecurityLevelMixin can be used in a view class."""

        class TestView(SecurityLevelMixin, View):
            def __init__(self, **kwargs):
                super().__init__(security_feature=MockSecurityFeature(), **kwargs)

            def get(self, request):
                return HttpResponse('Test response')

        view = TestView()
        self.assertIsNotNone(view.sec)
        self.assertIsInstance(view.security_feature, MockSecurityFeature)


class SecurityLevelMixinRedirectTest(TestCase):
    """Test suite for SecurityLevelMixinRedirect."""

    def setUp(self):
        """Set up test fixtures."""
        self.security_config = SecurityConfig.objects.create(
            security_mode=SecurityConfig.SecurityModeChoices.LOW,
            auto_gen_pki=False,
        )
        self.factory = RequestFactory()

    def test_init_with_redirect_url(self):
        """Test __init__ accepts disabled_by_security_level_url parameter."""
        mixin = SecurityLevelMixinRedirect(disabled_by_security_level_url='/redirect/')
        self.assertEqual(mixin.disabled_by_security_level_url, '/redirect/')

    def test_init_without_redirect_url(self):
        """Test __init__ works without disabled_by_security_level_url parameter."""
        mixin = SecurityLevelMixinRedirect()
        self.assertIsNone(mixin.disabled_by_security_level_url)

    def test_dispatch_allows_access_when_feature_allowed(self):
        """Test dispatch allows access when feature is allowed."""

        class TestView(SecurityLevelMixinRedirect, View):
            def __init__(self, **kwargs):
                super().__init__(
                    security_feature=AutoGenPkiFeature,
                    disabled_by_security_level_url='/denied/',
                    **kwargs
                )

            def get(self, request):
                return HttpResponse('Allowed')

        # Set to LOW where AutoGenPkiFeature is allowed
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        request = self.factory.get('/test/')
        view = TestView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'Allowed')

    def test_dispatch_redirects_when_feature_not_allowed(self):
        """Test dispatch redirects when feature is not allowed."""

        class TestView(SecurityLevelMixinRedirect, View):
            def __init__(self, **kwargs):
                super().__init__(
                    security_feature=MockSecurityFeature,
                    disabled_by_security_level_url='/denied/',
                    **kwargs
                )

            def get(self, request):
                return HttpResponse('Should not reach here')

        # Set to HIGHEST where MockSecurityFeature is not allowed
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.HIGHEST
        self.security_config.save()

        request = self.factory.get('/test/')
        # Enable message storage for the request
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        view = TestView.as_view()
        response = view(request)

        # Should redirect
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/denied/')

    def test_dispatch_adds_error_message_on_redirect(self):
        """Test dispatch adds error message when redirecting due to security level."""

        class TestView(SecurityLevelMixinRedirect, View):
            def __init__(self, **kwargs):
                super().__init__(
                    security_feature=MockSecurityFeature,
                    disabled_by_security_level_url='/denied/',
                    **kwargs
                )

            def get(self, request):
                return HttpResponse('Should not reach here')

        # Set to HIGHEST where MockSecurityFeature is not allowed
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.HIGHEST
        self.security_config.save()

        request = self.factory.get('/test/')
        # Enable message storage for the request
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        view = TestView.as_view()
        response = view(request)

        # Check that error message was added
        all_messages = list(messages.get_messages(request))
        self.assertEqual(len(all_messages), 1)
        self.assertIn('security setting', str(all_messages[0]))
        self.assertIn('does not allow', str(all_messages[0]))

    def test_dispatch_calls_parent_dispatch_when_allowed(self):
        """Test dispatch calls parent dispatch method when feature is allowed."""

        class TestView(SecurityLevelMixinRedirect, View):
            def __init__(self, **kwargs):
                super().__init__(
                    security_feature=AutoGenPkiFeature,
                    disabled_by_security_level_url='/denied/',
                    **kwargs
                )

            def dispatch(self, request, *args, **kwargs):
                # Call parent dispatch
                response = super().dispatch(request, *args, **kwargs)
                # Add custom header to verify parent dispatch was called
                response['X-Parent-Called'] = 'true'
                return response

            def get(self, request):
                return HttpResponse('Allowed')

        # Set to LOW where AutoGenPkiFeature is allowed
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        request = self.factory.get('/test/')
        view = TestView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-Parent-Called'], 'true')

    def test_mixin_with_post_request(self):
        """Test mixin works with POST requests."""

        class TestView(SecurityLevelMixinRedirect, View):
            def __init__(self, **kwargs):
                super().__init__(
                    security_feature=AutoGenPkiFeature,
                    disabled_by_security_level_url='/denied/',
                    **kwargs
                )

            def post(self, request):
                return HttpResponse('Posted')

        # Set to LOW where AutoGenPkiFeature is allowed
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        request = self.factory.post('/test/')
        view = TestView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'Posted')

    def test_mixin_with_args_and_kwargs(self):
        """Test mixin passes args and kwargs to parent dispatch."""

        class TestView(SecurityLevelMixinRedirect, View):
            def __init__(self, **kwargs):
                super().__init__(
                    security_feature=AutoGenPkiFeature,
                    disabled_by_security_level_url='/denied/',
                    **kwargs
                )

            def get(self, request, pk, slug=None):
                return HttpResponse(f'pk={pk}, slug={slug}')

        # Set to LOW where AutoGenPkiFeature is allowed
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()

        request = self.factory.get('/test/123/my-slug/')
        view = TestView.as_view()
        response = view(request, pk=123, slug='my-slug')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'pk=123, slug=my-slug')

    def test_inherits_from_security_level_mixin(self):
        """Test SecurityLevelMixinRedirect inherits from SecurityLevelMixin."""
        self.assertTrue(issubclass(SecurityLevelMixinRedirect, SecurityLevelMixin))

    def test_has_access_to_parent_methods(self):
        """Test SecurityLevelMixinRedirect has access to parent mixin methods."""
        mixin = SecurityLevelMixinRedirect()
        self.assertTrue(hasattr(mixin, 'get_security_level'))
        self.assertTrue(callable(mixin.get_security_level))
        self.assertTrue(hasattr(mixin, 'sec'))

    def test_dispatch_with_dev_mode_allows_all_features(self):
        """Test dispatch allows all features in DEV mode."""

        class TestView(SecurityLevelMixinRedirect, View):
            def __init__(self, **kwargs):
                super().__init__(
                    security_feature=MockSecurityFeature,
                    disabled_by_security_level_url='/denied/',
                    **kwargs
                )

            def get(self, request):
                return HttpResponse('Dev mode allowed')

        # Set to DEV where all features are allowed
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.DEV
        self.security_config.save()

        request = self.factory.get('/test/')
        view = TestView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'Dev mode allowed')
