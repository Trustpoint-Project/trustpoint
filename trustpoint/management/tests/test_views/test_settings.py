"""Test suite for settings views."""
import logging
from unittest.mock import Mock, patch

from django.contrib.messages import get_messages
from django.test import RequestFactory, TestCase
from django.urls import reverse
from management.forms import SecurityConfigForm
from management.models import LoggingConfig, SecurityConfig
from management.views.settings import ChangeLogLevelView, LOG_LEVELS, SettingsView
from notifications.models import NotificationConfig
from pki.util.keys import AutoGenPkiKeyAlgorithm


class SettingsViewTest(TestCase):
    """Test suite for SettingsView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SettingsView()
        self.view.request = self.factory.get('/settings/')
        
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(self.view.request, 'session', 'session')
        messages_storage = FallbackStorage(self.view.request)
        setattr(self.view.request, '_messages', messages_storage)
        
        # Create notification config
        self.notification_config = NotificationConfig.objects.create()
        self.security_config = SecurityConfig.objects.create(
            id=1,
            security_mode=SecurityConfig.SecurityModeChoices.LOW,
            auto_gen_pki=False,
            notification_config=self.notification_config,
        )

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/settings.html')

    def test_form_class(self):
        """Test correct form class is used."""
        self.assertEqual(self.view.form_class, SecurityConfigForm)

    def test_success_url(self):
        """Test success URL is set correctly."""
        self.assertEqual(str(self.view.success_url), reverse('management:settings'))

    def test_page_category_and_name(self):
        """Test page category and name are set correctly."""
        self.assertEqual(self.view.page_category, 'management')
        self.assertEqual(self.view.page_name, 'settings')

    def test_get_form_kwargs_with_existing_config(self):
        """Test get_form_kwargs returns existing SecurityConfig."""
        form_kwargs = self.view.get_form_kwargs()
        
        self.assertIn('instance', form_kwargs)
        self.assertEqual(form_kwargs['instance'], self.security_config)

    def test_get_form_kwargs_creates_config_if_missing(self):
        """Test get_form_kwargs creates SecurityConfig if it doesn't exist."""
        SecurityConfig.objects.all().delete()
        
        form_kwargs = self.view.get_form_kwargs()
        
        self.assertIn('instance', form_kwargs)
        self.assertIsInstance(form_kwargs['instance'], SecurityConfig)
        self.assertIsNotNone(form_kwargs['instance'].notification_config)

    def test_get_context_data_includes_page_info(self):
        """Test get_context_data includes page category and name."""
        context = self.view.get_context_data()
        
        self.assertEqual(context['page_category'], 'management')
        self.assertEqual(context['page_name'], 'settings')

    def test_get_context_data_includes_log_levels(self):
        """Test get_context_data includes log levels."""
        context = self.view.get_context_data()
        
        self.assertIn('loglevels', context)
        self.assertEqual(context['loglevels'], LOG_LEVELS)

    def test_get_context_data_includes_current_log_level(self):
        """Test get_context_data includes current log level."""
        context = self.view.get_context_data()
        
        self.assertIn('current_loglevel', context)
        self.assertIsInstance(context['current_loglevel'], str)

    def test_get_context_data_includes_notification_configs(self):
        """Test get_context_data includes notification configurations JSON."""
        context = self.view.get_context_data()
        
        self.assertIn('notification_configurations_json', context)
        import json
        config_json = json.loads(context['notification_configurations_json'])
        self.assertIsInstance(config_json, dict)
        # Should have entries for all security modes
        self.assertIn(SecurityConfig.SecurityModeChoices.DEV, config_json)
        self.assertIn(SecurityConfig.SecurityModeChoices.LOW, config_json)

    @patch.object(SecurityConfig, 'apply_security_settings')
    def test_form_valid_saves_and_applies_settings(self, mock_apply):
        """Test form_valid saves form and applies security settings."""
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = []
        form.save = Mock()
        
        self.view.form_valid(form)
        
        form.save.assert_called_once()

    @patch.object(SecurityConfig, 'apply_security_settings')
    def test_form_valid_resets_settings_on_security_mode_increase(self, mock_apply):
        """Test form_valid resets settings when security mode is increased."""
        mock_sec = Mock()
        self.view.sec = mock_sec
        
        # Change from LOW (1) to HIGH (3)
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.LOW
        self.security_config.save()
        
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = ['security_mode']
        form.cleaned_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.HIGH
        }
        form.save = Mock()
        
        self.view.form_valid(form)
        
        mock_sec.reset_settings.assert_called_once_with(SecurityConfig.SecurityModeChoices.HIGH)

    @patch('management.security.features.AutoGenPkiFeature.enable')
    @patch.object(SecurityConfig, 'apply_security_settings')
    def test_form_valid_enables_auto_gen_pki(self, mock_apply, mock_enable):
        """Test form_valid enables AutoGenPkiFeature when auto_gen_pki is enabled."""
        mock_sec = Mock()
        mock_sec.enable_feature = Mock()
        self.view.sec = mock_sec
        
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = ['auto_gen_pki']
        form.cleaned_data = {
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048,
        }
        form.save = Mock()
        
        self.view.form_valid(form)
        
        mock_sec.enable_feature.assert_called_once()

    @patch('management.security.features.AutoGenPkiFeature.disable')
    @patch.object(SecurityConfig, 'apply_security_settings')
    def test_form_valid_disables_auto_gen_pki(self, mock_apply, mock_disable):
        """Test form_valid disables AutoGenPkiFeature when auto_gen_pki is disabled."""
        # Start with it enabled
        self.security_config.auto_gen_pki = True
        self.security_config.save()
        
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = ['auto_gen_pki']
        form.cleaned_data = {
            'auto_gen_pki': False,
        }
        form.save = Mock()
        
        self.view.form_valid(form)
        
        mock_disable.assert_called_once()

    def test_form_valid_shows_success_message(self):
        """Test form_valid displays success message."""
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = []
        form.save = Mock()
        
        with patch.object(SecurityConfig, 'apply_security_settings'):
            self.view.form_valid(form)
        
        messages_list = list(get_messages(self.view.request))
        self.assertEqual(len(messages_list), 1)
        self.assertIn('saved successfully', str(messages_list[0]))

    def test_form_valid_handles_missing_security_mode(self):
        """Test form_valid handles missing security_mode value."""
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = ['security_mode']
        form.cleaned_data = {'security_mode': None}
        form.save = Mock()
        
        with patch.object(SecurityConfig, 'apply_security_settings'):
            response = self.view.form_valid(form)
        
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('missing' in str(msg).lower() for msg in messages_list))

    def test_form_valid_handles_missing_key_algorithm(self):
        """Test form_valid handles missing key algorithm when enabling auto_gen_pki."""
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = ['auto_gen_pki']
        form.cleaned_data = {
            'auto_gen_pki': True,
            'auto_gen_pki_key_algorithm': None,
        }
        form.save = Mock()
        
        with patch.object(SecurityConfig, 'apply_security_settings'):
            response = self.view.form_valid(form)
        
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('missing' in str(msg).lower() for msg in messages_list))

    def test_form_invalid_shows_error_message(self):
        """Test form_invalid displays error message."""
        form = Mock(spec=SecurityConfigForm)
        
        with patch.object(self.view, 'render_to_response') as mock_render:
            self.view.form_invalid(form)
        
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('error' in str(msg).lower() for msg in messages_list))

    def test_inherits_from_form_view(self):
        """Test SettingsView inherits from FormView."""
        from django.views.generic.edit import FormView
        self.assertTrue(issubclass(SettingsView, FormView))


class ChangeLogLevelViewTest(TestCase):
    """Test suite for ChangeLogLevelView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = ChangeLogLevelView()
        
        # Save original log level
        self.original_level = logging.getLogger().getEffectiveLevel()

    def tearDown(self):
        """Restore original log level."""
        logging.getLogger().setLevel(self.original_level)

    def test_post_with_valid_log_level(self):
        """Test POST with valid log level updates logger and database."""
        request = self.factory.post('/change-log-level/', {'loglevel': 'DEBUG'})
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        response = self.view.post(request)
        
        # Check logger was updated
        self.assertEqual(logging.getLogger().getEffectiveLevel(), logging.DEBUG)
        
        # Check database was updated
        config = LoggingConfig.objects.get(id=1)
        self.assertEqual(config.log_level, 'DEBUG')
        
        # Check success message
        messages_list = list(get_messages(request))
        self.assertTrue(any('DEBUG' in str(msg) for msg in messages_list))
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('management:settings'))

    def test_post_with_invalid_log_level(self):
        """Test POST with invalid log level shows error."""
        request = self.factory.post('/change-log-level/', {'loglevel': 'INVALID'})
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        original_level = logging.getLogger().getEffectiveLevel()
        
        response = self.view.post(request)
        
        # Logger should not be changed
        self.assertEqual(logging.getLogger().getEffectiveLevel(), original_level)
        
        # Check error message
        messages_list = list(get_messages(request))
        self.assertTrue(any('invalid' in str(msg).lower() for msg in messages_list))

    def test_post_with_lowercase_log_level(self):
        """Test POST with lowercase log level (gets converted to uppercase)."""
        request = self.factory.post('/change-log-level/', {'loglevel': 'info'})
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.post(request)
        
        # Should be converted to uppercase and accepted
        self.assertEqual(logging.getLogger().getEffectiveLevel(), logging.INFO)

    def test_post_with_empty_log_level(self):
        """Test POST with empty log level shows error."""
        request = self.factory.post('/change-log-level/', {'loglevel': ''})
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.post(request)
        
        messages_list = list(get_messages(request))
        self.assertTrue(any('invalid' in str(msg).lower() for msg in messages_list))

    def test_post_updates_existing_logging_config(self):
        """Test POST updates existing LoggingConfig instead of creating new one."""
        # Create initial config
        LoggingConfig.objects.create(id=1, log_level='INFO')
        
        request = self.factory.post('/change-log-level/', {'loglevel': 'WARNING'})
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.post(request)
        
        # Should still only be one config
        self.assertEqual(LoggingConfig.objects.count(), 1)
        # And it should be updated
        config = LoggingConfig.objects.get(id=1)
        self.assertEqual(config.log_level, 'WARNING')

    def test_post_with_all_valid_log_levels(self):
        """Test POST works with all valid log levels."""
        for level in LOG_LEVELS:
            request = self.factory.post('/change-log-level/', {'loglevel': level})
            # Enable message storage
            from django.contrib.messages.storage.fallback import FallbackStorage
            setattr(request, 'session', 'session')
            messages_storage = FallbackStorage(request)
            setattr(request, '_messages', messages_storage)
            
            self.view.post(request)
            
            expected_level = getattr(logging, level)
            self.assertEqual(logging.getLogger().getEffectiveLevel(), expected_level)

    def test_inherits_from_view(self):
        """Test ChangeLogLevelView inherits from View."""
        from django.views import View
        self.assertTrue(issubclass(ChangeLogLevelView, View))


class LogLevelsConstantTest(TestCase):
    """Test suite for LOG_LEVELS constant."""

    def test_log_levels_contains_all_standard_levels(self):
        """Test LOG_LEVELS contains all standard Python logging levels."""
        expected_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        self.assertEqual(LOG_LEVELS, expected_levels)

    def test_log_levels_order_is_correct(self):
        """Test LOG_LEVELS are in ascending severity order."""
        level_values = [getattr(logging, level) for level in LOG_LEVELS]
        self.assertEqual(level_values, sorted(level_values))
