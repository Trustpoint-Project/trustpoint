"""Test suite for settings views."""
import logging
import smtplib
from unittest.mock import Mock, patch

from django.conf import settings as django_settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages import get_messages
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from management.forms import SecurityConfigForm, SmtpEmailConfigForm, SmtpEmailTestForm
from management.models import LoggingConfig, SecurityConfig, SmtpEmailConfig
from management.views.settings import ChangeLogLevelView, SecuritySettingsView, SettingsTabView, MetricsSettingsView
from pki.util.keys import AutoGenPkiKeyAlgorithm

LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']


class SecuritySettingsViewTest(TestCase):
    """Test suite for SecuritySettingsView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SecuritySettingsView()
        self.view.request = self.factory.get('/settings/security/')
        self.view.request.user = AnonymousUser()

        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(self.view.request, 'session', 'session')
        messages_storage = FallbackStorage(self.view.request)
        setattr(self.view.request, '_messages', messages_storage)

        # Create security config
        self.security_config = SecurityConfig.objects.create(
            id=1,
            security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD,
            auto_gen_pki=False,
        )

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/includes/security_configuration.html')

    def test_form_class(self):
        """Test correct form class is used."""
        self.assertEqual(self.view.form_class, SecurityConfigForm)

    def test_success_url(self):
        """Test success URL is set correctly."""
        self.assertEqual(str(self.view.success_url), reverse('management:settings-security'))

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

    def test_get_context_data_includes_page_info(self):
        """Test get_context_data includes page category and name."""
        context = self.view.get_context_data()
        
        self.assertEqual(context['page_category'], 'management')
        self.assertEqual(context['page_name'], 'settings')

    def test_get_context_data_includes_notification_configs(self):
        """Test get_context_data includes notification configurations JSON."""
        context = self.view.get_context_data()
        
        self.assertIn('notification_configurations_json', context)
        import json
        config_json = json.loads(context['notification_configurations_json'])
        self.assertIsInstance(config_json, dict)
        # Should have entries for all security modes
        self.assertIn(SecurityConfig.SecurityModeChoices.LAB, config_json)
        self.assertIn(SecurityConfig.SecurityModeChoices.BROWNFIELD, config_json)

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
        
        # Change from BROWNFIELD (1) to HARDENED (3)
        self.security_config.security_mode = SecurityConfig.SecurityModeChoices.BROWNFIELD
        self.security_config.save()
        
        form = Mock(spec=SecurityConfigForm)
        form.instance = self.security_config
        form.instance.pk = 1
        form.changed_data = ['security_mode']
        form.cleaned_data = {
            'security_mode': SecurityConfig.SecurityModeChoices.HARDENED
        }
        form.save = Mock()
        
        self.view.form_valid(form)
        
        mock_sec.reset_settings.assert_called_once_with(SecurityConfig.SecurityModeChoices.HARDENED)

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
            self.view.form_valid(form)
        
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
            self.view.form_valid(form)
        
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('missing' in str(msg).lower() for msg in messages_list))

    def test_form_invalid_shows_error_message(self):
        """Test form_invalid displays error message."""
        form = Mock(spec=SecurityConfigForm)

        with patch.object(self.view, 'render_to_response') as mock_render_to_response:
            self.view.form_invalid(form)

        context = mock_render_to_response.call_args.args[0]
        self.assertEqual(context['security_form'], form)
        self.assertIn('ui_form', context)
        self.assertIn('workflow_execution_form', context)
        self.assertIn('smtp_email_form', context)
        self.assertIn('prometheus_form', context)
        messages_list = list(get_messages(self.view.request))
        self.assertTrue(any('error' in str(msg).lower() for msg in messages_list))

    def test_form_invalid_renders_full_settings_page(self):
        """Test invalid security submissions render all settings tabs without crispy form crashes."""
        form = SecurityConfigForm(
            data={
                'security_mode': SecurityConfig.SecurityModeChoices.HARDENED,
                'auto_gen_pki': False,
                'auto_gen_pki_key_algorithm': AutoGenPkiKeyAlgorithm.RSA2048,
                'rsa_minimum_key_size': 1024,
                'max_cert_validity_days': 365,
                'max_crl_validity_days': 90,
                'allow_ca_issuance': True,
                'allow_auto_gen_pki': False,
                'allow_self_signed_ca': False,
            },
            instance=self.security_config,
        )
        self.assertFalse(form.is_valid())

        response = self.view.form_invalid(form)
        response.render()

        self.assertEqual(response.status_code, 200)

    def test_inherits_from_form_view(self):
        """Test SecuritySettingsView inherits from FormView."""
        from django.views.generic.edit import FormView
        self.assertTrue(issubclass(SecuritySettingsView, FormView))


class SettingsTabViewTest(TestCase):
    """Test suite for SettingsTabView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SettingsTabView()
        self.view.request = self.factory.get('/settings/')

        # Create security config
        SecurityConfig.objects.create(
            id=1,
            security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD,
            auto_gen_pki=False,
        )

    def test_template_name(self):
        """Test correct template is used."""
        self.assertEqual(self.view.template_name, 'management/settings.html')

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

    def test_get_context_data_includes_workflow_and_smtp_forms(self):
        """Test get_context_data includes inline settings forms."""
        context = self.view.get_context_data()

        self.assertIn('workflow_execution_form', context)
        self.assertIn('smtp_email_form', context)
        self.assertIn('smtp_email_test_form', context)
        self.assertIsInstance(context['smtp_email_form'], SmtpEmailConfigForm)
        self.assertIsInstance(context['smtp_email_test_form'], SmtpEmailTestForm)

    @override_settings(
        EMAIL_BACKEND='django.core.mail.backends.console.EmailBackend',
        DEFAULT_FROM_EMAIL='before@example.com',
    )
    def test_post_smtp_email_settings_saves_and_applies_runtime_settings(self):
        """Test SMTP email settings can be saved from the tab view."""
        request = self.factory.post('/settings/', {
            'form_name': 'smtp_email',
            'enabled': 'on',
            'host': 'smtp.example.com',
            'port': '2525',
            'use_tls': 'on',
            'username': 'mailer',
            'password': 'secret',
            'timeout_seconds': '15',
            'default_from_email': 'no-reply@example.com',
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        response = self.view.post(request)

        smtp_config = SmtpEmailConfig.load()
        self.assertEqual(response.status_code, 302)
        self.assertIn('tab=smtp-email', response.url)
        self.assertTrue(smtp_config.enabled)
        self.assertEqual(smtp_config.host, 'smtp.example.com')
        self.assertEqual(django_settings.EMAIL_BACKEND, SmtpEmailConfig.SMTP_BACKEND)
        self.assertEqual(django_settings.EMAIL_HOST, 'smtp.example.com')
        self.assertEqual(django_settings.EMAIL_PORT, 2525)
        self.assertEqual(django_settings.DEFAULT_FROM_EMAIL, 'no-reply@example.com')

    def test_post_smtp_email_test_sends_using_current_form_settings(self):
        """Test SMTP email test sends through the current unsaved form configuration."""
        SmtpEmailConfig.objects.create(
            enabled=True,
            host='smtp.example.com',
            port=2525,
            default_from_email='saved@example.com',
        )
        request = self.factory.post('/settings/', {
            'form_name': 'smtp_email_test',
            'enabled': 'on',
            'host': 'smtp.example.com',
            'port': '2525',
            'timeout_seconds': '15',
            'default_from_email': 'unsaved@example.com',
            'recipient': 'admin@example.com',
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        def fake_send_test_email(config: SmtpEmailConfig, recipient: str) -> int:
            self.assertEqual(config.default_from_email, 'unsaved@example.com')
            self.assertEqual(recipient, 'admin@example.com')
            return 1

        with patch.object(SmtpEmailConfig, 'send_test_email', autospec=True, side_effect=fake_send_test_email) as mock_send:
            response = self.view.post(request)

        self.assertEqual(response.status_code, 302)
        self.assertIn('tab=smtp-email', response.url)
        mock_send.assert_called_once()
        messages_list = list(get_messages(request))
        self.assertTrue(any('sent to admin@example.com' in str(msg) for msg in messages_list))

    @patch.object(SmtpEmailConfig, 'send_test_email', side_effect=smtplib.SMTPNotSupportedError)
    def test_post_smtp_email_test_clears_auth_when_server_does_not_support_auth(self, mock_send_test_email):
        """Test unsupported SMTP AUTH clears username and password in the rendered form."""
        SmtpEmailConfig.objects.create(
            enabled=True,
            host='smtp.example.com',
            port=2525,
            default_from_email='saved@example.com',
        )
        request = self.factory.post('/settings/', {
            'form_name': 'smtp_email_test',
            'enabled': 'on',
            'host': 'smtp.example.com',
            'port': '2525',
            'username': 'admin',
            'password': 'secret',
            'timeout_seconds': '15',
            'default_from_email': 'unsaved@example.com',
            'recipient': 'admin@example.com',
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        response = self.view.post(request)

        self.assertEqual(response.status_code, 200)
        mock_send_test_email.assert_called_once()
        smtp_email_form = response.context_data['smtp_email_form']
        self.assertEqual(smtp_email_form.data['username'], '')
        self.assertEqual(smtp_email_form.data['password'], '')
        messages_list = list(get_messages(request))
        self.assertTrue(any('Username and password were cleared' in str(msg) for msg in messages_list))

    @patch.object(SmtpEmailConfig, 'send_test_email', return_value=1)
    def test_post_smtp_email_test_requires_enabled_smtp(self, mock_send_test_email):
        """Test SMTP email test requires enabled SMTP settings in the current form."""
        SmtpEmailConfig.objects.create(
            enabled=True,
            host='smtp.example.com',
            port=2525,
            default_from_email='no-reply@example.com',
        )
        request = self.factory.post('/settings/', {
            'form_name': 'smtp_email_test',
            'host': 'smtp.example.com',
            'port': '2525',
            'timeout_seconds': '15',
            'default_from_email': 'no-reply@example.com',
            'recipient': 'admin@example.com',
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        response = self.view.post(request)

        self.assertEqual(response.status_code, 200)
        mock_send_test_email.assert_not_called()
        messages_list = list(get_messages(request))
        self.assertTrue(any('Enable SMTP email delivery' in str(msg) for msg in messages_list))

    @patch.object(SmtpEmailConfig, 'send_test_email', return_value=1)
    def test_post_smtp_email_test_with_invalid_security_settings_rerenders(self, mock_send_test_email):
        """Test invalid SMTP security settings re-render without binding unrelated settings forms."""
        SmtpEmailConfig.objects.create(
            enabled=True,
            host='smtp.example.com',
            port=2525,
            default_from_email='no-reply@example.com',
        )
        request = self.factory.post('/settings/', {
            'form_name': 'smtp_email_test',
            'enabled': 'on',
            'host': 'smtp.example.com',
            'port': '2525',
            'use_tls': 'on',
            'use_ssl': 'on',
            'timeout_seconds': '15',
            'default_from_email': 'no-reply@example.com',
            'recipient': 'admin@example.com',
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        response = self.view.post(request)

        self.assertEqual(response.status_code, 200)
        mock_send_test_email.assert_not_called()
        messages_list = list(get_messages(request))
        self.assertTrue(any('correct the SMTP email settings' in str(msg) for msg in messages_list))

    def test_inherits_from_template_view(self):
        """Test SettingsTabView inherits from TemplateView."""
        from django.views.generic import TemplateView
        self.assertTrue(issubclass(SettingsTabView, TemplateView))


class SmtpEmailConfigFormTest(TestCase):
    """Test suite for SmtpEmailConfigForm."""

    def test_valid_enabled_smtp_config(self):
        """Test a complete enabled SMTP configuration is valid."""
        form = SmtpEmailConfigForm(data={
            'enabled': 'on',
            'host': 'smtp.example.com',
            'port': '587',
            'use_tls': 'on',
            'username': 'mailer',
            'password': 'secret',
            'timeout_seconds': '10',
            'default_from_email': 'no-reply@example.com',
        })

        self.assertTrue(form.is_valid(), form.errors)

    def test_enabled_requires_host(self):
        """Test SMTP host is required when delivery is enabled."""
        form = SmtpEmailConfigForm(data={
            'enabled': 'on',
            'host': '',
            'port': '587',
            'timeout_seconds': '10',
            'default_from_email': 'no-reply@example.com',
        })

        self.assertFalse(form.is_valid())
        self.assertIn('host', form.errors)

    def test_tls_and_ssl_are_mutually_exclusive(self):
        """Test STARTTLS and SSL/TLS cannot be enabled together."""
        form = SmtpEmailConfigForm(data={
            'enabled': 'on',
            'host': 'smtp.example.com',
            'port': '465',
            'use_tls': 'on',
            'use_ssl': 'on',
            'timeout_seconds': '10',
            'default_from_email': 'no-reply@example.com',
        })

        self.assertFalse(form.is_valid())
        self.assertIn('use_ssl', form.errors)


class SmtpEmailTestFormTest(TestCase):
    """Test suite for SmtpEmailTestForm."""

    def test_valid_recipient(self):
        """Test valid recipient email is accepted."""
        form = SmtpEmailTestForm(data={'recipient': 'admin@example.com'})

        self.assertTrue(form.is_valid(), form.errors)

    def test_invalid_recipient(self):
        """Test invalid recipient email is rejected."""
        form = SmtpEmailTestForm(data={'recipient': 'not-an-email'})

        self.assertFalse(form.is_valid())
        self.assertIn('recipient', form.errors)



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
        self.assertTrue(any('updated successfully' in str(msg).lower() for msg in messages_list))
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('management:settings')))

    def test_post_with_invalid_log_level(self):
        """Test POST with invalid log level shows error."""
        request = self.factory.post('/change-log-level/', {'loglevel': 'INVALID'})
        # Enable message storage
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        original_level = logging.getLogger().getEffectiveLevel()
        
        self.view.post(request)
        
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


class MetricsSettingsViewTest(TestCase):
    """Test suite for MetricsSettingsView."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_get_context_data(self):
        """Test get_context_data returns expected values."""
        request = self.factory.get('/settings/')
        view = MetricsSettingsView()
        view.request = request

        context = view.get_context_data()

        self.assertIn('uptime', context)
        self.assertIn('started_time', context)
        self.assertIn('database_size', context)


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
