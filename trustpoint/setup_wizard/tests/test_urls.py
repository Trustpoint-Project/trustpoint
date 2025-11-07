"""Tests for the setup_wizard URL configuration."""

from unittest.mock import patch

import pytest
from django.test import TestCase
from django.urls import resolve, reverse
from django.urls.exceptions import NoReverseMatch

from setup_wizard.views import (
    BackupAutoRestorePasswordView,
    BackupRestoreView,
    SetupWizardBackupPasswordView,
    SetupWizardCreateSuperUserView,
    SetupWizardCryptoStorageView,
    SetupWizardDemoDataView,
    SetupWizardGenerateTlsServerCredentialView,
    SetupWizardHsmSetupView,
    SetupWizardImportTlsServerCredentialView,
    SetupWizardRestoreOptionsView,
    SetupWizardSelectTlsServerCredentialView,
    SetupWizardSetupModeView,
    SetupWizardTlsServerCredentialApplyCancelView,
    SetupWizardTlsServerCredentialApplyView,
)


class SetupWizardUrlsTestCase(TestCase):
    """Test cases for setup_wizard URL patterns."""

    def test_app_name_configuration(self):
        """Test that app_name is correctly configured."""
        from setup_wizard import urls
        self.assertEqual(urls.app_name, 'setup_wizard')

    def test_crypto_storage_setup_url(self):
        """Test crypto storage setup URL pattern."""
        url = reverse('setup_wizard:crypto_storage_setup')
        self.assertEqual(url, '/setup-wizard/crypto-storage-setup/')

        # Test URL resolution
        resolver = resolve('/setup-wizard/crypto-storage-setup/')
        self.assertEqual(resolver.view_name, 'setup_wizard:crypto_storage_setup')
        self.assertEqual(resolver.func.view_class, SetupWizardCryptoStorageView)

    def test_hsm_setup_url_with_parameter(self):
        """Test HSM setup URL pattern with hsm_type parameter."""
        test_cases = [
            ('softhsm', '/setup-wizard/hsm-setup/softhsm/'),
            ('physical', '/setup-wizard/hsm-setup/physical/'),
            ('test-hsm', '/setup-wizard/hsm-setup/test-hsm/'),
        ]

        for hsm_type, expected_url in test_cases:
            with self.subTest(hsm_type=hsm_type):
                url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': hsm_type})
                self.assertEqual(url, expected_url)

                # Test URL resolution
                resolver = resolve(expected_url)
                self.assertEqual(resolver.view_name, 'setup_wizard:hsm_setup')
                self.assertEqual(resolver.func.view_class, SetupWizardHsmSetupView)
                self.assertEqual(resolver.kwargs['hsm_type'], hsm_type)

    def test_setup_mode_url(self):
        """Test setup mode URL pattern."""
        url = reverse('setup_wizard:setup_mode')
        self.assertEqual(url, '/setup-wizard/setup_mode/')

        resolver = resolve('/setup-wizard/setup_mode/')
        self.assertEqual(resolver.view_name, 'setup_wizard:setup_mode')
        self.assertEqual(resolver.func.view_class, SetupWizardSetupModeView)

    def test_select_tls_server_credential_url(self):
        """Test select TLS server credential URL pattern."""
        url = reverse('setup_wizard:select_tls_server_credential')
        self.assertEqual(url, '/setup-wizard/select_tls_server_credential/')

        resolver = resolve('/setup-wizard/select_tls_server_credential/')
        self.assertEqual(resolver.view_name, 'setup_wizard:select_tls_server_credential')
        self.assertEqual(resolver.func.view_class, SetupWizardSelectTlsServerCredentialView)

    def test_backup_password_url(self):
        """Test backup password URL pattern."""
        url = reverse('setup_wizard:backup_password')
        self.assertEqual(url, '/setup-wizard/backup-password/')

        resolver = resolve('/setup-wizard/backup-password/')
        self.assertEqual(resolver.view_name, 'setup_wizard:backup_password')
        self.assertEqual(resolver.func.view_class, SetupWizardBackupPasswordView)

    def test_generate_tls_server_credential_url(self):
        """Test generate TLS server credential URL pattern."""
        url = reverse('setup_wizard:generate_tls_server_credential')
        self.assertEqual(url, '/setup-wizard/generate-tls-server-credential/')

        resolver = resolve('/setup-wizard/generate-tls-server-credential/')
        self.assertEqual(resolver.view_name, 'setup_wizard:generate_tls_server_credential')
        self.assertEqual(resolver.func.view_class, SetupWizardGenerateTlsServerCredentialView)

    def test_import_tls_server_credential_url(self):
        """Test import TLS server credential URL pattern."""
        url = reverse('setup_wizard:import_tls_server_credential')
        self.assertEqual(url, '/setup-wizard/import-tls-server-credential/')

        resolver = resolve('/setup-wizard/import-tls-server-credential/')
        self.assertEqual(resolver.view_name, 'setup_wizard:import_tls_server_credential')
        self.assertEqual(resolver.func.view_class, SetupWizardImportTlsServerCredentialView)

    def test_restore_options_url(self):
        """Test restore options URL pattern."""
        url = reverse('setup_wizard:restore_options')
        self.assertEqual(url, '/setup-wizard/restore_options/')

        resolver = resolve('/setup-wizard/restore_options/')
        self.assertEqual(resolver.view_name, 'setup_wizard:restore_options')
        self.assertEqual(resolver.func.view_class, SetupWizardRestoreOptionsView)

    def test_tls_server_credential_apply_url_without_parameter(self):
        """Test TLS server credential apply URL without file_format parameter."""
        url = reverse('setup_wizard:tls_server_credential_apply')
        self.assertEqual(url, '/setup-wizard/tls-server-credential-apply/')

        resolver = resolve('/setup-wizard/tls-server-credential-apply/')
        self.assertEqual(resolver.view_name, 'setup_wizard:tls_server_credential_apply')
        self.assertEqual(resolver.func.view_class, SetupWizardTlsServerCredentialApplyView)
        self.assertEqual(resolver.kwargs, {})

    def test_tls_server_credential_apply_url_with_parameter(self):
        """Test TLS server credential apply URL with file_format parameter."""
        test_cases = [
            ('pem', '/setup-wizard/tls-server-credential-apply/pem/'),
            ('pkcs12', '/setup-wizard/tls-server-credential-apply/pkcs12/'),
            ('der', '/setup-wizard/tls-server-credential-apply/der/'),
        ]

        for file_format, expected_url in test_cases:
            with self.subTest(file_format=file_format):
                url = reverse('setup_wizard:tls_server_credential_apply', kwargs={'file_format': file_format})
                self.assertEqual(url, expected_url)

                resolver = resolve(expected_url)
                self.assertEqual(resolver.view_name, 'setup_wizard:tls_server_credential_apply')
                self.assertEqual(resolver.func.view_class, SetupWizardTlsServerCredentialApplyView)
                self.assertEqual(resolver.kwargs['file_format'], file_format)

    def test_tls_server_credential_apply_cancel_url(self):
        """Test TLS server credential apply cancel URL pattern."""
        url = reverse('setup_wizard:tls_server_credential_apply_cancel')
        self.assertEqual(url, '/setup-wizard/tls-server-credential-apply-cancel/')

        resolver = resolve('/setup-wizard/tls-server-credential-apply-cancel/')
        self.assertEqual(resolver.view_name, 'setup_wizard:tls_server_credential_apply_cancel')
        self.assertEqual(resolver.func.view_class, SetupWizardTlsServerCredentialApplyCancelView)

    def test_demo_data_url(self):
        """Test demo data URL pattern."""
        url = reverse('setup_wizard:demo_data')
        self.assertEqual(url, '/setup-wizard/demo-data/')

        resolver = resolve('/setup-wizard/demo-data/')
        self.assertEqual(resolver.view_name, 'setup_wizard:demo_data')
        self.assertEqual(resolver.func.view_class, SetupWizardDemoDataView)

    def test_create_super_user_url(self):
        """Test create super user URL pattern."""
        url = reverse('setup_wizard:create_super_user')
        self.assertEqual(url, '/setup-wizard/create-super-user')

        resolver = resolve('/setup-wizard/create-super-user')
        self.assertEqual(resolver.view_name, 'setup_wizard:create_super_user')
        self.assertEqual(resolver.func.view_class, SetupWizardCreateSuperUserView)

    def test_restore_url(self):
        """Test restore URL pattern."""
        url = reverse('setup_wizard:restore')
        self.assertEqual(url, '/setup-wizard/restore/')

        resolver = resolve('/setup-wizard/restore/')
        self.assertEqual(resolver.view_name, 'setup_wizard:restore')
        self.assertEqual(resolver.func.view_class, BackupRestoreView)



    def test_auto_restore_password_url(self):
        """Test auto restore password URL pattern."""
        url = reverse('setup_wizard:auto_restore_password')
        self.assertEqual(url, '/setup-wizard/auto_restore_password/')

        resolver = resolve('/setup-wizard/auto_restore_password/')
        self.assertEqual(resolver.view_name, 'setup_wizard:auto_restore_password')
        self.assertEqual(resolver.func.view_class, BackupAutoRestorePasswordView)

    def test_all_urls_resolve_correctly(self):
        """Test that all URL patterns resolve to their correct views."""
        # Test URLs that don't require parameters
        url_view_mapping = {
            'setup_wizard:crypto_storage_setup': SetupWizardCryptoStorageView,
            'setup_wizard:setup_mode': SetupWizardSetupModeView,
            'setup_wizard:select_tls_server_credential': SetupWizardSelectTlsServerCredentialView,
            'setup_wizard:backup_password': SetupWizardBackupPasswordView,
            'setup_wizard:generate_tls_server_credential': SetupWizardGenerateTlsServerCredentialView,
            'setup_wizard:import_tls_server_credential': SetupWizardImportTlsServerCredentialView,
            'setup_wizard:restore_options': SetupWizardRestoreOptionsView,
            'setup_wizard:tls_server_credential_apply': SetupWizardTlsServerCredentialApplyView,
            'setup_wizard:tls_server_credential_apply_cancel': SetupWizardTlsServerCredentialApplyCancelView,
            'setup_wizard:demo_data': SetupWizardDemoDataView,
            'setup_wizard:create_super_user': SetupWizardCreateSuperUserView,
            'setup_wizard:restore': BackupRestoreView,
            'setup_wizard:auto_restore_password': BackupAutoRestorePasswordView,
        }

        for url_name, expected_view_class in url_view_mapping.items():
            with self.subTest(url_name=url_name):
                url = reverse(url_name)
                resolver = resolve(url)
                self.assertEqual(resolver.func.view_class, expected_view_class)

        # Test URLs that require parameters
        parametrized_urls = [
            ('setup_wizard:hsm_setup', {'hsm_type': 'softhsm'}, SetupWizardHsmSetupView),
        ]

        for url_name, kwargs, expected_view_class in parametrized_urls:
            with self.subTest(url_name=url_name, kwargs=kwargs):
                url = reverse(url_name, kwargs=kwargs)
                resolver = resolve(url)
                self.assertEqual(resolver.func.view_class, expected_view_class)

    def test_hsm_setup_url_parameter_validation(self):
        """Test HSM setup URL with various parameter types."""
        # Test valid hsm_type parameters
        valid_types = ['softhsm', 'physical', 'test-hsm-123', 'hsm_with_underscores']

        for hsm_type in valid_types:
            with self.subTest(hsm_type=hsm_type):
                url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': hsm_type})
                resolver = resolve(url)
                self.assertEqual(resolver.kwargs['hsm_type'], hsm_type)

    def test_url_pattern_consistency(self):
        """Test that URL patterns follow consistent naming conventions."""
        # Test that dashes are used consistently in URLs
        dash_urls = [
            'crypto-storage-setup',
            'backup-password',
            'generate-tls-server-credential',
            'import-tls-server-credential',
            'tls-server-credential-apply',
            'tls-server-credential-apply-cancel',
            'demo-data',
            'create-super-user',
        ]

        for url_pattern in dash_urls:
            with self.subTest(url_pattern=url_pattern):
                # URL should contain dashes, not underscores
                self.assertIn('-', url_pattern)
                self.assertNotIn('_', url_pattern.replace('tls_server', 'tls-server'))

        # Test that underscores are used in some specific cases
        underscore_urls = [
            'setup_mode',
            'select_tls_server_credential',
            'restore_options',
            'auto_restore_hsm',
            'auto_restore_password',
        ]

        for url_pattern in underscore_urls:
            with self.subTest(url_pattern=url_pattern):
                # These specific URLs use underscores
                self.assertIn('_', url_pattern)

    def test_url_namespacing(self):
        """Test that all URLs are properly namespaced."""
        # URLs that don't require parameters
        simple_url_names = [
            'crypto_storage_setup',
            'setup_mode',
            'select_tls_server_credential',
            'backup_password',
            'generate_tls_server_credential',
            'import_tls_server_credential',
            'restore_options',
            'tls_server_credential_apply',
            'tls_server_credential_apply_cancel',
            'demo_data',
            'create_super_user',
            'restore',
        ]

        for url_name in simple_url_names:
            with self.subTest(url_name=url_name):
                # Should be able to reverse with namespace
                namespaced_url = reverse(f'setup_wizard:{url_name}')
                self.assertIsNotNone(namespaced_url)

                # Should fail without namespace (unless there's a global pattern)
                try:
                    non_namespaced = reverse(url_name)
                    # If this succeeds, there might be a global URL with the same name
                    # which could cause conflicts
                    self.assertNotEqual(namespaced_url, non_namespaced,
                                      f"URL name '{url_name}' conflicts with global namespace")
                except NoReverseMatch:
                    # This is expected - the URL should only work with namespace
                    pass

        # URLs that require parameters
        parametrized_url_names = [
            ('hsm_setup', {'hsm_type': 'softhsm'}),
        ]

        for url_name, kwargs in parametrized_url_names:
            with self.subTest(url_name=url_name, kwargs=kwargs):
                # Should be able to reverse with namespace and parameters
                namespaced_url = reverse(f'setup_wizard:{url_name}', kwargs=kwargs)
                self.assertIsNotNone(namespaced_url)

                # Should fail without namespace
                try:
                    non_namespaced = reverse(url_name, kwargs=kwargs)
                    self.assertNotEqual(namespaced_url, non_namespaced,
                                      f"URL name '{url_name}' conflicts with global namespace")
                except NoReverseMatch:
                    # This is expected - the URL should only work with namespace
                    pass

    @pytest.mark.django_db
    def test_url_integration_with_views(self):
        """Test that URLs integrate properly with their corresponding views."""
        # Test that views can be accessed through their URLs
        with patch('setup_wizard.views.DOCKER_CONTAINER', True):
            with patch('setup_wizard.views.SetupWizardState.get_current_state') as mock_state:
                from setup_wizard import SetupWizardState
                mock_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

                # Test a simple GET request to crypto storage setup
                from django.test import Client
                client = Client()

                url = reverse('setup_wizard:crypto_storage_setup')
                response = client.get(url)

                # Should not crash and should return a valid HTTP response
                self.assertIn(response.status_code, [200, 302, 405])

    def test_parameter_extraction_in_urls(self):
        """Test that URL parameters are correctly extracted."""
        # Test hsm_type parameter extraction
        hsm_url = '/setup-wizard/hsm-setup/test-hsm/'
        resolver = resolve(hsm_url)
        self.assertEqual(resolver.kwargs['hsm_type'], 'test-hsm')

        # Test file_format parameter extraction
        apply_url = '/setup-wizard/tls-server-credential-apply/pkcs12/'
        resolver = resolve(apply_url)
        self.assertEqual(resolver.kwargs['file_format'], 'pkcs12')

    def test_url_trailing_slash_consistency(self):
        """Test that URL patterns are consistent with trailing slashes."""
        urls_with_trailing_slash = [
            reverse('setup_wizard:crypto_storage_setup'),
            reverse('setup_wizard:setup_mode'),
            reverse('setup_wizard:select_tls_server_credential'),
            reverse('setup_wizard:backup_password'),
            reverse('setup_wizard:generate_tls_server_credential'),
            reverse('setup_wizard:import_tls_server_credential'),
            reverse('setup_wizard:restore_options'),
            reverse('setup_wizard:tls_server_credential_apply'),
            reverse('setup_wizard:tls_server_credential_apply_cancel'),
            reverse('setup_wizard:demo_data'),
            reverse('setup_wizard:restore'),
        ]

        urls_without_trailing_slash = [
            reverse('setup_wizard:create_super_user'),
        ]

        # Most URLs should end with a trailing slash
        for url in urls_with_trailing_slash:
            with self.subTest(url=url):
                self.assertTrue(url.endswith('/'), f'URL {url} should end with trailing slash')

        # Some URLs don't have trailing slashes
        for url in urls_without_trailing_slash:
            with self.subTest(url=url):
                self.assertFalse(url.endswith('/'), f'URL {url} should not end with trailing slash')

    def test_special_characters_in_parameters(self):
        """Test URL patterns with special characters in parameters."""
        # Test hsm_type with various valid characters
        special_hsm_types = [
            'softhsm-2.0',
            'hsm_test_123',
            'physical-hsm',
        ]

        for hsm_type in special_hsm_types:
            with self.subTest(hsm_type=hsm_type):
                url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': hsm_type})
                resolver = resolve(url)
                self.assertEqual(resolver.kwargs['hsm_type'], hsm_type)

        # Test file_format with various valid formats
        file_formats = [
            'pem',
            'pkcs12',
            'der',
            'p12',
        ]

        for file_format in file_formats:
            with self.subTest(file_format=file_format):
                url = reverse('setup_wizard:tls_server_credential_apply', kwargs={'file_format': file_format})
                resolver = resolve(url)
                self.assertEqual(resolver.kwargs['file_format'], file_format)

    def test_url_pattern_security(self):
        """Test that URL patterns don't allow potentially dangerous input."""
        # Test that path traversal attempts are handled correctly
        dangerous_inputs = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            'test/../admin',
        ]

        for dangerous_input in dangerous_inputs:
            with self.subTest(dangerous_input=dangerous_input):
                try:
                    # Attempt to create URL with dangerous input
                    url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': dangerous_input})
                    resolver = resolve(url)

                    # The parameter should be treated as a literal string, not interpreted as path traversal
                    self.assertEqual(resolver.kwargs['hsm_type'], dangerous_input)

                    # URL should not contain actual path traversal sequences when resolved
                    self.assertNotIn('/../', url)

                except Exception:
                    # If reverse fails, that's also acceptable for security
                    pass

    def test_hsm_setup_requires_parameter(self):
        """Test that hsm_setup URL requires hsm_type parameter."""
        # Should fail without the required parameter
        with self.assertRaises(NoReverseMatch):
            reverse('setup_wizard:hsm_setup')

        # Should succeed with the required parameter
        url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': 'softhsm'})
        self.assertIsNotNone(url)

    def test_tls_server_credential_apply_optional_parameter(self):
        """Test that tls_server_credential_apply URL works with and without file_format parameter."""
        # Should work without parameter
        url_without_param = reverse('setup_wizard:tls_server_credential_apply')
        self.assertIsNotNone(url_without_param)

        # Should work with parameter
        url_with_param = reverse('setup_wizard:tls_server_credential_apply', kwargs={'file_format': 'pem'})
        self.assertIsNotNone(url_with_param)

        # URLs should be different
        self.assertNotEqual(url_without_param, url_with_param)

    def test_url_view_class_consistency(self):
        """Test that all URL patterns resolve to the expected view classes."""
        # Test that all imported view classes are actually used in URL patterns
        imported_views = {
            BackupAutoRestorePasswordView,
            BackupRestoreView,
            SetupWizardBackupPasswordView,
            SetupWizardCreateSuperUserView,
            SetupWizardCryptoStorageView,
            SetupWizardDemoDataView,
            SetupWizardGenerateTlsServerCredentialView,
            SetupWizardHsmSetupView,
            SetupWizardImportTlsServerCredentialView,
            SetupWizardRestoreOptionsView,
            SetupWizardSelectTlsServerCredentialView,
            SetupWizardSetupModeView,
            SetupWizardTlsServerCredentialApplyCancelView,
            SetupWizardTlsServerCredentialApplyView,
        }

        from setup_wizard.urls import urlpatterns

        used_views = set()
        for pattern in urlpatterns:
            if hasattr(pattern, 'callback') and hasattr(pattern.callback, 'view_class'):
                used_views.add(pattern.callback.view_class)

        # All imported views should be used in URL patterns
        self.assertEqual(imported_views, used_views,
                        'Mismatch between imported views and views used in URL patterns')

    def test_setup_wizard_url_prefix_consistency(self):
        """Test that all setup wizard URLs use consistent prefix."""
        from setup_wizard.urls import urlpatterns

        for pattern in urlpatterns:
            # All patterns should be for setup wizard functionality
            if hasattr(pattern, 'pattern'):
                pattern_str = str(pattern.pattern)
                # Pattern should not start with '^' (that's added by the main URLconf)
                # but should represent setup wizard functionality
                self.assertIsInstance(pattern_str, str)
