"""Tests for the redesigned setup_wizard URL configuration."""

from django.test import TestCase
from django.urls import resolve, reverse

from setup_wizard import urls
from setup_wizard.views import (
    FreshInstallCancelView,
    FreshInstallCryptoStorageView,
    FreshInstallDemoDataView,
    FreshInstallSummaryTruststoreDownloadView,
    FreshInstallSummaryView,
    FreshInstallTlsConfigView,
    SetupWizardCreateSuperUserView,
    SetupWizardIndexView,
    SetupWizardRestoreBackupView,
)


class SetupWizardUrlsTestCase(TestCase):
    """Test cases for the current setup_wizard URL patterns."""

    def test_app_name_configuration(self) -> None:
        self.assertEqual(urls.app_name, 'setup_wizard')

    def test_index_url(self) -> None:
        url = reverse('setup_wizard:index')
        self.assertEqual(url, '/setup-wizard/')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, SetupWizardIndexView)

    def test_create_super_user_url(self) -> None:
        url = reverse('setup_wizard:create_super_user')
        self.assertEqual(url, '/setup-wizard/create-super-user/')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, SetupWizardCreateSuperUserView)

    def test_restore_backup_url(self) -> None:
        url = reverse('setup_wizard:restore_backup')
        self.assertEqual(url, '/setup-wizard/restore-backup/')
        resolver = resolve(url)
        self.assertEqual(resolver.func.view_class, SetupWizardRestoreBackupView)

    def test_fresh_install_urls(self) -> None:
        cases = [
            ('setup_wizard:fresh_install_crypto_storage', '/setup-wizard/fresh-install/crypto-storage/', FreshInstallCryptoStorageView),
            ('setup_wizard:fresh_install_demo_data', '/setup-wizard/fresh-install/demo-data/', FreshInstallDemoDataView),
            ('setup_wizard:fresh_install_tls_config', '/setup-wizard/fresh-install/tls-config/', FreshInstallTlsConfigView),
            ('setup_wizard:fresh_install_summary', '/setup-wizard/fresh-install/summary/', FreshInstallSummaryView),
            ('setup_wizard:fresh_install_cancel', '/setup-wizard/fresh-install/cancel/', FreshInstallCancelView),
        ]

        for url_name, expected_url, expected_view_class in cases:
            with self.subTest(url_name=url_name):
                url = reverse(url_name)
                self.assertEqual(url, expected_url)
                resolver = resolve(url)
                self.assertEqual(resolver.func.view_class, expected_view_class)

    def test_summary_truststore_download_url(self) -> None:
        for file_format in ('pem', 'der'):
            with self.subTest(file_format=file_format):
                url = reverse(
                    'setup_wizard:fresh_install_summary_truststore_download',
                    kwargs={'file_format': file_format},
                )
                self.assertEqual(
                    url,
                    f'/setup-wizard/fresh-install/summary/truststore/{file_format}/',
                )
                resolver = resolve(url)
                self.assertEqual(resolver.func.view_class, FreshInstallSummaryTruststoreDownloadView)
                self.assertEqual(resolver.kwargs['file_format'], file_format)
