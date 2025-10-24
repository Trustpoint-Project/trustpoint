"""Tests for settings app URL configuration."""

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import resolve, reverse

from management.views import IndexView, backup, logging, tls, key_storage, settings


class SettingsUrlsTestCase(TestCase):
    def setUp(self):
        """Set up test data and authenticate the test client."""
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.force_login(self.user)

    def test_index_url(self):
        """Test the management index URL."""
        url = reverse('management:index')
        self.assertEqual(url, '/management/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'management:index')
        self.assertEqual(resolver.func.view_class, IndexView)

    def test_logging_files_url(self):
        """Test the logging files table URL."""
        url = reverse('management:logging-files')
        self.assertEqual(url, '/management/logging/files/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'management:logging-files')
        self.assertEqual(resolver.func.view_class, logging.LoggingFilesTableView)

    def test_logging_files_details_url(self):
        """Test the logging files details URL."""
        # Test with main log file
        url = reverse('management:logging-files-details', kwargs={'filename': 'trustpoint.log'})
        self.assertEqual(url, '/management/logging/files/details/trustpoint.log')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'management:logging-files-details')
        self.assertEqual(resolver.func.view_class, logging.LoggingFilesDetailsView)
        self.assertEqual(resolver.kwargs['filename'], 'trustpoint.log')

        # Test with numbered log file
        url = reverse('management:logging-files-details', kwargs={'filename': 'trustpoint.log.1'})
        self.assertEqual(url, '/management/logging/files/details/trustpoint.log.1')

        resolver = resolve(url)
        self.assertEqual(resolver.kwargs['filename'], 'trustpoint.log.1')

    def test_logging_files_download_url(self):
        """Test the logging files download URL."""
        # Test with main log file
        url = reverse('management:logging-files-download', kwargs={'filename': 'trustpoint.log'})
        self.assertEqual(url, '/management/logging/files/download/trustpoint.log')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'management:logging-files-download')
        self.assertEqual(resolver.func.view_class, logging.LoggingFilesDownloadView)
        self.assertEqual(resolver.kwargs['filename'], 'trustpoint.log')

        # Test with numbered log file
        url = reverse('management:logging-files-download', kwargs={'filename': 'trustpoint.log.12345'})
        self.assertEqual(url, '/management/logging/files/download/trustpoint.log.12345')

        resolver = resolve(url)
        self.assertEqual(resolver.kwargs['filename'], 'trustpoint.log.12345')

    def test_logging_files_download_multiple_url(self):
        """Test the logging files download multiple URL."""
        # Test with tar.gz format
        url = reverse('management:logging-files-download-multiple',
                    kwargs={'archive_format': 'tar.gz', 'filenames': '/trustpoint.log/trustpoint.log.1'})
        self.assertEqual(url, '/management/logging/files/download/tar.gz/trustpoint.log/trustpoint.log.1')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'management:logging-files-download-multiple')
        self.assertEqual(resolver.func.view_class, logging.LoggingFilesDownloadMultipleView)
        self.assertEqual(resolver.kwargs['archive_format'], 'tar.gz')
        self.assertEqual(resolver.kwargs['filenames'], '/trustpoint.log/trustpoint.log.1')

        # Test with zip format
        url = reverse('settings:logging-files-download-multiple',
                    kwargs={'archive_format': 'zip', 'filenames': '/trustpoint.log'})
        self.assertEqual(url, '/settings/logging/files/download/zip/trustpoint.log')

        resolver = resolve(url)
        self.assertEqual(resolver.kwargs['archive_format'], 'zip')

    def test_security_url(self):
        """Test the security settings URL."""
        url = reverse('settings:security')
        self.assertEqual(url, '/settings/security/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'settings:security')
        self.assertEqual(resolver.func.view_class, security.SecurityView)

    def test_tls_url(self):
        """Test the TLS settings URL."""
        url = reverse('settings:tls')
        self.assertEqual(url, '/settings/tls/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'settings:tls')
        self.assertEqual(resolver.func.view_class, tls.TlsView)

    def test_backups_url(self):
        """Test the backups management URL."""
        url = reverse('settings:backups')
        self.assertEqual(url, '/settings/backups/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'settings:backups')
        self.assertEqual(resolver.func.view_class, backup.BackupManageView)

    def test_backup_download_url(self):
        """Test the backup file download URL."""
        url = reverse('settings:backup-download', kwargs={'filename': 'backup_20231201.tar.gz'})
        self.assertEqual(url, '/settings/backups/download/backup_20231201.tar.gz/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'settings:backup-download')
        self.assertEqual(resolver.func.view_class, backup.BackupFileDownloadView)
        self.assertEqual(resolver.kwargs['filename'], 'backup_20231201.tar.gz')

    def test_backup_download_multiple_url(self):
        """Test the backup files download multiple URL."""
        # Test with tar.gz format
        url = reverse('settings:backup-download-multiple', kwargs={'archive_format': 'tar.gz'})
        self.assertEqual(url, '/settings/backups/download-multiple/tar.gz/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'settings:backup-download-multiple')
        self.assertEqual(resolver.func.view_class, backup.BackupFilesDownloadMultipleView)
        self.assertEqual(resolver.kwargs['archive_format'], 'tar.gz')

        # Test with zip format
        url = reverse('settings:backup-download-multiple', kwargs={'archive_format': 'zip'})
        self.assertEqual(url, '/settings/backups/download-multiple/zip/')

        resolver = resolve(url)
        self.assertEqual(resolver.kwargs['archive_format'], 'zip')

    def test_backup_delete_multiple_url(self):
        """Test the backup files delete multiple URL."""
        url = reverse('settings:backup-delete-multiple')
        self.assertEqual(url, '/settings/backups/delete-multiple/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'settings:backup-delete-multiple')
        self.assertEqual(resolver.func.view_class, backup.BackupFilesDeleteMultipleView)

    def test_pkcs11_url(self):
        """Test the PKCS#11 configuration URL."""
        url = reverse('settings:pkcs11')
        self.assertEqual(url, '/settings/pkcs11/')

        resolver = resolve(url)
        self.assertEqual(resolver.view_name, 'settings:pkcs11')
        self.assertEqual(resolver.func.view_class, key_storage.PKCS11ConfigView)

    def test_logging_regex_patterns(self):
        """Test that logging regex patterns work correctly."""
        # Test various valid log filenames
        valid_filenames = [
            'trustpoint.log',
            'trustpoint.log.1',
            'trustpoint.log.12345',
        ]

        for filename in valid_filenames:
            # Test details URL
            url = f'/settings/logging/files/details/{filename}'
            resolver = resolve(url)
            self.assertEqual(resolver.view_name, 'settings:logging-files-details')
            self.assertEqual(resolver.kwargs['filename'], filename)

            # Test download URL
            url = f'/settings/logging/files/download/{filename}'
            resolver = resolve(url)
            self.assertEqual(resolver.view_name, 'settings:logging-files-download')
            self.assertEqual(resolver.kwargs['filename'], filename)

    def test_app_name(self):
        """Test that the app name is correctly set."""
        # This is tested implicitly by all the reverse() calls above
        # but we can also test it explicitly
        from management.urls import app_name
        self.assertEqual(app_name, 'settings')
