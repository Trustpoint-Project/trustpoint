"""Test suite for the Backup views."""
from unittest.mock import patch, MagicMock, Mock
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.messages import get_messages
from django.contrib.auth.models import User
from django.core.management.base import CommandError
from management.models import BackupOptions
from management.views.backup import get_backup_file_data, create_db_backup
from util.sftp import SftpError
from pathlib import Path
import tempfile
import datetime


class GetBackupFileDataTest(TestCase):
    """Test suite for get_backup_file_data function."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name)

    def test_get_backup_file_data_existing_file(self) -> None:
        """Test getting metadata for an existing backup file."""
        # Create a test file
        test_file = self.backup_dir / 'backup_test.dump.gz'
        test_file.write_text('test content')

        with patch('management.views.backup.settings') as mock_settings:
            mock_settings.BACKUP_FILE_PATH = self.backup_dir
            data = get_backup_file_data('backup_test.dump.gz')

        self.assertEqual(data['filename'], 'backup_test.dump.gz')
        self.assertIn('created_at', data)
        self.assertIn('modified_at', data)
        self.assertIn('size_kb', data)

    def test_get_backup_file_data_nonexistent_file(self) -> None:
        """Test getting metadata for a nonexistent file."""
        with patch('management.views.backup.settings') as mock_settings:
            mock_settings.BACKUP_FILE_PATH = self.backup_dir
            data = get_backup_file_data('nonexistent.dump.gz')

        self.assertEqual(data, {})

    def test_get_backup_file_data_directory(self) -> None:
        """Test getting metadata for a directory (should return empty dict)."""
        subdir = self.backup_dir / 'subdir'
        subdir.mkdir()

        with patch('management.views.backup.settings') as mock_settings:
            mock_settings.BACKUP_FILE_PATH = self.backup_dir
            data = get_backup_file_data('subdir')

        self.assertEqual(data, {})

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()


class CreateDbBackupTest(TestCase):
    """Test suite for create_db_backup function."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name)

    @patch('management.views.backup.call_command')
    @patch('management.views.backup.datetime')
    def test_create_db_backup_success(self, mock_datetime: MagicMock, mock_call_command: MagicMock) -> None:
        """Test successful database backup creation."""
        mock_now = Mock()
        mock_now.strftime.return_value = '2025-12-08_12-00-00'
        mock_datetime.datetime.now.return_value = mock_now
        mock_datetime.UTC = datetime.UTC

        filename = create_db_backup(self.backup_dir)

        self.assertEqual(filename, 'backup_2025-12-08_12-00-00.dump.gz')
        mock_call_command.assert_called_once_with('trustpointbackup', filename=filename)
        self.assertTrue(self.backup_dir.exists())

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()


class BackupManageViewTest(TestCase):
    """Test suite for the BackupManageView."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.client = Client()
        self.url = reverse('management:backups')
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name)

        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    @patch('management.views.backup.settings')
    def test_get_queryset_no_backup_dir(self, mock_settings: MagicMock) -> None:
        """Test get_queryset when backup directory doesn't exist."""
        mock_settings.BACKUP_FILE_PATH = Path('/nonexistent/path')
        
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['backup_files']), 0)

    @patch('management.views.backup.settings')
    def test_get_queryset_with_backup_files(self, mock_settings: MagicMock) -> None:
        """Test get_queryset with existing backup files."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        # Create test backup files
        (self.backup_dir / 'backup_2025-12-08_10-00-00.dump.gz').write_text('test1')
        (self.backup_dir / 'backup_2025-12-08_11-00-00.dump.gz').write_text('test2')
        (self.backup_dir / 'other_file.txt').write_text('ignored')
        
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['backup_files']), 2)

    def test_get_context_data_no_saved_settings(self) -> None:
        """Test context data when no settings are saved."""
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('backup_options_form', response.context)
        self.assertFalse(response.context['has_saved_settings'])

    def test_get_context_data_with_saved_settings(self) -> None:
        """Test context data when settings are saved."""
        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='testuser',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='password'
        )
        
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['has_saved_settings'])

    def test_post_unknown_action(self) -> None:
        """Test POST with unknown action."""
        response = self.client.post(self.url, {'unknown_action': ''})
        
        self.assertEqual(response.status_code, 302)

    @patch('management.views.backup.create_db_backup')
    def test_create_local_backup_success(self, mock_create_db_backup: MagicMock) -> None:
        """Test creating a local backup successfully."""
        mock_create_db_backup.return_value = 'backup_2025-10-30_12-00-00.dump.gz'

        response = self.client.post(self.url, {'create_local_backup': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Database backup created locally' in str(message) for message in messages))

    @patch('management.views.backup.create_db_backup')
    def test_create_local_backup_oserror(self, mock_create_db_backup: MagicMock) -> None:
        """Test creating a local backup with OSError."""
        mock_create_db_backup.side_effect = OSError('Disk full')

        response = self.client.post(self.url, {'create_local_backup': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Error creating database backup' in str(message) for message in messages))

    @patch('management.views.backup.create_db_backup')
    def test_create_local_backup_command_error(self, mock_create_db_backup: MagicMock) -> None:
        """Test creating a local backup with CommandError."""
        mock_create_db_backup.side_effect = CommandError('Command failed')

        response = self.client.post(self.url, {'create_local_backup': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Error creating database backup' in str(message) for message in messages))

    @patch('management.views.backup.settings')
    @patch('management.views.backup.create_db_backup')
    @patch('management.views.backup.SftpClient')
    def test_create_sftp_backup_success(self, mock_sftp_client: MagicMock, mock_create_db_backup: MagicMock, mock_settings: MagicMock) -> None:
        """Test creating a backup and uploading via SFTP."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        mock_create_db_backup.return_value = 'backup_2025-10-30_12-00-00.dump.gz'
        mock_client = MagicMock()
        mock_client.remote_directory = '/remote/backups/'
        mock_sftp_client.return_value = mock_client

        # Create the backup file
        (self.backup_dir / 'backup_2025-10-30_12-00-00.dump.gz').write_text('test')

        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='user',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='password',
            remote_directory='/remote/backups/'
        )

        response = self.client.post(self.url, {'create_sftp_backup': ''})

        self.assertEqual(response.status_code, 302)
        mock_client.upload_file.assert_called_once()
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Uploaded' in str(message) for message in messages))

    @patch('management.views.backup.create_db_backup')
    def test_create_sftp_backup_db_error(self, mock_create_db_backup: MagicMock) -> None:
        """Test creating SFTP backup when database backup fails."""
        mock_create_db_backup.side_effect = OSError('Disk full')

        response = self.client.post(self.url, {'create_sftp_backup': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Error creating database backup' in str(message) for message in messages))

    @patch('management.views.backup.create_db_backup')
    def test_create_sftp_backup_no_settings(self, mock_create_db_backup: MagicMock) -> None:
        """Test creating SFTP backup without saved settings."""
        mock_create_db_backup.return_value = 'backup_2025-10-30_12-00-00.dump.gz'

        response = self.client.post(self.url, {'create_sftp_backup': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('no SFTP settings found' in str(message) for message in messages))

    @patch('management.views.backup.settings')
    @patch('management.views.backup.create_db_backup')
    @patch('management.views.backup.SftpClient')
    def test_create_sftp_backup_client_creation_error(self, mock_sftp_client: MagicMock, mock_create_db_backup: MagicMock, mock_settings: MagicMock) -> None:
        """Test SFTP backup when client creation fails."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        mock_create_db_backup.return_value = 'backup_2025-10-30_12-00-00.dump.gz'
        mock_sftp_client.side_effect = SftpError('Connection failed')

        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='user',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='password'
        )

        response = self.client.post(self.url, {'create_sftp_backup': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Failed to create SFTP client' in str(message) for message in messages))

    @patch('management.views.backup.settings')
    @patch('management.views.backup.create_db_backup')
    @patch('management.views.backup.SftpClient')
    def test_create_sftp_backup_upload_error(self, mock_sftp_client: MagicMock, mock_create_db_backup: MagicMock, mock_settings: MagicMock) -> None:
        """Test SFTP backup when upload fails."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        mock_create_db_backup.return_value = 'backup_2025-10-30_12-00-00.dump.gz'
        mock_client = MagicMock()
        mock_client.remote_directory = None
        mock_client.upload_file.side_effect = SftpError('Upload failed')
        mock_sftp_client.return_value = mock_client

        # Create the backup file
        (self.backup_dir / 'backup_2025-10-30_12-00-00.dump.gz').write_text('test')

        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='user',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='password'
        )

        response = self.client.post(self.url, {'create_sftp_backup': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('SFTP upload failed' in str(message) for message in messages))

    @patch('management.views.backup.settings')
    @patch('management.views.backup.create_db_backup')
    @patch('management.views.backup.SftpClient')
    def test_create_sftp_backup_remote_directory_variations(self, mock_sftp_client: MagicMock, mock_create_db_backup: MagicMock, mock_settings: MagicMock) -> None:
        """Test SFTP backup with different remote directory formats."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        mock_create_db_backup.return_value = 'backup_test.dump.gz'
        
        # Create the backup file
        (self.backup_dir / 'backup_test.dump.gz').write_text('test')

        # Test with trailing slash
        mock_client = MagicMock()
        mock_client.remote_directory = '/path/'
        mock_sftp_client.return_value = mock_client

        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='user',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='password',
            remote_directory='/path/'
        )

        response = self.client.post(self.url, {'create_sftp_backup': ''})
        
        call_args = mock_client.upload_file.call_args
        self.assertEqual(call_args[0][1], '/path/backup_test.dump.gz')

    @patch('management.views.backup.settings')
    @patch('management.views.backup.create_db_backup')
    @patch('management.views.backup.SftpClient')
    def test_create_sftp_backup_remote_directory_no_trailing_slash(self, mock_sftp_client: MagicMock, mock_create_db_backup: MagicMock, mock_settings: MagicMock) -> None:
        """Test SFTP backup with remote directory without trailing slash."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        mock_create_db_backup.return_value = 'backup_test2.dump.gz'
        
        # Create the backup file
        (self.backup_dir / 'backup_test2.dump.gz').write_text('test')

        # Test without trailing slash
        mock_client = MagicMock()
        mock_client.remote_directory = '/path'
        mock_sftp_client.return_value = mock_client

        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='user',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='password',
            remote_directory='/path'
        )

        response = self.client.post(self.url, {'create_sftp_backup': ''})
        
        call_args = mock_client.upload_file.call_args
        self.assertEqual(call_args[0][1], '/path/backup_test2.dump.gz')

    @patch('management.views.backup.SftpClient')
    def test_test_sftp_connection_success(self, mock_sftp_client: MagicMock) -> None:
        """Test testing SFTP connection successfully."""
        mock_client = MagicMock()
        mock_sftp_client.return_value = mock_client

        response = self.client.post(self.url, {
            'test_sftp_connection': '',
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'password',
        })

        self.assertEqual(response.status_code, 200)
        mock_client.test_connection.assert_called_once()
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('SFTP connection successful' in str(message) for message in messages))

    @patch('management.views.backup.SftpClient')
    def test_test_sftp_connection_failure(self, mock_sftp_client: MagicMock) -> None:
        """Test testing SFTP connection with failure."""
        mock_client = MagicMock()
        mock_client.test_connection.side_effect = SftpError('Connection refused')
        mock_sftp_client.return_value = mock_client

        response = self.client.post(self.url, {
            'test_sftp_connection': '',
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'password',
        })

        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('SFTP connection failed' in str(message) for message in messages))

    def test_test_sftp_connection_invalid_form(self) -> None:
        """Test testing SFTP connection with invalid form data."""
        response = self.client.post(self.url, {
            'test_sftp_connection': '',
            'host': '',  # Missing required field
            'port': 22,
            'user': 'user',
        })

        self.assertEqual(response.status_code, 200)

    def test_save_settings_success(self) -> None:
        """Test saving backup settings successfully."""
        response = self.client.post(self.url, {
            'save_backup_settings': '',
            'enable_sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'testuser',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'password',
            'remote_directory': '/remote/backups',
        })

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Backup settings saved successfully' in str(message) for message in messages))
        
        # Verify settings were saved
        opts = BackupOptions.objects.get(pk=1)
        self.assertEqual(opts.host, 'localhost')
        self.assertEqual(opts.user, 'testuser')

    def test_save_settings_invalid_form(self) -> None:
        """Test saving backup settings with invalid form data."""
        response = self.client.post(self.url, {
            'save_backup_settings': '',
            'enable_sftp_storage': True,
            'host': '',  # Missing required field
            'port': 'invalid',  # Invalid port
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('backup_options_form', response.context)

    def test_reset_settings(self) -> None:
        """Test resetting backup settings."""
        # Create settings first
        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='testuser',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='password'
        )

        response = self.client.post(self.url, {'reset_backup_settings': ''})

        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Backup settings have been reset' in str(message) for message in messages))
        
        # Verify settings were deleted
        self.assertFalse(BackupOptions.objects.filter(pk=1).exists())

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()


class BackupFileDownloadViewTest(TestCase):
    """Test suite for BackupFileDownloadView."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.client = Client()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name)
        
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    @patch('management.views.backup.settings')
    def test_download_existing_file(self, mock_settings: MagicMock) -> None:
        """Test downloading an existing backup file."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        # Create test backup file
        test_file = self.backup_dir / 'backup_test.dump.gz'
        test_file.write_bytes(b'test content')
        
        url = reverse('management:backup-download', kwargs={'filename': 'backup_test.dump.gz'})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertEqual(response.content, b'test content')

    @patch('management.views.backup.settings')
    def test_download_nonexistent_file(self, mock_settings: MagicMock) -> None:
        """Test downloading a nonexistent backup file."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        url = reverse('management:backup-download', kwargs={'filename': 'nonexistent.dump.gz'})
        response = self.client.get(url)
        
        # Django test client returns 404 status code instead of raising Http404
        self.assertEqual(response.status_code, 404)

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()


class BackupFilesDownloadMultipleViewTest(TestCase):
    """Test suite for BackupFilesDownloadMultipleView."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.client = Client()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name)
        
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    @patch('management.views.backup.settings')
    def test_download_multiple_as_zip(self, mock_settings: MagicMock) -> None:
        """Test downloading multiple backups as ZIP."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        # Create test backup files
        (self.backup_dir / 'backup_1.dump.gz').write_bytes(b'content1')
        (self.backup_dir / 'backup_2.dump.gz').write_bytes(b'content2')
        
        url = reverse('management:backup-download-multiple', kwargs={'archive_format': 'zip'})
        response = self.client.post(url, {'selected': ['backup_1.dump.gz', 'backup_2.dump.gz']})
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertIn('backups.zip', response['Content-Disposition'])

    @patch('management.views.backup.settings')
    def test_download_multiple_as_tar_gz(self, mock_settings: MagicMock) -> None:
        """Test downloading multiple backups as tar.gz."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        # Create test backup files
        (self.backup_dir / 'backup_1.dump.gz').write_bytes(b'content1')
        (self.backup_dir / 'backup_2.dump.gz').write_bytes(b'content2')
        
        url = reverse('management:backup-download-multiple', kwargs={'archive_format': 'tar.gz'})
        response = self.client.post(url, {'selected': ['backup_1.dump.gz', 'backup_2.dump.gz']})
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertIn('backups.tar.gz', response['Content-Disposition'])

    def test_download_multiple_no_selection(self) -> None:
        """Test downloading with no files selected."""
        url = reverse('management:backup-download-multiple', kwargs={'archive_format': 'zip'})
        response = self.client.post(url, {'selected': []})
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('No files selected' in str(message) for message in messages))

    @patch('management.views.backup.settings')
    def test_download_multiple_no_valid_files(self, mock_settings: MagicMock) -> None:
        """Test downloading with no valid files."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        url = reverse('management:backup-download-multiple', kwargs={'archive_format': 'zip'})
        response = self.client.post(url, {'selected': ['nonexistent.dump.gz']})
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('No valid files' in str(message) for message in messages))

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()


class BackupFilesDeleteMultipleViewTest(TestCase):
    """Test suite for BackupFilesDeleteMultipleView."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.client = Client()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp_dir.name)
        
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    @patch('management.views.backup.settings')
    def test_delete_multiple_success(self, mock_settings: MagicMock) -> None:
        """Test successfully deleting multiple backup files."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        # Create test backup files
        file1 = self.backup_dir / 'backup_1.dump.gz'
        file2 = self.backup_dir / 'backup_2.dump.gz'
        file1.write_bytes(b'content1')
        file2.write_bytes(b'content2')
        
        url = reverse('management:backup-delete-multiple')
        response = self.client.post(url, {'selected': ['backup_1.dump.gz', 'backup_2.dump.gz']})
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Deleted' in str(message) for message in messages))
        
        # Verify files were deleted
        self.assertFalse(file1.exists())
        self.assertFalse(file2.exists())

    def test_delete_multiple_no_selection(self) -> None:
        """Test deleting with no files selected."""
        url = reverse('management:backup-delete-multiple')
        response = self.client.post(url, {'selected': []})
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('No files selected' in str(message) for message in messages))

    @patch('management.views.backup.settings')
    def test_delete_multiple_nonexistent_file(self, mock_settings: MagicMock) -> None:
        """Test deleting files that don't exist."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        url = reverse('management:backup-delete-multiple')
        response = self.client.post(url, {'selected': ['nonexistent.dump.gz']})
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Errors deleting' in str(message) for message in messages))

    @patch('management.views.backup.settings')
    def test_delete_multiple_mixed_results(self, mock_settings: MagicMock) -> None:
        """Test deleting with mix of existing and nonexistent files."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        # Create one test backup file
        file1 = self.backup_dir / 'backup_1.dump.gz'
        file1.write_bytes(b'content1')
        
        url = reverse('management:backup-delete-multiple')
        response = self.client.post(url, {'selected': ['backup_1.dump.gz', 'nonexistent.dump.gz']})
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        message_strs = [str(m) for m in messages]
        
        # Should have both success and error messages
        self.assertTrue(any('Deleted' in msg for msg in message_strs))
        self.assertTrue(any('Errors deleting' in msg for msg in message_strs))

    @patch('management.views.backup.settings')
    @patch('pathlib.Path.unlink')
    def test_delete_multiple_os_error(self, mock_unlink: MagicMock, mock_settings: MagicMock) -> None:
        """Test deleting files with OSError."""
        mock_settings.BACKUP_FILE_PATH = self.backup_dir
        
        # Create test backup file
        file1 = self.backup_dir / 'backup_1.dump.gz'
        file1.write_bytes(b'content1')
        
        # Mock unlink to raise OSError
        mock_unlink.side_effect = OSError('Permission denied')
        
        url = reverse('management:backup-delete-multiple')
        response = self.client.post(url, {'selected': ['backup_1.dump.gz']})
        
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Errors deleting' in str(message) for message in messages))

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()
