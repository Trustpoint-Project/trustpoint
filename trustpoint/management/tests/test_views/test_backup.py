"""Test suite for the Backup views."""
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.messages import get_messages
from django.contrib.auth.models import User
from management.models import BackupOptions
from pathlib import Path
import tempfile
import os

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

    @patch('management.views.backup.create_db_backup')
    def test_create_local_backup(self, mock_create_db_backup: MagicMock) -> None:
        """Test creating a local backup."""
        mock_create_db_backup.return_value = 'backup_2025-10-30_12-00-00.dump.gz'

        response = self.client.post(self.url, {'create_local_backup': ''})

        assert response.status_code == 302
        messages = list(get_messages(response.wsgi_request))
        assert any('Database backup created locally' in str(message) for message in messages)

    @patch('management.views.backup.create_db_backup')
    @patch('management.views.backup.SftpClient')
    def test_create_sftp_backup_success(self, mock_sftp_client: MagicMock, mock_create_db_backup: MagicMock) -> None:
        """Test creating a backup and uploading via SFTP."""
        mock_create_db_backup.return_value = 'backup_2025-10-30_12-00-00.dump.gz'
        mock_client = MagicMock()
        mock_sftp_client.return_value = mock_client

        BackupOptions.objects.create(
            pk=1,
            enable_sftp_storage=True,
            host='localhost',
            port=22,
            user='user',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password=os.getenv('TEST_PASSWORD', 'password'),
            remote_directory='/remote/backups/'
        )

        response = self.client.post(self.url, {'create_sftp_backup': ''})

        assert response.status_code == 302
        mock_client.upload_file.assert_called_once()
        messages = list(get_messages(response.wsgi_request))
        assert any('Uploaded' in str(message) for message in messages)

    @patch('management.views.backup.SftpClient')
    def test_test_sftp_connection_success(self, mock_sftp_client: MagicMock) -> None:
        """Test testing SFTP connection."""
        mock_client = MagicMock()
        mock_sftp_client.return_value = mock_client

        response = self.client.post(self.url, {
            'test_sftp_connection': '',
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': os.getenv('TEST_PASSWORD', 'password'),
        })

        assert response.status_code == 200
        mock_client.test_connection.assert_called_once()
        messages = list(get_messages(response.wsgi_request))
        assert any('SFTP connection successful' in str(message) for message in messages)

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()
