"""Tests for BackupRestoreView and related functionality."""

import subprocess
from unittest.mock import Mock, patch

import pytest
from django.contrib.messages import get_messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory

from setup_wizard.views import BackupRestoreView


@pytest.mark.django_db
class TestBackupRestoreViewPost:
    """Test POST method of BackupRestoreView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BackupRestoreView()

    def test_post_invalid_form(self):
        """Test POST with invalid form data."""
        request = self.factory.post('/backup-restore/', {})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        with patch.object(self.view, '_handle_invalid_form') as mock_invalid:
            mock_invalid.return_value = Mock(status_code=302, url='/login/')

            response = self.view.post(request)

            mock_invalid.assert_called_once()

    @patch.object(BackupRestoreView, '_process_backup_file')
    def test_post_subprocess_error(self, mock_process):
        """Test POST with subprocess CalledProcessError."""
        mock_process.side_effect = subprocess.CalledProcessError(1, 'restore')

        backup_file = SimpleUploadedFile('backup.sql', b'backup data')
        request = self.factory.post('/backup-restore/', {'backup_file': backup_file, 'backup_password': 'test123'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        with patch.object(self.view, '_map_exit_code_to_message', return_value='Error'):
            response = self.view.post(request)

            assert response.status_code == 302
            messages_list = list(get_messages(request))
            assert any('Restore script failed' in str(m) for m in messages_list)

    @patch.object(BackupRestoreView, '_process_backup_file')
    def test_post_file_not_found(self, mock_process):
        """Test POST with FileNotFoundError."""
        mock_process.side_effect = FileNotFoundError('Script not found')

        backup_file = SimpleUploadedFile('backup.sql', b'backup data')
        request = self.factory.post('/backup-restore/', {'backup_file': backup_file})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        response = self.view.post(request)

        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('Restore script not found' in str(m) for m in messages_list)

    @patch.object(BackupRestoreView, '_process_backup_file')
    def test_post_unexpected_exception(self, mock_process):
        """Test POST with unexpected exception."""
        mock_process.side_effect = ValueError('Unexpected error')

        backup_file = SimpleUploadedFile('backup.sql', b'backup data')
        request = self.factory.post('/backup-restore/', {'backup_file': backup_file})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        response = self.view.post(request)

        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('unexpected error occurred' in str(m) for m in messages_list)


@pytest.mark.django_db
class TestBackupRestoreViewHelpers:
    """Test helper methods of BackupRestoreView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BackupRestoreView()
        request = self.factory.post('/backup-restore/')
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        self.view.request = request
        self.view.setup(request)

    def test_handle_invalid_form(self):
        """Test _handle_invalid_form adds error message."""
        response = self.view._handle_invalid_form()

        assert response.status_code == 302
        messages_list = list(get_messages(self.view.request))
        assert any('correct the errors' in str(m) for m in messages_list)
