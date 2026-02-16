"""Tests for util/sftp.py."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from management.models import BackupOptions
from util.sftp import SftpClient, SftpError


@pytest.mark.django_db
class TestSftpClient:
    """Tests for SftpClient class."""

    def test_init_with_no_backup_options(self) -> None:
        """Test initialization when no BackupOptions exist."""
        # No BackupOptions in DB
        client = SftpClient()
        
        assert client.host == ''
        assert client.port == 2222
        assert client.username == ''
        assert client.auth_method == ''

    def test_init_with_overrides(self) -> None:
        """Test initialization with overrides dict."""
        overrides = {
            'host': 'sftp.example.com',
            'port': 2200,
            'user': 'testuser',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'testpass',
            'remote_directory': '/backups',
        }
        
        client = SftpClient(overrides=overrides)
        
        assert client.host == 'sftp.example.com'
        assert client.port == 2200
        assert client.username == 'testuser'
        assert client.auth_method == BackupOptions.AuthMethod.PASSWORD
        assert client.password == 'testpass'
        assert client.remote_directory == '/backups'

    def test_init_with_backup_options_from_db(self) -> None:
        """Test initialization reading from BackupOptions model."""
        # Create BackupOptions in DB
        BackupOptions.objects.create(
            pk=1,
            host='db-sftp.example.com',
            port=2222,
            user='dbuser',
            auth_method=BackupOptions.AuthMethod.SSH_KEY,
            private_key='-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----',
            remote_directory='/db-backups',
        )
        
        client = SftpClient()
        
        assert client.host == 'db-sftp.example.com'
        assert client.port == 2222
        assert client.username == 'dbuser'
        assert client.auth_method == BackupOptions.AuthMethod.SSH_KEY

    def test_init_overrides_take_precedence(self) -> None:
        """Test that overrides take precedence over DB values."""
        BackupOptions.objects.create(
            pk=1,
            host='db-host.example.com',
            port=2222,
            user='dbuser',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='dbpassword',
        )
        
        overrides = {
            'host': 'override-host.example.com',
            'user': 'override-user',
        }
        
        client = SftpClient(overrides=overrides)
        
        assert client.host == 'override-host.example.com'
        assert client.username == 'override-user'
        assert client.port == 2222  # Not overridden, comes from DB
        assert client.auth_method == BackupOptions.AuthMethod.PASSWORD  # Comes from DB

    def test_init_invalid_auth_method_raises_error(self) -> None:
        """Test that invalid auth_method raises SftpError."""
        overrides = {
            'auth_method': 'invalid_method',
        }
        
        with pytest.raises(SftpError, match='Invalid auth_method'):
            SftpClient(overrides=overrides)

    def test_init_password_auth_without_password_raises_error(self) -> None:
        """Test that password auth without password raises SftpError."""
        overrides = {
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': '',  # Empty password
        }
        
        with pytest.raises(SftpError, match='Password is required'):
            SftpClient(overrides=overrides)

    def test_init_ssh_key_auth_without_key_raises_error(self) -> None:
        """Test that SSH key auth without key raises SftpError."""
        overrides = {
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'private_key': '',  # Empty key
        }
        
        with pytest.raises(SftpError, match='Private key is required'):
            SftpClient(overrides=overrides)

    def test_init_remote_directory_stripped(self) -> None:
        """Test that remote directory is stripped of whitespace."""
        overrides = {
            'remote_directory': '  /backups/data  ',
        }
        
        client = SftpClient(overrides=overrides)
        
        assert client.remote_directory == '/backups/data'

    @patch('util.sftp.paramiko.RSAKey.from_private_key')
    def test_load_private_key_success(self, mock_from_private_key: Mock) -> None:
        """Test successful private key loading."""
        mock_key = Mock()
        mock_from_private_key.return_value = mock_key
        
        overrides = {
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----',
        }
        
        client = SftpClient(overrides=overrides)
        key = client._load_private_key()
        
        assert key == mock_key
        mock_from_private_key.assert_called_once()

    def test_load_private_key_no_key_raises_error(self) -> None:
        """Test that loading key without key text raises SftpError."""
        overrides = {
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'test',
        }
        
        client = SftpClient(overrides=overrides)
        client.private_key_text = None
        
        with pytest.raises(SftpError, match='No private key provided'):
            client._load_private_key()

    @patch('util.sftp.paramiko.RSAKey.from_private_key')
    def test_load_private_key_with_passphrase(self, mock_from_private_key: Mock) -> None:
        """Test loading encrypted private key with passphrase."""
        mock_key = Mock()
        mock_from_private_key.return_value = mock_key
        
        overrides = {
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\nencrypted\n-----END RSA PRIVATE KEY-----',
            'key_passphrase': 'my-passphrase',
        }
        
        client = SftpClient(overrides=overrides)
        key = client._load_private_key()
        
        assert key == mock_key
        # Verify passphrase was passed
        call_kwargs = mock_from_private_key.call_args[1]
        assert call_kwargs['password'] == 'my-passphrase'

    @patch('util.sftp.paramiko.RSAKey.from_private_key')
    def test_load_private_key_ssh_exception_raises_error(self, mock_from_private_key: Mock) -> None:
        """Test that SSH exception during key load raises SftpError."""
        import paramiko
        mock_from_private_key.side_effect = paramiko.SSHException('Invalid key format')
        
        overrides = {
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----',
        }
        
        client = SftpClient(overrides=overrides)
        
        with pytest.raises(SftpError, match='Failed to load private key'):
            client._load_private_key()

    def test_connect_sftp_no_auth_method_raises_error(self) -> None:
        """Test that connecting without auth_method raises SftpError."""
        client = SftpClient()
        
        with pytest.raises(SftpError, match='No SFTP configured'):
            client._connect_sftp()

    @patch('util.sftp.paramiko.Transport')
    @patch('util.sftp.paramiko.SFTPClient.from_transport')
    def test_connect_sftp_password_auth_success(
        self,
        mock_sftp_from_transport: Mock,
        mock_transport_class: Mock
    ) -> None:
        """Test successful SFTP connection with password auth."""
        mock_transport = Mock()
        mock_transport_class.return_value = mock_transport
        mock_sftp = Mock()
        mock_sftp_from_transport.return_value = mock_sftp
        
        overrides = {
            'host': 'sftp.example.com',
            'port': 2222,
            'user': 'testuser',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'testpass',
        }
        
        client = SftpClient(overrides=overrides)
        transport, sftp = client._connect_sftp()
        
        assert transport == mock_transport
        assert sftp == mock_sftp
        mock_transport_class.assert_called_once_with(('sftp.example.com', 2222))
        mock_transport.connect.assert_called_once_with(username='testuser', password='testpass')

    @patch('util.sftp.paramiko.Transport')
    @patch('util.sftp.paramiko.SFTPClient.from_transport')
    def test_test_connection_success(
        self,
        mock_sftp_from_transport: Mock,
        mock_transport_class: Mock
    ) -> None:
        """Test successful connection test."""
        mock_transport = Mock()
        mock_transport_class.return_value = mock_transport
        mock_sftp = Mock()
        mock_sftp_from_transport.return_value = mock_sftp
        
        overrides = {
            'host': 'sftp.example.com',
            'port': 2222,
            'user': 'testuser',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'testpass',
        }
        
        client = SftpClient(overrides=overrides)
        client.test_connection()  # Should not raise
        
        mock_sftp.close.assert_called_once()
        mock_transport.close.assert_called_once()

    def test_upload_file_no_auth_method_raises_error(self, tmp_path: Path) -> None:
        """Test that upload without auth_method raises SftpError."""
        client = SftpClient()
        local_file = tmp_path / 'test.txt'
        local_file.write_text('test content')
        
        with pytest.raises(SftpError, match='No SFTP configured'):
            client.upload_file(local_file, '/remote/test.txt')

    def test_upload_file_nonexistent_file_raises_error(self) -> None:
        """Test that upload of nonexistent file raises SftpError."""
        overrides = {
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'test',
        }
        
        client = SftpClient(overrides=overrides)
        
        with pytest.raises(SftpError, match='Local file does not exist'):
            client.upload_file(Path('/nonexistent/file.txt'), '/remote/test.txt')

    @patch('util.sftp.paramiko.Transport')
    @patch('util.sftp.paramiko.SFTPClient.from_transport')
    def test_upload_file_success(
        self,
        mock_sftp_from_transport: Mock,
        mock_transport_class: Mock,
        tmp_path: Path
    ) -> None:
        """Test successful file upload."""
        mock_transport = Mock()
        mock_transport_class.return_value = mock_transport
        mock_sftp = Mock()
        mock_sftp_from_transport.return_value = mock_sftp
        
        # Mock stat to simulate directory exists
        mock_sftp.stat.return_value = Mock()
        
        local_file = tmp_path / 'test.txt'
        local_file.write_text('test content')
        
        overrides = {
            'host': 'sftp.example.com',
            'port': 2222,
            'user': 'testuser',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'testpass',
        }
        
        client = SftpClient(overrides=overrides)
        client.upload_file(local_file, '/remote/backups/test.txt')
        
        mock_sftp.put.assert_called_once_with(str(local_file), '/remote/backups/test.txt')
        mock_sftp.close.assert_called_once()
        mock_transport.close.assert_called_once()
