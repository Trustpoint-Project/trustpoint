# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for util/sftp.py."""

from io import StringIO
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest
import paramiko

from management.models import BackupOptions
from management.tests.ssh_helpers import SFTP_HOST_KEY
from util.sftp import SftpClient, SftpError


@pytest.fixture(scope='module')
def ssh_keys():
    return [paramiko.RSAKey.generate(2048) for _ in range(3)]


@pytest.mark.django_db
@pytest.mark.parametrize('auth_method', [BackupOptions.AuthMethod.PASSWORD, BackupOptions.AuthMethod.SSH_KEY])
@pytest.mark.parametrize('host_status', ['trusted', 'missing', 'changed'])
@pytest.mark.parametrize('port', [22, 2222])
def test_pinned_host_key_is_verified_before_authentication(ssh_keys, auth_method, host_status, port):
    """Paramiko verifies the configured key before either authentication method runs."""
    trusted, changed, private = ssh_keys
    key_text = StringIO()
    private.write_private_key(key_text)
    public_key = f'{trusted.get_name()} {trusted.get_base64()}'
    client = SftpClient(
        overrides={
            'host': 'sftp.example.com',
            'port': port,
            'user': 'backup',
            'auth_method': auth_method,
            'host_key': public_key if host_status != 'missing' else '',
            'password': 'configured-password',
            'private_key': key_text.getvalue(),
        }
    )
    transport = Mock()
    transport.get_remote_server_key.return_value = changed if host_status == 'changed' else trusted
    transport.get_security_options.return_value.key_types = ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa']
    sftp = Mock()
    transport.open_sftp_client.return_value = sftp
    with (
        patch.object(paramiko.SSHClient, '_families_and_addresses', return_value=[(2, ('127.0.0.1', port))]),
        patch('paramiko.client.socket.socket'),
        patch('paramiko.client.Transport', return_value=transport),
        patch.object(paramiko.SSHClient, '_auth') as authenticate,
    ):
        if host_status == 'trusted':
            ssh, connection = client._connect_sftp()
            try:
                assert connection is sftp
                authenticate.assert_called_once()
                assert authenticate.call_args.args[0] == 'backup'
                assert authenticate.call_args.args[1] == (
                    'configured-password' if auth_method == BackupOptions.AuthMethod.PASSWORD else None
                )
                assert authenticate.call_args.args[2] == (
                    private if auth_method == BackupOptions.AuthMethod.SSH_KEY else None
                )
                assert authenticate.call_args.args[4:6] == (False, False)
            finally:
                ssh.close()
        else:
            with pytest.raises(SftpError):
                client._connect_sftp()
            authenticate.assert_not_called()
            transport.open_sftp_client.assert_not_called()
            if host_status == 'changed':
                transport.close.assert_called_once()
            else:
                transport.close.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize(
    'error',
    [
        paramiko.AuthenticationException('Bad credentials'),
        paramiko.SSHException('Handshake failed'),
        OSError('Connection refused'),
    ],
)
def test_failed_connection_closes_ssh_client(error):
    client = SftpClient(
        overrides={
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'test',
            'host_key': SFTP_HOST_KEY,
        }
    )
    with (
        patch.object(paramiko.SSHClient, 'connect', side_effect=error),
        patch.object(paramiko.SSHClient, 'close') as close,
    ):
        with pytest.raises(SftpError):
            client._connect_sftp()
    close.assert_called_once()


@pytest.mark.django_db
@pytest.mark.parametrize('host_key', ['', 'not a key', 'ssh-rsa invalid', SFTP_HOST_KEY + '\n' + SFTP_HOST_KEY])
def test_invalid_pinned_key_fails_before_connecting(host_key):
    client = SftpClient(
        overrides={
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'test',
            'host_key': host_key,
        }
    )
    with patch('util.sftp.paramiko.SSHClient') as ssh_class:
        with pytest.raises(SftpError):
            client._connect_sftp()
    ssh_class.assert_not_called()


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
            'host_key': SFTP_HOST_KEY,
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
            host_key=SFTP_HOST_KEY,
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
            host_key=SFTP_HOST_KEY,
            port=2222,
            user='dbuser',
            auth_method=BackupOptions.AuthMethod.PASSWORD,
            password='dbpassword',
        )

        overrides = {
            'host': 'override-host.example.com',
            'host_key': SFTP_HOST_KEY,
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

    @patch('util.sftp.paramiko.SSHClient')
    def test_connect_sftp_password_auth_success(self, mock_ssh_class: Mock) -> None:
        """Load trusted host keys and use only the configured password."""
        ssh = mock_ssh_class.return_value
        ssh.__enter__.return_value = ssh
        client = SftpClient(
            overrides={
                'host': 'sftp.example.com',
                'port': 2222,
                'user': 'testuser',
                'host_key': SFTP_HOST_KEY,
                'auth_method': BackupOptions.AuthMethod.PASSWORD,
                'password': 'testpass',
            }
        )

        connection, sftp = client._connect_sftp()

        assert connection is ssh
        assert sftp is ssh.open_sftp.return_value
        ssh.load_system_host_keys.assert_not_called()
        assert isinstance(ssh.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
        ssh.connect.assert_called_once_with(
            hostname='sftp.example.com',
            port=2222,
            username='testuser',
            password='testpass',
            pkey=None,
            allow_agent=False,
            look_for_keys=False,
        )
        ssh.close.assert_not_called()
        connection.close()

    @patch('util.sftp.paramiko.SSHClient')
    def test_test_connection_success(self, mock_ssh_class: Mock) -> None:
        """Connection testing closes both the SFTP session and its SSH owner."""
        ssh = mock_ssh_class.return_value
        ssh.__enter__.return_value = ssh
        client = SftpClient(
            overrides={
                'host': 'sftp.example.com',
                'port': 2222,
                'user': 'testuser',
                'host_key': SFTP_HOST_KEY,
                'auth_method': BackupOptions.AuthMethod.PASSWORD,
                'password': 'testpass',
            }
        )

        client.test_connection()

        ssh.open_sftp.return_value.close.assert_called_once()
        ssh.close.assert_called_once()

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

    @pytest.mark.parametrize('directories_exist', [False, True])
    @pytest.mark.parametrize(
        ('remote_path', 'directories'),
        [
            ('backups/file.dump.gz', ['backups']),
            ('backups/daily/file.dump.gz', ['backups', 'backups/daily']),
            ('./backups/file.dump.gz', ['backups']),
            ('/backups/daily/file.dump.gz', ['/backups', '/backups/daily']),
            ('//backups/file.dump.gz', ['//backups']),
            ('/file.dump.gz', []),
            ('file.dump.gz', []),
        ],
    )
    def test_upload_checks_every_directory_component(
        self,
        tmp_path: Path,
        remote_path: str,
        directories: list[str],
        directories_exist: bool,
    ) -> None:
        """Create missing parents in order without checking or creating the remote root."""
        local_file = tmp_path / 'backup.dump.gz'
        local_file.write_bytes(b'backup')
        client = SftpClient(overrides={'auth_method': BackupOptions.AuthMethod.PASSWORD, 'password': 'test'})
        ssh, sftp = Mock(), Mock()
        if not directories_exist:
            sftp.stat.side_effect = FileNotFoundError

        with patch.object(client, '_connect_sftp', return_value=(ssh, sftp)):
            client.upload_file(local_file, remote_path)

        assert sftp.stat.call_args_list == [call(directory) for directory in directories]
        assert sftp.mkdir.call_args_list == (
            [] if directories_exist else [call(directory) for directory in directories]
        )
        sftp.put.assert_called_once_with(str(local_file), remote_path)
        sftp.close.assert_called_once()
        ssh.close.assert_called_once()

    @patch('util.sftp.paramiko.SSHClient')
    def test_upload_file_success(self, mock_ssh_class: Mock, tmp_path: Path) -> None:
        """Uploads retain their path handling and close the verified connection."""
        ssh = mock_ssh_class.return_value
        ssh.__enter__.return_value = ssh
        sftp = ssh.open_sftp.return_value
        local_file = tmp_path / 'test.txt'
        local_file.write_text('test content')
        client = SftpClient(
            overrides={
                'host': 'sftp.example.com',
                'port': 2222,
                'user': 'testuser',
                'host_key': SFTP_HOST_KEY,
                'auth_method': BackupOptions.AuthMethod.PASSWORD,
                'password': 'testpass',
            }
        )

        client.upload_file(local_file, '/remote/backups/test.txt')

        sftp.put.assert_called_once_with(str(local_file), '/remote/backups/test.txt')
        sftp.close.assert_called_once()
        ssh.close.assert_called_once()
