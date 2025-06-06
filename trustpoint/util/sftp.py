# util/sftp.py
"""Wrapper around Paramiko SFTP functionality and related exceptions."""

import io
import socket
from pathlib import Path, PurePosixPath
from typing import Any

import paramiko
from settings.models import BackupOptions


class SftpError(Exception):
    """Custom exception for any SFTP-related failures."""


class SftpClient:
    """Wrapper around Paramiko SFTP functionality.

    If instantiated without overrides, reads settings from BackupOptions(pk=1).
    Optionally, an overrides dict can supply:
      host, port, user, auth_method, password, private_key, key_passphrase,
      local_storage, remote_directory.
    """

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        """Initialize the SftpClient.

        Args:
            overrides: If provided, a dict of any BackupOptions fields to override.
        """
        try:
            opts = BackupOptions.objects.get(pk=1)
        except BackupOptions.DoesNotExist:
            opts = None

        def _get(field: str, default: Any = None) -> Any:
            if overrides and field in overrides:
                return overrides[field]
            if opts:
                return getattr(opts, field)
            return default

        self.host: str = _get('host', '') or ''
        self.port: int = _get('port', default=2222) or 2222
        self.username: str = _get('user', '') or ''
        self.auth_method: str = _get('auth_method', '') or ''
        self.password: str | None = _get('password', '') or None
        self.private_key_text: str | None = _get('private_key', '') or None
        self.passphrase: str | None = _get('key_passphrase', '') or None

        self.store_locally: bool = bool(_get('local_storage', default=False))
        self.remote_directory: str = (_get('remote_directory', '') or '').strip()

        if self.auth_method:
            valid_methods = BackupOptions.AuthMethod.values
            if self.auth_method not in valid_methods:
                msg = f'Invalid auth_method: {self.auth_method}'
                raise SftpError(msg)
            if (
                self.auth_method == BackupOptions.AuthMethod.PASSWORD
                and not self.password
            ):
                msg = 'Password is required for password authentication.'
                raise SftpError(msg)
            if (
                self.auth_method == BackupOptions.AuthMethod.SSH_KEY
                and not (self.private_key_text or '').strip()
            ):
                msg = 'Private key is required for SSH-key authentication.'
                raise SftpError(msg)

    def _load_private_key(self) -> paramiko.PKey:
        """Load a Paramiko PKey from the stored private_key_text and passphrase.

        Returns:
            A Paramiko PKey object.

        Raises:
            SftpError: If key loading fails or no key provided.
        """
        if not self.private_key_text:
            msg = 'No private key provided.'
            raise SftpError(msg)

        try:
            key_stream = io.StringIO(self.private_key_text)
            return paramiko.RSAKey.from_private_key(
                key_stream, password=self.passphrase or None
            )
        except paramiko.SSHException as e:
            msg = f'Failed to load private key: {e}'
            raise SftpError(msg) from e

    def _connect_sftp(self) -> tuple[paramiko.Transport, paramiko.SFTPClient]:
        """Establish an SFTP connection and return the Transport and SFTPClient.

        Returns:
            A tuple of (Transport, SFTPClient).

        Raises:
            SftpError: If no auth_method is set or authentication/SSH errors occur.
        """
        if not self.auth_method:
            msg = 'No SFTP configured; cannot connect.'
            raise SftpError(msg)

        try:
            transport = paramiko.Transport((self.host, self.port))
            if self.auth_method == BackupOptions.AuthMethod.PASSWORD:
                transport.connect(username=self.username, password=self.password)
            else:
                pkey = self._load_private_key()
                transport.connect(username=self.username, pkey=pkey)

            sftp = paramiko.SFTPClient.from_transport(transport)
            if sftp is None:
                transport.close()
                msg = 'Authentication failed.'
                raise SftpError(msg)
            return transport, sftp  # noqa: TRY300

        except paramiko.AuthenticationException as e:
            msg = 'Authentication failed.'
            raise SftpError(msg) from e
        except paramiko.SSHException as e:
            msg = f'SSH error: {e}'
            raise SftpError(msg) from e
        except (socket.gaierror, OSError) as e:
            msg = f'Could not connect to {self.host}:{self.port} – {e}'
            raise SftpError(msg) from e

    def test_connection(self) -> None:
        """Attempt an SFTP connection with the current settings.

        Raises:
            SftpError: If no auth_method, authentication fails, or any SSH error.
        """
        transport: paramiko.Transport | None = None
        try:
            transport, sftp = self._connect_sftp()
            sftp.close()
        finally:
            if transport and transport.is_active():
                transport.close()

    def upload_file(self, local_filepath: Path, remote_path: str) -> None:  # noqa: C901
        """Upload a single local file to the remote_path via SFTP.

        Args:
            local_filepath: Path to the local file to upload.
            remote_path: Full remote path (including filename) at the server.

        Raises:
            SftpError: If no auth_method, local file missing, or any SSH/SFTP error.
        """
        if not self.auth_method:
            msg = 'No SFTP configured; cannot upload.'
            raise SftpError(msg)

        if not local_filepath.exists() or not local_filepath.is_file():
            msg = f'Local file does not exist: {local_filepath}'
            raise SftpError(msg)

        transport: paramiko.Transport | None = None
        try:
            transport, sftp = self._connect_sftp()

            # Ensure remote directory exists (mkdir -p behavior)
            remote_dir = PurePosixPath(remote_path).parent
            if str(remote_dir) not in ('', '.'):
                path_accum = PurePosixPath(remote_dir.parts[0])
                for part in remote_dir.parts[1:]:
                    path_accum /= part
                    try:
                        sftp.stat(str(path_accum))
                    except OSError:
                        try:
                            sftp.mkdir(str(path_accum))
                        except paramiko.SSHException as e:
                            msg = f'Failed to create remote directory {path_accum}: {e}'
                            raise SftpError(msg) from e
                        except PermissionError as e:
                            msg = f'Failed to create remote directory {path_accum}: {e}'
                            raise SftpError(msg) from e

            try:
                sftp.put(str(local_filepath), remote_path)
            except paramiko.SSHException as e:
                msg = f'SSH error during upload: {e}'
                raise SftpError(msg) from e

            sftp.close()
        except paramiko.SSHException as e:
            msg = f'Upload failed: {e}'
            raise SftpError(msg) from e
        finally:
            if transport and transport.is_active():
                transport.close()
