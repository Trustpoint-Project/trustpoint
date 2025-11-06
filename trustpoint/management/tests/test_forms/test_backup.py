"""Test suite for the BackupOptionsForm."""
from django.test import TestCase
from management.forms import BackupOptionsForm
from management.models import BackupOptions

class BackupOptionsFormTest(TestCase):
    """Test suite for the BackupOptionsForm."""

    def test_valid_form_with_password_auth(self):
        """Test form validation with PASSWORD authentication."""
        form_data = {
            'enable_sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'secure_password',
            'remote_directory': '/backups/',
        }
        form = BackupOptionsForm(data=form_data)
        assert form.is_valid()

    def test_valid_form_with_ssh_key_auth(self):
        """Test form validation with SSH_KEY authentication."""
        form_data = {
            'enable_sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'private_key': 'secure_private_key',
            'remote_directory': '/backups/',
        }
        form = BackupOptionsForm(data=form_data)
        assert form.is_valid()

    def test_missing_required_fields(self):
        """Test form validation fails when required fields are missing."""
        form_data = {
            'enable_sftp_storage': True,
            'host': '',
            'port': 22,
            'user': '',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': '',
            'remote_directory': '',
        }
        form = BackupOptionsForm(data=form_data)
        assert not form.is_valid()
        assert 'The following fields are required when SFTP storage is enabled' in str(form.errors)

    def test_password_auth_with_private_key(self):
        """Test form validation fails when PASSWORD auth is used with a private key."""
        form_data = {
            'enable_sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'secure_password',
            'private_key': 'private_key',
            'remote_directory': '/backups/',
        }
        form = BackupOptionsForm(data=form_data)
        assert not form.is_valid()
        assert 'Private key and passphrase must be empty when using password authentication.' in str(form.errors)

    def test_ssh_key_auth_with_password(self):
        """Test form validation fails when SSH_KEY auth is used with a password."""
        form_data = {
            'enable_sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'password': 'secure_password',
            'private_key': 'secure_private_key',
            'remote_directory': '/backups/',
        }
        form = BackupOptionsForm(data=form_data)
        assert not form.is_valid()
        assert 'Password must be empty when using SSH key authentication.' in str(form.errors)
