"""Test suite for the BackupOptions model."""
from django.core.exceptions import ValidationError
from django.test import TestCase
from management.forms import BackupOptionsForm
from management.models import BackupOptions


class BackupOptionsModelTest(TestCase):
    """Test suite for the BackupOptions model, ensuring that it enforces singleton behavior."""

    def test_singleton_creation(self) -> None:
        """Test that attempts to create more than one BackupOptions instance."""
        BackupOptions.objects.create(
            host='localhost',
            port=22,
            user='user',
            local_storage=True
        )
        with self.assertRaises(ValidationError):
            BackupOptions.objects.create(
                host='remote',
                port=22,
                user='another_user',
                local_storage=False
            )

    def test_singleton_save_overwrite(self) -> None:
        """Test that saving an existing BackupOptions instance overwrites its values."""
        instance = BackupOptions.objects.create(
            host='localhost',
            port=22,
            user='user',
            local_storage=True
        )
        instance.host = 'updated_host'
        instance.save()
        self.assertEqual(BackupOptions.objects.count(), 1)
        self.assertEqual(BackupOptions.objects.first().host, 'updated_host')

class BackupOptionsFormTest(TestCase):
    """Test suite for the BackupOptionsForm, ensuring validation logic."""

    def test_invalid_sftp_configuration(self) -> None:
        """Test that enabling SFTP storage without providing required fields."""
        # SFTP is enabled but without necessary fields like host and user
        form_data = {
            'local_storage': False,
            'sftp_storage': True,
            'host': '',
            'port': 2222,
            'user': '',
            'auth_method': '',
        }
        form = BackupOptionsForm(data=form_data)

        self.assertFalse(form.is_valid())
        error_message = form.errors.as_text()

        self.assertIn('Host', error_message)
        self.assertIn('Username', error_message)
        self.assertIn('Remote Directory', error_message)

    def test_sftp_password_auth_without_password(self) -> None:
        """Test validation fails when password is not provided for PASSWORD auth method."""
        form_data = {
            'local_storage': False,
            'sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': '',  # Missing password
        }
        form = BackupOptionsForm(data=form_data)

        self.assertFalse(form.is_valid())
        self.assertIn('Password is required when using password authentication.', form.errors['password'])

    def test_sftp_ssh_key_auth_without_private_key(self) -> None:
        """Test validation fails when private_key is not provided for SSH_KEY auth method."""
        form_data = {
            'local_storage': False,
            'sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'private_key': '',  # Missing private key
        }
        form = BackupOptionsForm(data=form_data)

        self.assertFalse(form.is_valid())
        self.assertIn('Private key is required when using SSH Key authentication.', form.errors['private_key'])

    def test_valid_sftp_password_auth(self) -> None:
        """Test that SFTP with PASSWORD auth method and valid password passes validation."""
        form_data = {
            'local_storage': False,
            'sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.PASSWORD,
            'password': 'secure_password',
            'remote_directory': '/backups/',
        }
        form = BackupOptionsForm(data=form_data)

        self.assertTrue(form.is_valid())

    def test_valid_sftp_ssh_key_auth(self) -> None:
        """Test that SFTP with SSH_KEY auth method and valid private_key passes validation."""
        form_data = {
            'local_storage': False,
            'sftp_storage': True,
            'host': 'localhost',
            'port': 22,
            'user': 'user',
            'auth_method': BackupOptions.AuthMethod.SSH_KEY,
            'private_key': 'secure_private_key',
            'remote_directory': '/backups/',
        }
        form = BackupOptionsForm(data=form_data)

        self.assertTrue(form.is_valid())


