"""Test suite for Django management commands."""

from io import StringIO
from unittest.mock import Mock, MagicMock, patch

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from packaging.version import Version

from management.models import AppVersion, PKCS11Token, KeyStorageConfig


class CompileMsgCommandTest(TestCase):
    """Test suite for compilemsg command."""

    def test_compilemsg_inherits_from_compilemessages(self) -> None:
        """Test that compilemsg is an alias for compilemessages."""
        from management.management.commands.compilemsg import Command
        from django.core.management.commands.compilemessages import Command as CompileMessagesCommand

        # Verify it inherits from the right class
        self.assertTrue(issubclass(Command, CompileMessagesCommand))


class MakeMsgCommandTest(TestCase):
    """Test suite for makemsg command."""

    def test_makemsg_has_custom_msgmerge_options(self) -> None:
        """Test that makemsg has custom msgmerge options."""
        from management.management.commands.makemsg import Command

        command = Command()
        expected_options = ['-q', '-N', '--backup=none', '--previous', '--update']

        self.assertEqual(command.msgmerge_options, expected_options)


class PrintVersionCommandTest(TestCase):
    """Test suite for printversion command."""

    def test_printversion_outputs_app_version(self) -> None:
        """Test that printversion outputs the application version."""
        out = StringIO()
        call_command('printversion', stdout=out)

        output = out.getvalue().strip()
        self.assertEqual(output, settings.APP_VERSION)

    def test_printversion_help_text(self) -> None:
        """Test that printversion has correct help text."""
        from management.management.commands.printversion import Command

        command = Command()
        self.assertIn('version', command.help.lower())


class InitTrustpointCommandTest(TestCase):
    """Test suite for inittrustpoint command."""

    @patch('management.management.commands.inittrustpoint.Path.open')
    @patch('management.management.commands.inittrustpoint.call_command')
    def test_inittrustpoint_with_migrations(self, mock_call_command: MagicMock, mock_open_file: MagicMock) -> None:
        """Test inittrustpoint runs migrations by default."""
        mock_open_file.return_value.__enter__.return_value.read.return_value = 'test-container-id'

        out = StringIO()
        call_command('inittrustpoint', stdout=out)

        # Should call migrate, collectstatic, compilemessages
        calls = [call[0][0] for call in mock_call_command.call_args_list]
        self.assertIn('migrate', calls)
        self.assertIn('collectstatic', calls)
        self.assertIn('compilemessages', calls)

    @patch('management.management.commands.inittrustpoint.Path.open')
    @patch('management.management.commands.inittrustpoint.call_command')
    def test_inittrustpoint_without_migrations(self, mock_call_command: MagicMock, mock_open_file: MagicMock) -> None:
        """Test inittrustpoint skips migrations with --nomigrations."""
        mock_open_file.return_value.__enter__.return_value.read.return_value = 'test-container-id'

        out = StringIO()
        call_command('inittrustpoint', '--nomigrations', stdout=out)

        # Should NOT call migrate
        calls = [call[0][0] for call in mock_call_command.call_args_list]
        self.assertNotIn('migrate', calls)
        # But should still call collectstatic and compilemessages
        self.assertIn('collectstatic', calls)
        self.assertIn('compilemessages', calls)

    @patch('management.management.commands.inittrustpoint.Path.open')
    @patch('management.management.commands.inittrustpoint.call_command')
    def test_inittrustpoint_with_tls(self, mock_call_command: MagicMock, mock_open_file: MagicMock) -> None:
        """Test inittrustpoint prepares TLS with --tls option."""
        mock_open_file.return_value.__enter__.return_value.read.return_value = 'test-container-id'

        out = StringIO()
        call_command('inittrustpoint', '--tls', stdout=out)

        # Should call tls_cred
        calls = [call[0][0] for call in mock_call_command.call_args_list]
        self.assertIn('tls_cred', calls)

        # Should create KeyStorageConfig
        self.assertTrue(KeyStorageConfig.objects.filter(pk=1).exists())

    @patch('management.management.commands.inittrustpoint.Path.open')
    @patch('management.management.commands.inittrustpoint.call_command')
    def test_inittrustpoint_container_id_not_found(
        self, mock_call_command: MagicMock, mock_open_file: MagicMock
    ) -> None:
        """Test inittrustpoint handles missing /etc/hostname file."""
        mock_open_file.side_effect = FileNotFoundError()

        out = StringIO()
        call_command('inittrustpoint', stdout=out)

        # Should still complete successfully
        output = out.getvalue()
        self.assertIn('initializing', output.lower())

    @patch('management.management.commands.inittrustpoint.Path.open')
    @patch('management.management.commands.inittrustpoint.call_command')
    def test_inittrustpoint_creates_app_version(self, mock_call_command: MagicMock, mock_open_file: MagicMock) -> None:
        """Test inittrustpoint creates AppVersion record."""
        mock_open_file.return_value.__enter__.return_value.read.return_value = 'container-123'

        out = StringIO()
        call_command('inittrustpoint', stdout=out)

        # Should create AppVersion
        app_version = AppVersion.objects.get(pk=1)
        self.assertEqual(app_version.version, settings.APP_VERSION)
        self.assertEqual(app_version.container_id, 'container-123')


class StartupManagerCommandTest(TestCase):
    """Test suite for startup_manager command."""

    @patch('management.management.commands.startup_manager.StartupStrategySelector')
    @patch('management.management.commands.startup_manager.StartupContextBuilder')
    def test_startup_manager_db_not_initialized(self, mock_builder: MagicMock, mock_selector: MagicMock) -> None:
        """Test startup_manager when database is not initialized."""
        # Simulate ProgrammingError when querying AppVersion
        with patch('management.management.commands.startup_manager.AppVersion.objects.first') as mock_first:
            from django.db.utils import ProgrammingError

            mock_first.side_effect = ProgrammingError('relation does not exist')

            mock_context = Mock()
            mock_builder_instance = Mock()
            mock_builder_instance.build_for_db_init.return_value = mock_context
            mock_builder.return_value = mock_builder_instance

            mock_strategy = Mock()
            mock_selector.select_startup_strategy.return_value = mock_strategy

            out = StringIO()
            call_command('startup_manager', stdout=out)

            mock_selector.select_startup_strategy.assert_called_once_with(db_initialized=False, has_version=False)
            mock_strategy.execute.assert_called_once_with(mock_context)

    @patch('management.management.commands.startup_manager.StartupStrategySelector')
    @patch('management.management.commands.startup_manager.StartupContextBuilder')
    def test_startup_manager_db_initialized_no_version(self, mock_builder: MagicMock, mock_selector: MagicMock) -> None:
        """Test startup_manager when database is initialized but no version record."""
        with patch('management.management.commands.startup_manager.AppVersion.objects.first') as mock_first:
            mock_first.return_value = None

            mock_context = Mock()
            mock_builder_instance = Mock()
            mock_builder_instance.build_for_db_init.return_value = mock_context
            mock_builder.return_value = mock_builder_instance

            mock_strategy = Mock()
            mock_selector.select_startup_strategy.return_value = mock_strategy

            out = StringIO()
            call_command('startup_manager', stdout=out)

            mock_selector.select_startup_strategy.assert_called_once_with(db_initialized=True, has_version=False)

    def test_startup_manager_version_parsing(self) -> None:
        """Test startup_manager can parse version from settings."""
        from management.management.commands.startup_manager import Command

        command = Command()
        version = command._parse_version('1.2.3')

        self.assertIsInstance(version, Version)
        self.assertEqual(str(version), '1.2.3')


class TlsCredCommandTest(TestCase):
    """Test suite for tls_cred command."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        KeyStorageConfig.objects.create(pk=1, storage_type=KeyStorageConfig.StorageType.SOFTWARE)

    @patch('management.management.commands.tls_cred.TlsServerCredentialGenerator')
    @patch('management.management.commands.tls_cred.CredentialModel')
    @patch('management.management.commands.tls_cred.ActiveTrustpointTlsServerCredentialModel')
    @patch('management.management.commands.tls_cred.NGINX_KEY_PATH')
    @patch('management.management.commands.tls_cred.NGINX_CERT_PATH')
    @patch('management.management.commands.tls_cred.NGINX_CERT_CHAIN_PATH')
    def test_tls_cred_write_out(
        self,
        mock_chain_path: MagicMock,
        mock_cert_path: MagicMock,
        mock_key_path: MagicMock,
        mock_active: MagicMock,
        mock_credential: MagicMock,
        mock_generator_class: MagicMock,
    ) -> None:
        """Test tls_cred command with --write_out option."""
        # Setup mocks
        mock_generator = Mock()
        mock_generator_class.return_value = mock_generator
        mock_tls_cred = Mock()
        mock_generator.generate_tls_server_credential.return_value = mock_tls_cred

        # Setup mock for the saved credential (this is what gets assigned to active_tls.credential)
        mock_saved_cred = Mock()

        # Setup mock for private key chain
        mock_key_serializer = Mock()
        mock_key_pem = Mock()
        mock_key_pem.decode.return_value = 'private_key'
        mock_key_serializer.as_pkcs8_pem.return_value = mock_key_pem

        # Setup mock for certificate chain
        mock_cert_serializer = Mock()
        mock_cert_pem = Mock()
        mock_cert_pem.decode.return_value = 'certificate'
        mock_cert_serializer.as_pem.return_value = mock_cert_pem

        # Setup mock for chain
        mock_chain_serializer = Mock()
        mock_chain_pem = Mock()
        mock_chain_pem.decode.return_value = 'chain'
        mock_chain_serializer.as_pem.return_value = mock_chain_pem

        mock_saved_cred.get_private_key_serializer.return_value = mock_key_serializer
        mock_saved_cred.get_certificate_serializer.return_value = mock_cert_serializer
        mock_saved_cred.get_certificate_chain_serializer.return_value = mock_chain_serializer
        mock_saved_cred.get_certificate().fingerprint.return_value = b'\x00\x01\x02\x03' * 8  # 32 bytes

        mock_credential.save_credential_serializer.return_value = mock_saved_cred

        mock_active_instance = Mock()
        mock_active.objects.get_or_create.return_value = (mock_active_instance, True)

        out = StringIO()
        call_command('tls_cred', '--write_out', stdout=out)

        # Verify write_text was called
        mock_key_path.write_text.assert_called_once()
        mock_cert_path.write_text.assert_called_once()
        mock_chain_path.write_text.assert_called_once()

    @patch('management.management.commands.tls_cred.TlsServerCredentialGenerator')
    @patch('management.management.commands.tls_cred.CredentialModel')
    @patch('management.management.commands.tls_cred.ActiveTrustpointTlsServerCredentialModel')
    def test_tls_cred_without_write_out(
        self, mock_active: MagicMock, mock_credential: MagicMock, mock_generator_class: MagicMock
    ) -> None:
        """Test tls_cred command without --write_out option."""
        # Setup mocks
        mock_generator = Mock()
        mock_generator_class.return_value = mock_generator
        mock_tls_cred = Mock()
        mock_generator.generate_tls_server_credential.return_value = mock_tls_cred

        # Setup mock for the saved credential (this is what gets assigned to active_tls.credential)
        mock_saved_cred = Mock()

        # Setup mock for private key chain
        mock_key_serializer = Mock()
        mock_key_pem = Mock()
        mock_key_pem.decode.return_value = 'private_key'
        mock_key_serializer.as_pkcs8_pem.return_value = mock_key_pem

        # Setup mock for certificate chain
        mock_cert_serializer = Mock()
        mock_cert_pem = Mock()
        mock_cert_pem.decode.return_value = 'certificate'
        mock_cert_serializer.as_pem.return_value = mock_cert_pem

        # Setup mock for chain
        mock_chain_serializer = Mock()
        mock_chain_pem = Mock()
        mock_chain_pem.decode.return_value = 'chain'
        mock_chain_serializer.as_pem.return_value = mock_chain_pem

        mock_saved_cred.get_private_key_serializer.return_value = mock_key_serializer
        mock_saved_cred.get_certificate_serializer.return_value = mock_cert_serializer
        mock_saved_cred.get_certificate_chain_serializer.return_value = mock_chain_serializer
        mock_saved_cred.get_certificate().fingerprint.return_value = b'\x00\x01\x02\x03' * 8  # 32 bytes

        mock_credential.save_credential_serializer.return_value = mock_saved_cred

        mock_active_instance = Mock()
        mock_active.objects.get_or_create.return_value = (mock_active_instance, True)

        out = StringIO()
        call_command('tls_cred', stdout=out)

        output = out.getvalue()
        self.assertIn('TLS Server Credential generated successfully', output)


class TrustpointBackupCommandTest(TestCase):
    """Test suite for trustpointbackup command."""

    @patch('management.management.commands.trustpointbackup.call_command')
    def test_trustpointbackup_with_filename(self, mock_call_command: MagicMock) -> None:
        """Test trustpointbackup command with filename option."""
        out = StringIO()
        call_command('trustpointbackup', '--filename=test_backup.dump.gz', stdout=out)

        # Should call dbbackup with the filename
        mock_call_command.assert_called_once_with('dbbackup', '-o', 'test_backup.dump.gz', '-z')

    def test_trustpointbackup_requires_filename(self) -> None:
        """Test trustpointbackup command requires filename."""
        out = StringIO()

        with self.assertRaises(CommandError) as cm:
            call_command('trustpointbackup', stdout=out)

        self.assertIn('--filename', str(cm.exception))


class TrustpointRestoreCommandTest(TestCase):
    """Test suite for trustpointrestore command."""

    @patch('management.management.commands.trustpointrestore.subprocess.run')
    @patch('management.management.commands.trustpointrestore.call_command')
    @patch('management.management.commands.trustpointrestore.ActiveTrustpointTlsServerCredentialModel')
    @patch('management.management.commands.trustpointrestore.AppVersion')
    def test_trustpointrestore_without_filepath(
        self,
        mock_app_version: MagicMock,
        mock_active_tls: MagicMock,
        mock_call_command: MagicMock,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test trustpointrestore command without filepath option."""
        # Setup mocks
        mock_version = Mock()
        mock_version.version = '1.0.0'
        mock_app_version.objects.first.return_value = mock_version

        mock_tls = Mock()
        mock_tls.credential.get_private_key_serializer().as_pkcs8_pem.return_value = b'key'
        mock_tls.credential.get_certificate_serializer().as_pem.return_value = b'cert'
        mock_tls.credential.get_certificate_chain_serializer().as_pem.return_value = b'chain'
        mock_active_tls.objects.get.return_value = mock_tls

        mock_subprocess.return_value = Mock(returncode=0)

        out = StringIO()
        call_command('trustpointrestore', stdout=out)

        # Should restore and show version mismatch message
        output = out.getvalue()
        self.assertIn('restoration', output.lower())

    @patch('management.management.commands.trustpointrestore.Path')
    def test_trustpointrestore_with_invalid_filepath(self, mock_path_class: MagicMock) -> None:
        """Test trustpointrestore when filepath doesn't exist."""
        mock_path = Mock()
        mock_path.exists.return_value = False
        mock_path_class.return_value = mock_path

        with self.assertRaises(CommandError):
            call_command('trustpointrestore', '--filepath=/nonexistent/file.dump.gz')


class UnwrapDekCommandTest(TestCase):
    """Test suite for unwrap_dek command."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        # kek is optional (nullable) - no need to create it for basic tests
        self.token = PKCS11Token.objects.create(
            label='test-token',
            slot=0,
            module_path='/usr/lib/softhsm/libsofthsm2.so',
        )

    def test_unwrap_dek_default_token(self) -> None:
        """Test unwrap_dek command with default token label."""
        out = StringIO()
        call_command('unwrap_dek', stdout=out)

        output = out.getvalue()
        # Should access the token we created in setUp
        self.assertIn('test-token', output)

    def test_unwrap_dek_custom_token(self) -> None:
        """Test unwrap_dek command with custom token label."""
        out = StringIO()
        call_command('unwrap_dek', '--token-label=test-token', stdout=out)

        output = out.getvalue()
        self.assertIn('test-token', output)

    def test_unwrap_dek_token_not_found(self) -> None:
        """Test unwrap_dek when token doesn't exist."""
        PKCS11Token.objects.all().delete()

        out = StringIO()
        # Command returns early without error when token not found
        call_command('unwrap_dek', '--token-label=nonexistent', stdout=out)

        output = out.getvalue()
        self.assertIn('not found', output.lower())


class UpdateTlsCommandTest(TestCase):
    """Test suite for update_tls command."""

    @patch('management.management.commands.update_tls.subprocess.run')
    @patch('management.management.commands.update_tls.Path')
    @patch('management.management.commands.update_tls.NGINX_KEY_PATH')
    @patch('management.management.commands.update_tls.NGINX_CERT_PATH')
    @patch('management.management.commands.update_tls.NGINX_CERT_CHAIN_PATH')
    @patch('management.management.commands.update_tls.ActiveTrustpointTlsServerCredentialModel')
    def test_update_tls_success(
        self,
        mock_active_tls: MagicMock,
        mock_chain_path: MagicMock,
        mock_cert_path: MagicMock,
        mock_key_path: MagicMock,
        mock_path_class: MagicMock,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test update_tls command successful execution."""
        # Setup credential model
        mock_credential = Mock()
        mock_credential.get_private_key_serializer().as_pkcs8_pem.return_value = b'test_key'
        mock_credential.get_certificate_serializer().as_pem.return_value = b'test_cert'
        mock_credential.get_certificate_chain_serializer().as_pem.return_value = b'test_chain'
        mock_credential.get_certificate().fingerprint.return_value = b'\x00\x01\x02\x03' * 8  # 32 bytes

        mock_active = Mock()
        mock_active.credential = mock_credential
        mock_active_tls.objects.get.return_value = mock_active

        # Mock Path for script
        mock_script_path = Mock()
        mock_script_path.exists.return_value = True
        mock_script_path.is_file.return_value = True
        mock_path_class.return_value.resolve.return_value = mock_script_path

        # Mock subprocess
        mock_result = Mock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        out = StringIO()
        call_command('update_tls', stdout=out)

        # Verify file writes
        mock_key_path.write_text.assert_called_once()
        mock_cert_path.write_text.assert_called_once()

    @patch('management.management.commands.update_tls.ActiveTrustpointTlsServerCredentialModel')
    def test_update_tls_no_credential(self, mock_active_tls: MagicMock) -> None:
        """Test update_tls command when no active credential exists."""
        from django.core.exceptions import ObjectDoesNotExist

        mock_active_tls.objects.get.side_effect = ObjectDoesNotExist

        with self.assertRaises(CommandError) as cm:
            call_command('update_tls')

        self.assertIn('not found', str(cm.exception).lower())

    @patch('management.management.commands.update_tls.subprocess.run')
    @patch('management.management.commands.update_tls.Path')
    @patch('management.management.commands.update_tls.NGINX_KEY_PATH')
    @patch('management.management.commands.update_tls.NGINX_CERT_PATH')
    @patch('management.management.commands.update_tls.NGINX_CERT_CHAIN_PATH')
    @patch('management.management.commands.update_tls.ActiveTrustpointTlsServerCredentialModel')
    def test_update_tls_script_failure(
        self,
        mock_active_tls: MagicMock,
        mock_chain_path: MagicMock,
        mock_cert_path: MagicMock,
        mock_key_path: MagicMock,
        mock_path_class: MagicMock,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test update_tls command when subprocess script fails."""
        # Setup credential model
        mock_credential = Mock()
        mock_credential.get_private_key_serializer().as_pkcs8_pem.return_value = b'test_key'
        mock_credential.get_certificate_serializer().as_pem.return_value = b'test_cert'
        mock_credential.get_certificate_chain_serializer().as_pem.return_value = b'test_chain'
        mock_credential.get_certificate().fingerprint.return_value = b'\x00\x01\x02\x03' * 8  # 32 bytes

        mock_active = Mock()
        mock_active.credential = mock_credential
        mock_active_tls.objects.get.return_value = mock_active

        # Mock Path for script
        mock_script_path = Mock()
        mock_script_path.exists.return_value = True
        mock_script_path.is_file.return_value = True
        mock_path_class.return_value.resolve.return_value = mock_script_path

        # Mock subprocess failure
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = 'error output'
        mock_result.stderr = 'error details'
        mock_subprocess.return_value = mock_result

        out = StringIO()
        call_command('update_tls', stdout=out)

        # Command should complete but log error
        output = out.getvalue()
        self.assertIn('successful', output.lower())


class ManagePyOverrideTest(TestCase):
    """Test suite for managepy_override module."""

    @patch('management.management.managepy_override.execute_from_command_line')
    def test_override_makemigrations_function(self, mock_execute: MagicMock) -> None:
        """Test override_makemigrations function exists and is callable."""
        from management.management.managepy_override import override_makemigrations

        # Verify function exists and is callable
        self.assertTrue(callable(override_makemigrations))

        # Call it with required arguments
        override_makemigrations(['manage.py', 'makemigrations'])

        # Verify execute_from_command_line was called
        mock_execute.assert_called_once()

    def test_managepy_override_imports(self) -> None:
        """Test that managepy_override module can be imported."""
        try:
            from management.management import managepy_override
            from management.management.managepy_override import override_makemigrations

            self.assertIsNotNone(managepy_override)
            self.assertIsNotNone(override_makemigrations)
        except ImportError as e:
            self.fail(f'Failed to import managepy_override: {e}')
