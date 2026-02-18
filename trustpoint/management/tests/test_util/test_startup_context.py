"""Test suite for StartupContextBuilder."""

from unittest.mock import Mock, patch

from django.test import TestCase
from management.models import KeyStorageConfig
from management.util.startup_context import StartupContextBuilder
from packaging.version import Version
from setup_wizard import SetupWizardState


class StartupContextBuilderTest(TestCase):
    """Test suite for StartupContextBuilder class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_output = Mock()
        self.current_version = Version('1.0.0')
        self.builder = StartupContextBuilder(self.mock_output, self.current_version)

    def test_init(self):
        """Test initialization sets default values."""
        self.assertEqual(self.builder.output, self.mock_output)
        self.assertEqual(self.builder.current_version, self.current_version)
        self.assertIsNone(self.builder.db_version)
        self.assertIsNone(self.builder.wizard_state)
        self.assertFalse(self.builder.wizard_completed)
        self.assertIsNone(self.builder.storage_type)
        self.assertFalse(self.builder.is_hsm)
        self.assertFalse(self.builder.dek_accessible)
        self.assertFalse(self.builder.has_kek)
        self.assertFalse(self.builder.has_backup_encrypted_dek)

    def test_with_db_version(self):
        """Test setting database version."""
        db_version = Version('0.9.0')

        result = self.builder.with_db_version(db_version)

        self.assertEqual(self.builder.db_version, db_version)
        self.assertEqual(result, self.builder)  # Check method chaining

    @patch('management.util.startup_context.SetupWizardState.get_current_state')
    def test_collect_wizard_state_completed(self, mock_get_state):
        """Test collecting wizard state when completed."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED

        result = self.builder.collect_wizard_state()

        self.assertEqual(self.builder.wizard_state, SetupWizardState.WIZARD_COMPLETED)
        self.assertTrue(self.builder.wizard_completed)
        self.assertEqual(result, self.builder)
        self.mock_output.write.assert_called()

    @patch('management.util.startup_context.SetupWizardState.get_current_state')
    def test_collect_wizard_state_incomplete(self, mock_get_state):
        """Test collecting wizard state when incomplete."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        result = self.builder.collect_wizard_state()

        self.assertEqual(self.builder.wizard_state, SetupWizardState.WIZARD_SETUP_MODE)
        self.assertFalse(self.builder.wizard_completed)
        self.assertEqual(result, self.builder)

    @patch('management.util.startup_context.SetupWizardState.get_current_state')
    def test_collect_wizard_state_runtime_error(self, mock_get_state):
        """Test collecting wizard state when RuntimeError occurs."""
        mock_get_state.side_effect = RuntimeError('Test error')

        result = self.builder.collect_wizard_state()

        self.assertIsNone(self.builder.wizard_state)
        self.assertFalse(self.builder.wizard_completed)
        self.assertEqual(result, self.builder)

    def test_collect_storage_config_no_config(self):
        """Test collecting storage config when none exists."""
        # No KeyStorageConfig in database

        result = self.builder.collect_storage_config()

        self.assertIsNone(self.builder.storage_type)
        self.assertFalse(self.builder.is_hsm)
        self.assertEqual(result, self.builder)

    def test_collect_storage_config_software(self):
        """Test collecting storage config for software storage."""
        KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTWARE)

        result = self.builder.collect_storage_config()

        self.assertEqual(self.builder.storage_type, KeyStorageConfig.StorageType.SOFTWARE)
        self.assertFalse(self.builder.is_hsm)
        self.assertEqual(result, self.builder)

    def test_collect_storage_config_softhsm(self):
        """Test collecting storage config for SoftHSM."""
        KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTHSM)

        result = self.builder.collect_storage_config()

        self.assertEqual(self.builder.storage_type, KeyStorageConfig.StorageType.SOFTHSM)
        self.assertTrue(self.builder.is_hsm)
        self.assertEqual(result, self.builder)

    def test_collect_storage_config_physical_hsm(self):
        """Test collecting storage config for physical HSM."""
        KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.PHYSICAL_HSM)

        result = self.builder.collect_storage_config()

        self.assertEqual(self.builder.storage_type, KeyStorageConfig.StorageType.PHYSICAL_HSM)
        self.assertTrue(self.builder.is_hsm)
        self.assertEqual(result, self.builder)

    @patch.object(KeyStorageConfig.objects, 'first')
    def test_collect_storage_config_exception(self, mock_first):
        """Test collecting storage config when exception occurs."""
        mock_first.side_effect = Exception('Database error')

        result = self.builder.collect_storage_config()

        self.assertIsNone(self.builder.storage_type)
        self.assertFalse(self.builder.is_hsm)
        self.assertEqual(result, self.builder)

    def test_collect_dek_state_not_hsm(self):
        """Test collecting DEK state for non-HSM configuration."""
        self.builder.is_hsm = False

        result = self.builder.collect_dek_state()

        self.assertTrue(self.builder.dek_accessible)
        self.assertEqual(result, self.builder)

    def test_collect_dek_state_no_config(self):
        """Test collecting DEK state when no HSM config exists."""
        self.builder.is_hsm = True

        result = self.builder.collect_dek_state()

        self.assertFalse(self.builder.dek_accessible)
        self.assertEqual(result, self.builder)

    @patch('management.models.PKCS11Token.get_dek_cache')
    def test_collect_dek_state_cached(self, mock_get_cache):
        """Test collecting DEK state when DEK is cached."""
        self.builder.is_hsm = True

        # Create HSM config
        config = KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTHSM)

        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1, encrypted_dek=b'encrypted_dek_data')
        config.hsm_config = token
        config.save()

        mock_get_cache.return_value = b'cached_dek'

        with patch.object(self.builder, '_check_kek_exists_on_hsm', return_value=True):
            result = self.builder.collect_dek_state()

        self.assertTrue(self.builder.dek_accessible)
        self.assertEqual(result, self.builder)

    def test_collect_dek_state_no_dek(self):
        """Test collecting DEK state when no DEK exists."""
        self.builder.is_hsm = True

        # Create HSM config without DEK
        config = KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTHSM)

        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1)
        config.hsm_config = token
        config.save()

        result = self.builder.collect_dek_state()

        self.assertFalse(self.builder.dek_accessible)
        self.assertEqual(result, self.builder)

    @patch('management.models.PKCS11Token.get_dek')
    @patch('management.models.PKCS11Token.get_dek_cache')
    def test_collect_dek_state_unwrap_success(self, mock_get_cache, mock_get_dek):
        """Test collecting DEK state when DEK unwrap succeeds."""
        self.builder.is_hsm = True

        # Create HSM config
        config = KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTHSM)

        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1, encrypted_dek=b'encrypted_dek_data')
        config.hsm_config = token
        config.save()

        mock_get_cache.return_value = None
        mock_get_dek.return_value = b'unwrapped_dek'

        with patch.object(self.builder, '_check_kek_exists_on_hsm', return_value=True):
            result = self.builder.collect_dek_state()

        self.assertTrue(self.builder.dek_accessible)
        self.assertEqual(result, self.builder)

    @patch('management.models.PKCS11Token.get_dek')
    @patch('management.models.PKCS11Token.get_dek_cache')
    def test_collect_dek_state_unwrap_failure(self, mock_get_cache, mock_get_dek):
        """Test collecting DEK state when DEK unwrap fails."""
        self.builder.is_hsm = True

        # Create HSM config
        config = KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTHSM)

        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1, encrypted_dek=b'encrypted_dek_data')
        config.hsm_config = token
        config.save()

        mock_get_cache.return_value = None
        mock_get_dek.side_effect = Exception('Unwrap failed')

        with patch.object(self.builder, '_check_kek_exists_on_hsm', return_value=True):
            result = self.builder.collect_dek_state()

        self.assertFalse(self.builder.dek_accessible)
        self.assertEqual(result, self.builder)

    @patch('management.models.PKCS11Token.get_dek_cache')
    def test_collect_dek_state_no_kek(self, mock_get_cache):
        """Test collecting DEK state when KEK is not available."""
        self.builder.is_hsm = True

        # Create HSM config
        config = KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTHSM)

        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1, encrypted_dek=b'encrypted_dek_data')
        config.hsm_config = token
        config.save()

        mock_get_cache.return_value = None

        with patch.object(self.builder, '_check_kek_exists_on_hsm', return_value=False):
            result = self.builder.collect_dek_state()

        self.assertFalse(self.builder.dek_accessible)
        self.assertFalse(self.builder.has_kek)
        self.assertEqual(result, self.builder)

    def test_check_kek_exists_on_hsm_success(self):
        """Test checking KEK exists on HSM when it does."""
        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1)

        with patch.object(token, 'load_kek', return_value=True):
            result = self.builder._check_kek_exists_on_hsm(token)

        self.assertTrue(result)

    def test_check_kek_exists_on_hsm_not_found(self):
        """Test checking KEK exists on HSM when it doesn't."""
        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1)

        with patch.object(token, 'load_kek', return_value=False):
            result = self.builder._check_kek_exists_on_hsm(token)

        self.assertFalse(result)

    def test_check_kek_exists_on_hsm_exception(self):
        """Test checking KEK exists on HSM when exception occurs."""
        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(label='test_token', slot=1)

        with patch.object(token, 'load_kek', side_effect=Exception('HSM error')):
            result = self.builder._check_kek_exists_on_hsm(token)

        self.assertFalse(result)

    def test_build(self):
        """Test building StartupContext."""
        self.builder.db_version = Version('1.0.0')
        self.builder.wizard_completed = True
        self.builder.wizard_state = SetupWizardState.WIZARD_COMPLETED
        self.builder.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        self.builder.is_hsm = False

        context = self.builder.build()

        self.assertTrue(context.db_initialized)
        self.assertEqual(context.db_version, Version('1.0.0'))
        self.assertEqual(context.current_version, self.current_version)
        self.assertIsNone(context.dek_cache_state)

    def test_build_with_hsm(self):
        """Test building StartupContext with HSM configuration."""
        self.builder.db_version = Version('1.0.0')
        self.builder.wizard_completed = True
        self.builder.wizard_state = SetupWizardState.WIZARD_COMPLETED
        self.builder.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        self.builder.is_hsm = True
        self.builder.dek_accessible = True
        self.builder.has_kek = True
        self.builder.has_backup_encrypted_dek = True

        context = self.builder.build()

        self.assertTrue(context.db_initialized)
        self.assertIsNotNone(context.dek_cache_state)
        self.assertTrue(context.has_kek)
        self.assertTrue(context.has_backup_encrypted_dek)

    def test_build_for_db_init(self):
        """Test building minimal StartupContext for database initialization."""
        context = self.builder.build_for_db_init()

        self.assertFalse(context.db_initialized)
        self.assertIsNone(context.db_version)
        self.assertEqual(context.current_version, self.current_version)
        self.assertIsNone(context.storage_type)
        self.assertIsNone(context.dek_cache_state)
        self.assertEqual(context.output, self.mock_output)

    def test_method_chaining(self):
        """Test method chaining works correctly."""
        db_version = Version('1.0.0')

        result = self.builder.with_db_version(db_version).collect_storage_config()

        self.assertEqual(result, self.builder)
        self.assertEqual(self.builder.db_version, db_version)

    @patch('management.models.PKCS11Token.get_dek_cache')
    def test_collect_dek_state_with_backup_encrypted_dek(self, mock_get_cache):
        """Test collecting DEK state when backup encrypted DEK exists."""
        self.builder.is_hsm = True

        # Create HSM config with backup encrypted DEK
        config = KeyStorageConfig.objects.create(storage_type=KeyStorageConfig.StorageType.SOFTHSM)

        from management.models import PKCS11Token

        token = PKCS11Token.objects.create(
            label='test_token',
            slot=1,
            encrypted_dek=b'encrypted_dek_data',
            bek_encrypted_dek=b'backup_encrypted_dek_data',
        )
        config.hsm_config = token
        config.save()

        mock_get_cache.return_value = b'cached_dek'

        with patch.object(self.builder, '_check_kek_exists_on_hsm', return_value=True):
            result = self.builder.collect_dek_state()

        self.assertTrue(self.builder.has_backup_encrypted_dek)
        self.assertTrue(self.builder.dek_accessible)
        self.assertEqual(result, self.builder)
