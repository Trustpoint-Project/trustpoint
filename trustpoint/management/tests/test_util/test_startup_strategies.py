"""Test suite for startup strategies."""
from unittest.mock import Mock, patch

from django.test import TestCase
from management.models import KeyStorageConfig
from management.util.startup_strategies import (
    DekCacheState,
    StartupContext,
    WizardState,
    DatabaseNotInitializedStrategy,
    DatabaseInitializedNoVersionStrategy,
    VersionMatchStrategy,
    VersionUpgradeStrategy,
    RestoreSoftwareWizardCompletedStrategy,
    RestoreSoftwareWizardIncompleteStrategy,
    StartupStrategySelector,
    RestoreSoftHsmWizardCompletedDekCachedStrategy,
    RestoreSoftHsmNewKekWizardCompletedStrategy,
)
from packaging.version import Version
from setup_wizard import SetupWizardState


class WizardStateTest(TestCase):
    """Test suite for WizardState enum."""

    def test_completed_value(self):
        """Test COMPLETED enum value."""
        self.assertEqual(WizardState.COMPLETED.value, 'COMPLETED')

    def test_incomplete_value(self):
        """Test INCOMPLETE enum value."""
        self.assertEqual(WizardState.INCOMPLETE.value, 'INCOMPLETE')


class DekCacheStateTest(TestCase):
    """Test suite for DekCacheState enum."""

    def test_cached_value(self):
        """Test CACHED enum value."""
        self.assertEqual(DekCacheState.CACHED.value, 'CACHED')

    def test_not_cached_value(self):
        """Test NOT_CACHED enum value."""
        self.assertEqual(DekCacheState.NOT_CACHED.value, 'NOT_CACHED')


class StartupContextTest(TestCase):
    """Test suite for StartupContext dataclass."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_output = Mock()
        self.current_version = Version('1.0.0')
        self.db_version = Version('1.0.0')

    def test_initialization(self):
        """Test StartupContext initialization."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=SetupWizardState.WIZARD_COMPLETED,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        self.assertTrue(context.db_initialized)
        self.assertEqual(context.db_version, self.db_version)
        self.assertEqual(context.current_version, self.current_version)
        self.assertEqual(context.wizard_state_enum, WizardState.COMPLETED)
        self.assertFalse(context.has_kek)
        self.assertFalse(context.has_backup_encrypted_dek)

    def test_is_wizard_completed_true(self):
        """Test is_wizard_completed property when completed."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=None,
            dek_cache_state=None,
            output=self.mock_output,
        )

        self.assertTrue(context.is_wizard_completed)

    def test_is_wizard_completed_false(self):
        """Test is_wizard_completed property when incomplete."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.INCOMPLETE,
            wizard_state_raw=None,
            storage_type=None,
            dek_cache_state=None,
            output=self.mock_output,
        )

        self.assertFalse(context.is_wizard_completed)

    def test_is_software_storage(self):
        """Test is_software_storage property."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        self.assertTrue(context.is_software_storage)
        self.assertFalse(context.is_softhsm_storage)
        self.assertFalse(context.is_physical_hsm_storage)
        self.assertFalse(context.is_hsm_storage)

    def test_is_softhsm_storage(self):
        """Test is_softhsm_storage property."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.CACHED,
            output=self.mock_output,
        )

        self.assertFalse(context.is_software_storage)
        self.assertTrue(context.is_softhsm_storage)
        self.assertFalse(context.is_physical_hsm_storage)
        self.assertTrue(context.is_hsm_storage)

    def test_is_physical_hsm_storage(self):
        """Test is_physical_hsm_storage property."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.PHYSICAL_HSM,
            dek_cache_state=DekCacheState.CACHED,
            output=self.mock_output,
        )

        self.assertFalse(context.is_software_storage)
        self.assertFalse(context.is_softhsm_storage)
        self.assertTrue(context.is_physical_hsm_storage)
        self.assertTrue(context.is_hsm_storage)

    def test_is_dek_cached_true(self):
        """Test is_dek_cached property when cached."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.CACHED,
            output=self.mock_output,
        )

        self.assertTrue(context.is_dek_cached)

    def test_is_dek_cached_false(self):
        """Test is_dek_cached property when not cached."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.NOT_CACHED,
            output=self.mock_output,
        )

        self.assertFalse(context.is_dek_cached)

    def test_is_dek_cached_raises_for_software_storage(self):
        """Test is_dek_cached raises ValueError for software storage."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        with self.assertRaises(ValueError) as cm:
            _ = context.is_dek_cached

        self.assertIn('only applicable for HSM storage', str(cm.exception))

    def test_is_new_kek_scenario_true(self):
        """Test is_new_kek_scenario when conditions are met."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.NOT_CACHED,
            output=self.mock_output,
            has_kek=False,
            has_backup_encrypted_dek=True,
        )

        self.assertTrue(context.is_new_kek_scenario)

    def test_is_new_kek_scenario_false_software_storage(self):
        """Test is_new_kek_scenario is False for software storage."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
            has_kek=False,
            has_backup_encrypted_dek=True,
        )

        self.assertFalse(context.is_new_kek_scenario)

    def test_is_new_kek_scenario_false_dek_cached(self):
        """Test is_new_kek_scenario is False when DEK is cached."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.CACHED,
            output=self.mock_output,
            has_kek=False,
            has_backup_encrypted_dek=True,
        )

        self.assertFalse(context.is_new_kek_scenario)

    def test_is_new_kek_scenario_false_has_kek(self):
        """Test is_new_kek_scenario is False when KEK exists."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.NOT_CACHED,
            output=self.mock_output,
            has_kek=True,
            has_backup_encrypted_dek=True,
        )

        self.assertFalse(context.is_new_kek_scenario)

    def test_is_new_kek_scenario_false_no_backup(self):
        """Test is_new_kek_scenario is False without backup encrypted DEK."""
        context = StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.NOT_CACHED,
            output=self.mock_output,
            has_kek=False,
            has_backup_encrypted_dek=False,
        )

        self.assertFalse(context.is_new_kek_scenario)


class DatabaseNotInitializedStrategyTest(TestCase):
    """Test suite for DatabaseNotInitializedStrategy."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_output = Mock()
        self.mock_init_strategy = Mock()
        self.strategy = DatabaseNotInitializedStrategy(init_strategy=self.mock_init_strategy)
        self.context = StartupContext(
            db_initialized=False,
            db_version=None,
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.INCOMPLETE,
            wizard_state_raw=None,
            storage_type=None,
            dek_cache_state=None,
            output=self.mock_output,
        )

    def test_get_description(self):
        """Test get_description returns correct string."""
        description = self.strategy.get_description()
        self.assertIn('not initialized', description.lower())

    def test_execute_calls_init_strategy(self):
        """Test execute calls initialization strategy with TLS."""
        self.strategy.execute(self.context)

        self.mock_init_strategy.initialize.assert_called_once_with(self.context, with_tls=True)
        self.mock_output.write.assert_called()


class DatabaseInitializedNoVersionStrategyTest(TestCase):
    """Test suite for DatabaseInitializedNoVersionStrategy."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_output = Mock()
        self.mock_init_strategy = Mock()
        self.strategy = DatabaseInitializedNoVersionStrategy(init_strategy=self.mock_init_strategy)
        self.context = StartupContext(
            db_initialized=True,
            db_version=None,
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.INCOMPLETE,
            wizard_state_raw=None,
            storage_type=None,
            dek_cache_state=None,
            output=self.mock_output,
        )

    def test_get_description(self):
        """Test get_description returns correct string."""
        description = self.strategy.get_description()
        self.assertIn('no version', description.lower())

    def test_execute_calls_init_strategy(self):
        """Test execute calls initialization strategy with TLS."""
        self.strategy.execute(self.context)

        self.mock_init_strategy.initialize.assert_called_once_with(self.context, with_tls=True)
        self.mock_output.write.assert_called()


class VersionMatchStrategyTest(TestCase):
    """Test suite for VersionMatchStrategy."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_output = Mock()
        self.mock_restore_strategy = Mock()
        self.mock_init_strategy = Mock()
        self.strategy = VersionMatchStrategy(
            restore_strategy=self.mock_restore_strategy, init_strategy=self.mock_init_strategy
        )
        self.context = StartupContext(
            db_initialized=True,
            db_version=Version('1.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=SetupWizardState.WIZARD_COMPLETED,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

    def test_get_description(self):
        """Test get_description returns correct string."""
        description = self.strategy.get_description()
        self.assertIn('match', description.lower())

    def test_execute_initializes_and_restores(self):
        """Test execute calls init and restore strategies."""
        self.strategy.execute(self.context)

        self.mock_init_strategy.initialize.assert_called_once_with(self.context, with_tls=False)
        self.mock_restore_strategy.execute.assert_called_once_with(self.context)
        self.mock_output.write.assert_called()


class VersionUpgradeStrategyTest(TestCase):
    """Test suite for VersionUpgradeStrategy."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_output = Mock()
        self.mock_restore_strategy = Mock()
        self.mock_init_strategy = Mock()
        self.mock_app_version = Mock()
        self.mock_app_version.version = '0.9.0'
        self.strategy = VersionUpgradeStrategy(
            restore_strategy=self.mock_restore_strategy,
            app_version=self.mock_app_version,
            init_strategy=self.mock_init_strategy,
        )
        self.context = StartupContext(
            db_initialized=True,
            db_version=Version('0.9.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=SetupWizardState.WIZARD_COMPLETED,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

    def test_get_description(self):
        """Test get_description returns correct string."""
        description = self.strategy.get_description()
        self.assertIn('upgrade', description.lower())

    def test_execute_upgrades_version(self):
        """Test execute performs upgrade and updates version."""
        self.strategy.execute(self.context)

        self.mock_init_strategy.initialize.assert_called_once_with(self.context, with_tls=False)
        self.mock_restore_strategy.execute.assert_called_once_with(self.context)
        self.assertEqual(self.mock_app_version.version, '1.0.0')
        self.mock_app_version.save.assert_called_once()
        self.mock_output.write.assert_called()


class StartupStrategySelectorTest(TestCase):
    """Test suite for StartupStrategySelector."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_output = Mock()

    def test_select_startup_strategy_db_not_initialized(self):
        """Test select_startup_strategy when DB not initialized."""
        strategy = StartupStrategySelector.select_startup_strategy(
            db_initialized=False,
            has_version=False,
        )

        self.assertIsInstance(strategy, DatabaseNotInitializedStrategy)

    def test_select_startup_strategy_db_initialized_no_version(self):
        """Test select_startup_strategy when DB has no version."""
        strategy = StartupStrategySelector.select_startup_strategy(
            db_initialized=True,
            has_version=False,
        )

        self.assertIsInstance(strategy, DatabaseInitializedNoVersionStrategy)

    def test_select_startup_strategy_requires_context_and_version(self):
        """Test select_startup_strategy raises error without context/version."""
        with self.assertRaises(ValueError) as cm:
            StartupStrategySelector.select_startup_strategy(
                db_initialized=True,
                has_version=True,
            )

        self.assertIn('required', str(cm.exception).lower())

    def test_select_restore_strategy_software_wizard_completed(self):
        """Test select_restore_strategy for software storage with completed wizard."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('1.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        strategy = StartupStrategySelector.select_restore_strategy(context)
        self.assertIsInstance(strategy, RestoreSoftwareWizardCompletedStrategy)

    def test_select_restore_strategy_software_wizard_incomplete(self):
        """Test select_restore_strategy for software storage with incomplete wizard."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('1.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.INCOMPLETE,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        strategy = StartupStrategySelector.select_restore_strategy(context)
        self.assertIsInstance(strategy, RestoreSoftwareWizardIncompleteStrategy)

    def test_select_restore_strategy_softhsm_wizard_completed_dek_cached(self):
        """Test select_restore_strategy for SoftHSM with completed wizard and cached DEK."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('1.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.CACHED,
            output=self.mock_output,
        )

        strategy = StartupStrategySelector.select_restore_strategy(context)
        self.assertIsInstance(strategy, RestoreSoftHsmWizardCompletedDekCachedStrategy)

    def test_select_restore_strategy_softhsm_new_kek(self):
        """Test select_restore_strategy for SoftHSM with new KEK (old KEK lost)."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('1.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTHSM,
            dek_cache_state=DekCacheState.NOT_CACHED,
            output=self.mock_output,
            has_kek=False,
            has_backup_encrypted_dek=True,
        )

        strategy = StartupStrategySelector.select_restore_strategy(context)
        self.assertIsInstance(strategy, RestoreSoftHsmNewKekWizardCompletedStrategy)

    def test_select_restore_strategy_unsupported_storage_raises_error(self):
        """Test select_restore_strategy raises error for unsupported storage."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('1.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=None,
            dek_cache_state=None,
            output=self.mock_output,
        )

        with self.assertRaises(ValueError) as cm:
            StartupStrategySelector.select_restore_strategy(context)

        self.assertIn('unexpected', str(cm.exception).lower())

    @patch('management.util.startup_strategies.AppVersion')
    def test_select_version_strategy_version_match(self, mock_app_version):
        """Test select_version_strategy when versions match."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('1.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        strategy = StartupStrategySelector.select_version_strategy(context, mock_app_version)
        self.assertIsInstance(strategy, VersionMatchStrategy)

    @patch('management.util.startup_strategies.AppVersion')
    def test_select_version_strategy_version_upgrade(self, mock_app_version):
        """Test select_version_strategy when upgrade needed."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('0.9.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        strategy = StartupStrategySelector.select_version_strategy(context, mock_app_version)
        self.assertIsInstance(strategy, VersionUpgradeStrategy)

    @patch('management.util.startup_strategies.AppVersion')
    def test_select_version_strategy_version_downgrade_raises_error(self, mock_app_version):
        """Test select_version_strategy raises error for downgrade."""
        context = StartupContext(
            db_initialized=True,
            db_version=Version('2.0.0'),
            current_version=Version('1.0.0'),
            wizard_state_enum=WizardState.COMPLETED,
            wizard_state_raw=None,
            storage_type=KeyStorageConfig.StorageType.SOFTWARE,
            dek_cache_state=None,
            output=self.mock_output,
        )

        with self.assertRaises(RuntimeError) as cm:
            StartupStrategySelector.select_version_strategy(context, mock_app_version)

        self.assertIn('not supported', str(cm.exception).lower())
