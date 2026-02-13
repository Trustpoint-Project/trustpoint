"""Context builder for startup strategies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from management.models import KeyStorageConfig
from setup_wizard import SetupWizardState

if TYPE_CHECKING:
    from packaging.version import Version

    from management.models import PKCS11Token
    from management.util.startup_strategies import OutputWriter, StartupContext


class StartupContextBuilder:
    """Builder for creating StartupContext objects."""

    def __init__(self, output: OutputWriter, current_version: Version) -> None:
        """Initialize the context builder.

        Args:
            output: The output writer for logging.
            current_version: The current application version.
        """
        self.output = output
        self.current_version = current_version
        self.db_version: Version | None = None
        self.wizard_state: SetupWizardState | None = None
        self.wizard_completed: bool = False
        self.storage_type: KeyStorageConfig.StorageType | None = None
        self.is_hsm: bool = False
        self.dek_accessible: bool = False
        self.has_kek: bool = False
        self.has_backup_encrypted_dek: bool = False

    def with_db_version(self, db_version: Version) -> StartupContextBuilder:
        """Set the database version.

        Args:
            db_version: The version from the database.

        Returns:
            Self for method chaining.
        """
        self.db_version = db_version
        return self

    def collect_wizard_state(self) -> StartupContextBuilder:
        """Collect wizard state information.

        Returns:
            Self for method chaining.
        """
        self.output.write('Checking wizard completion state...')
        try:
            self.wizard_state = SetupWizardState.get_current_state()
            self.output.write(f'Current wizard state: {self.wizard_state}')
            self.wizard_completed = self.wizard_state == SetupWizardState.WIZARD_COMPLETED
            self.output.write(f'Wizard is completed: {self.wizard_completed}')
        except RuntimeError as e:
            self.output.write(f'Could not determine wizard state: {e}')
            self.wizard_completed = False
        return self

    def collect_storage_config(self) -> StartupContextBuilder:
        """Collect storage configuration information.

        Returns:
            Self for method chaining.
        """
        self.output.write('Checking storage type configuration...')
        try:
            config = KeyStorageConfig.objects.first()
            if not config:
                self.output.write('No KeyStorageConfig found')
                self.storage_type = None
                self.is_hsm = False
                return self

            self.storage_type = KeyStorageConfig.StorageType(config.storage_type)
            self.is_hsm = self.storage_type in (
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM,
            )
            self.output.write(f'Storage type: {self.storage_type}')
            self.output.write(f'Storage requires backup recovery: {self.is_hsm}')
        except Exception as e:  # noqa: BLE001
            self.output.write(f'Error checking storage type: {e}')
            self.storage_type = None
            self.is_hsm = False
        return self

    def collect_dek_state(self) -> StartupContextBuilder:
        """Collect DEK accessibility information.

        Returns:
            Self for method chaining.
        """
        if not self.is_hsm:
            # DEK state only relevant for HSM configurations
            self.dek_accessible = True
            return self

        self.output.write('Checking DEK accessibility...')
        try:
            config = KeyStorageConfig.objects.first()
            if not config or not config.hsm_config:
                self.output.write('No HSM configuration found')
                self.dek_accessible = False
                return self

            token = config.hsm_config
            self.output.write(f'Token label: {token.label}')
            self.output.write(f'encrypted_dek present: {bool(token.encrypted_dek)}')
            self.output.write(f'bek_encrypted_dek present: {bool(token.bek_encrypted_dek)}')

            self.has_backup_encrypted_dek = bool(token.bek_encrypted_dek)

            self.has_kek = self._check_kek_exists_on_hsm(token)

            if not token.encrypted_dek and not token.bek_encrypted_dek:
                self.output.write('>>> No DEK found - backup password required')
                self.dek_accessible = False
                return self

            cached_dek = token.get_dek_cache()
            if cached_dek:
                self.output.write('>>> DEK available in cache - system operational')
                self.dek_accessible = True
                return self

            if not self.has_kek:
                self.output.write('>>> KEK not available on HSM - cannot unwrap DEK')
                self.dek_accessible = False
                return self

            self.output.write('Attempting to unwrap DEK to verify KEK accessibility...')
            try:
                dek = token.get_dek()
                if dek:
                    self.output.write('>>> DEK successfully unwrapped - KEK is accessible')
                    self.dek_accessible = True
                else:
                    self.output.write('>>> DEK unwrap returned None')
                    self.dek_accessible = False
            except Exception as unwrap_error:  # noqa: BLE001
                self.output.write(f'>>> DEK unwrap failed: {unwrap_error}')
                self.output.write('>>> KEK unavailable - backup password required')
                self.dek_accessible = False

        except Exception as e:  # noqa: BLE001
            self.output.write(f'Error checking DEK status: {e}')
            self.dek_accessible = False
        return self

    def _check_kek_exists_on_hsm(self, token: PKCS11Token) -> bool:
        """Check if the KEK actually exists on the physical HSM.

        This method verifies that the KEK is not just referenced in the database,
        but actually exists on the physical HSM by attempting to load it.

        Args:
            token: The PKCS11Token to check.

        Returns:
            bool: True if KEK exists on HSM, False otherwise.
        """
        try:
            kek_exists = token.load_kek()

            if kek_exists:
                self.output.write('>>> KEK verified to exist on HSM')
            else:
                self.output.write('>>> KEK does not exist on HSM')

        except Exception as e:  # noqa: BLE001
            self.output.write(f'>>> Error checking for KEK on HSM: {e}')
            return False
        else:
            return kek_exists

    def build(self) -> StartupContext:
        """Build the StartupContext object.

        Returns:
            The constructed StartupContext.
        """
        from management.util.startup_strategies import (  # noqa: PLC0415
            DekCacheState,
            StartupContext,
            WizardState,
        )

        # Map wizard completed bool to wizard state enum
        wizard_state_enum = WizardState.COMPLETED if self.wizard_completed else WizardState.INCOMPLETE

        # Map DEK accessibility to cache state (only for HSM)
        dek_cache = (DekCacheState.CACHED if self.dek_accessible else DekCacheState.NOT_CACHED) if self.is_hsm else None

        return StartupContext(
            db_initialized=True,
            db_version=self.db_version,
            current_version=self.current_version,
            wizard_state_enum=wizard_state_enum,
            wizard_state_raw=self.wizard_state,
            storage_type=self.storage_type,
            dek_cache_state=dek_cache,
            has_kek=self.has_kek,
            has_backup_encrypted_dek=self.has_backup_encrypted_dek,
            output=self.output,
        )

    def build_for_db_init(self) -> StartupContext:
        """Build a minimal StartupContext for database initialization scenarios.

        This is used when the database is not initialized or has no version,
        so we can't query for wizard state, storage config, or DEK state.

        Returns:
            A minimal StartupContext with db_initialized=False.
        """
        # Import here to avoid circular imports
        from management.util.startup_strategies import (  # noqa: PLC0415
            StartupContext,
            WizardState,
        )

        return StartupContext(
            db_initialized=False,
            db_version=None,
            current_version=self.current_version,
            wizard_state_enum=WizardState.INCOMPLETE,
            wizard_state_raw=None,
            storage_type=None,  # Safe default for uninitialized DB
            dek_cache_state=None,
            output=self.output,
        )
