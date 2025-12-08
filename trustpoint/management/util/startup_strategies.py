"""Startup strategies for Trustpoint initialization and restoration."""

import io
import ipaddress
import socket
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from django.core.exceptions import ObjectDoesNotExist
from django.core.management import call_command
from django.utils.translation import gettext as _
from packaging.version import Version
from pki.models import PKCS11Key
from pki.models.credential import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard import SetupWizardState
from setup_wizard.state_dir_paths import SCRIPT_WIZARD_AUTO_RESTORE_SET
from setup_wizard.tls_credential import TlsServerCredentialGenerator
from setup_wizard.views import execute_shell_script

from management.nginx_paths import NGINX_CERT_CHAIN_PATH, NGINX_CERT_PATH, NGINX_KEY_PATH
from management.models import AppVersion, KeyStorageConfig, PKCS11Token

# Constants
DEK_EXPECTED_LENGTH = 32
DEFAULT_TOKEN_LABEL = 'Trustpoint-SoftHSM'  # noqa: S105


class OutputWriter(Protocol):
    """Protocol for output writing (stdout/stderr)."""

    def write(self, msg: str) -> None:
        """Write a message to output."""
        ...

    def success(self, msg: str) -> str:
        """Format a success message."""
        ...

    def error(self, msg: str) -> str:
        """Format an error message."""
        ...

    def warning(self, msg: str) -> str:
        """Format a warning message."""
        ...


class WizardState(Enum):
    """Enumeration of wizard completion states."""

    COMPLETED = 'COMPLETED'
    INCOMPLETE = 'INCOMPLETE'


class DekCacheState(Enum):
    """Enumeration of DEK cache states (for HSM storage only)."""

    CACHED = 'CACHED'  # DEK is accessible/cached
    NOT_CACHED = 'NOT_CACHED'  # DEK is not accessible/not cached


class StartupScenario(Enum):
    """Enumeration of possible startup scenarios."""

    # Database initialization scenarios
    DB_NOT_INITIALIZED = auto()
    DB_INITIALIZED_NO_VERSION = auto()

    # Version scenarios
    VERSION_MATCH = auto()
    VERSION_UPGRADE = auto()
    VERSION_DOWNGRADE = auto()

    # ========================================================================
    # Restore scenarios - organized by storage method, wizard state, and DEK cache
    # ========================================================================

    # Software storage (no DEK cache state applies)
    RESTORE_SOFTWARE_WIZARD_COMPLETED = auto()
    RESTORE_SOFTWARE_WIZARD_INCOMPLETE = auto()

    # SoftHSM storage
    RESTORE_SOFTHSM_WIZARD_COMPLETED_DEK_CACHED = auto()
    RESTORE_SOFTHSM_WIZARD_COMPLETED_DEK_NOT_CACHED = auto()
    RESTORE_SOFTHSM_WIZARD_INCOMPLETE_DEK_CACHED = auto()
    RESTORE_SOFTHSM_WIZARD_INCOMPLETE_DEK_NOT_CACHED = auto()

    # SoftHSM storage with new KEK (old KEK lost, needs backup password)
    RESTORE_SOFTHSM_NEW_KEK_WIZARD_COMPLETED = auto()

    # Physical HSM storage (not yet supported, but included for completeness)
    RESTORE_PHYSICAL_HSM_WIZARD_COMPLETED_DEK_CACHED = auto()
    RESTORE_PHYSICAL_HSM_WIZARD_COMPLETED_DEK_NOT_CACHED = auto()
    RESTORE_PHYSICAL_HSM_WIZARD_INCOMPLETE_DEK_CACHED = auto()
    RESTORE_PHYSICAL_HSM_WIZARD_INCOMPLETE_DEK_NOT_CACHED = auto()


@dataclass
class StartupContext:
    """Context information for startup decisions."""

    # Database state
    db_initialized: bool
    db_version: Version | None
    current_version: Version

    # Wizard state
    wizard_state_enum: WizardState
    wizard_state_raw: SetupWizardState | None

    # Storage configuration
    storage_type: KeyStorageConfig.StorageType | None

    # DEK cache state (only applicable for HSM storage methods)
    dek_cache_state: DekCacheState | None

    # Output writer
    output: OutputWriter

    # HSM key state (only applicable for HSM storage methods)
    has_kek: bool = False  # Whether a KEK exists on the HSM
    has_backup_encrypted_dek: bool = False  # Whether bek_encrypted_dek exists in DB

    @property
    def is_wizard_completed(self) -> bool:
        """Check if wizard is completed."""
        return self.wizard_state_enum == WizardState.COMPLETED

    @property
    def is_software_storage(self) -> bool:
        """Check if using software storage."""
        return self.storage_type == KeyStorageConfig.StorageType.SOFTWARE

    @property
    def is_softhsm_storage(self) -> bool:
        """Check if using SoftHSM storage."""
        return self.storage_type == KeyStorageConfig.StorageType.SOFTHSM

    @property
    def is_physical_hsm_storage(self) -> bool:
        """Check if using physical HSM storage."""
        return self.storage_type == KeyStorageConfig.StorageType.PHYSICAL_HSM

    @property
    def is_hsm_storage(self) -> bool:
        """Check if using any HSM storage (SoftHSM or Physical)."""
        return self.is_softhsm_storage or self.is_physical_hsm_storage

    @property
    def is_dek_cached(self) -> bool:
        """Check if DEK is cached (only applicable for HSM storage)."""
        if not self.is_hsm_storage:
            msg = 'DEK cache state is only applicable for HSM storage'
            raise ValueError(msg)
        return self.dek_cache_state == DekCacheState.CACHED

    @property
    def is_new_kek_scenario(self) -> bool:
        """Check if this is a new KEK scenario (old KEK lost, requires backup password).

        This scenario occurs when:
        - Using HSM storage
        - DEK is not cached
        - KEK does NOT exist on the HSM (old KEK lost from previous installation)
        - Backup-encrypted DEK exists in the database

        Note: We don't check wizard_completed here because the wizard state might be
        inconsistent if restoring a database from a previous installation.

        Returns:
            True if this is a new KEK scenario requiring backup password recovery.
        """
        return (
            self.is_hsm_storage
            and not self.is_dek_cached
            and not self.has_kek  # KEK is missing (old KEK lost)
            and self.has_backup_encrypted_dek  # But we have backup-encrypted DEK
        )


class StartupStrategy(ABC):
    """Abstract base class for startup strategies."""

    @abstractmethod
    def execute(self, context: StartupContext) -> None:
        """Execute the startup strategy.

        Args:
            context: The startup context with all relevant information.
        """

    @abstractmethod
    def get_description(self) -> str:
        """Get a human-readable description of this strategy."""


# ============================================================================
# Initialization Strategies
# ============================================================================

class TlsCredentialStrategy(ABC):
    """Abstract base class for TLS credential generation strategies."""

    @abstractmethod
    def generate_and_save_tls_credential(self, context: StartupContext) -> None:
        """Generate and save TLS credentials.

        Args:
            context: The startup context with all relevant information.
        """


class StandardTlsCredentialStrategy(TlsCredentialStrategy):
    """Standard TLS credential generation using TlsServerCredentialGenerator."""

    def __init__(self, *, save_to_db: bool = True) -> None:
        """Initialize with save_to_db flag.

        Args:
            save_to_db: Whether to save the credential to database. Defaults to True.
        """
        self.save_to_db = save_to_db

    def generate_and_save_tls_credential(self, context: StartupContext) -> None:
        """Generate TLS credentials and save to database and files."""
        context.output.write('Generating TLS Server Credential...')

        # Generate the TLS Server Credential
        generator = TlsServerCredentialGenerator(
            ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')],
            ipv6_addresses=[],
            domain_names=[],
        )
        tls_server_credential = generator.generate_tls_server_credential()

        if self.save_to_db:
            context.output.write('Saving credential to database...')

            trustpoint_tls_server_credential = CredentialModel.save_credential_serializer(
                credential_serializer=tls_server_credential,
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
            )

            try:
                active_tls, created = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
                active_tls.credential = trustpoint_tls_server_credential
                active_tls.save()
            except Exception as e:
                error_msg = f'Failed to save TLS credential to database: {e}'
                context.output.write(context.output.error(error_msg))
                raise RuntimeError(error_msg) from e

            context.output.write(f'ActiveTrustpoint TLS record {"created" if created else "updated"}')

            context.output.write(f'Writing TLS files to {NGINX_KEY_PATH.parent}...')

            private_key_pem = active_tls.credential.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = active_tls.credential.get_certificate_serializer().as_pem().decode()
            trust_store_pem = active_tls.credential.get_certificate_chain_serializer().as_pem().decode()
        else:
            context.output.write('Skipping database save for temporary TLS...')

            context.output.write(f'Writing TLS files to {NGINX_KEY_PATH.parent}...')

            private_key_serializer = tls_server_credential.get_private_key_serializer()
            if private_key_serializer is None:
                error_msg = 'TLS server credential private key serializer is None'
                raise ValueError(error_msg)
            private_key_pem = private_key_serializer.as_pkcs8_pem().decode()
            certificate_serializer = tls_server_credential.get_certificate_serializer()
            if certificate_serializer is None:
                error_msg = 'TLS server credential certificate serializer is None'
                raise ValueError(error_msg)
            certificate_pem = certificate_serializer.as_pem().decode()
            trust_store_pem = certificate_pem

        NGINX_KEY_PATH.write_text(private_key_pem)
        NGINX_CERT_PATH.write_text(certificate_pem)

        # Only write chain file if there's actually a chain (not empty)
        if trust_store_pem.strip():
            NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)
        elif NGINX_CERT_CHAIN_PATH.exists():
            # Remove chain file if it exists but chain is empty
            NGINX_CERT_CHAIN_PATH.unlink()

        if self.save_to_db:
            if active_tls.credential is not None:
                sha256_fingerprint = active_tls.credential.get_certificate().fingerprint(hashes.SHA256())
            else:
                error_msg = 'Active TLS credential is None'
                raise ValueError(error_msg)
        else:
            if tls_server_credential.certificate is None:
                error_msg = 'TLS server credential certificate is None'
                raise ValueError(error_msg)
            sha256_fingerprint = tls_server_credential.certificate.fingerprint(hashes.SHA256())
        formatted = ':'.join(f'{b:02X}' for b in sha256_fingerprint)

        context.output.write(context.output.success('TLS credential generated successfully'))
        context.output.write(f'TLS SHA256 fingerprint: {formatted}')


class InitializationStrategy(ABC):
    """Abstract base class for Trustpoint initialization strategies."""

    @abstractmethod
    def initialize(self, context: StartupContext, *, with_tls: bool = False) -> None:
        """Initialize Trustpoint.

        Args:
            context: The startup context with all relevant information.
            with_tls: Whether to initialize TLS credentials.
        """


class StandardInitializationStrategy(InitializationStrategy):
    """Standard initialization: migrations, static files, messages."""

    def __init__(self, tls_strategy: TlsCredentialStrategy | None = None) -> None:
        """Initialize with optional TLS credential strategy.

        Args:
            tls_strategy: The TLS credential strategy to use. Defaults to StandardTlsCredentialStrategy.
        """
        self.tls_strategy = tls_strategy or StandardTlsCredentialStrategy()

    def initialize(self, context: StartupContext, *, with_tls: bool = False) -> None:
        """Initialize Trustpoint with standard workflow."""
        context.output.write('Initializing Trustpoint...')

        # Check SoftHSM connectivity if using SoftHSM storage
        if context.is_softhsm_storage:
            self._check_softhsm_connectivity(context)

        # Run migrations
        context.output.write('Running database migrations...')
        call_command('migrate')

        # Update version
        ver, _created = AppVersion.objects.get_or_create(pk=1)
        ver.version = str(context.current_version)

        # Get container ID
        try:
            hostname_path = Path('/etc/hostname')
            with hostname_path.open('r') as f:
                ver.container_id = f.read().strip()
        except FileNotFoundError:
            ver.container_id = 'unknown'

        ver.save()

        # Collect static files
        context.output.write('Collecting static files...')
        with io.StringIO() as fake_out:
            call_command('collectstatic', '--noinput', stdout=fake_out)

        # Compile messages
        context.output.write('Compiling translation messages...')
        with io.StringIO() as fake_out:
            call_command('compilemessages', '-l', 'de', '-l', 'en', stdout=fake_out)

        # Setup TLS if requested
        if with_tls:
            context.output.write('Preparing TLS certificate...')
            _crypto_config, created = KeyStorageConfig.objects.get_or_create(
                pk=1,
                defaults={
                    'storage_type': KeyStorageConfig.StorageType.SOFTWARE,
                }
            )
            if created:
                context.output.write('Created software crypto storage configuration')
            else:
                context.output.write('Using existing crypto storage configuration')

            # Use TLS credential strategy instead of call_command
            self.tls_strategy.generate_and_save_tls_credential(context)

        context.output.write(context.output.success('Trustpoint initialization complete'))

    def _raise_runtime_error(self, error_msg: str) -> None:
        """Raise a RuntimeError.

        Args:
            error_msg: The error message to log and raise.

        Raises:
            RuntimeError: Always raised with the provided error message.
        """
        raise RuntimeError(error_msg)

    def _check_softhsm_connectivity(self, context: StartupContext) -> None:
        """Check if SoftHSM daemon is reachable.

        Args:
            context: The startup context.

        Raises:
            RuntimeError: If SoftHSM daemon is not reachable.
        """
        context.output.write('Checking SoftHSM daemon connectivity...')

        try:
            # Try to connect to softhsm on port 5657 (default SoftHSM daemon port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout
            result = sock.connect_ex(('softhsm', 5657))
            sock.close()

            if result == 0:
                context.output.write('SoftHSM daemon is reachable on softhsm:5657')
            else:
                error_msg = 'SoftHSM daemon is not reachable on softhsm:5657 - connection refused'
                context.output.write(context.output.error(error_msg))
                self._raise_runtime_error(error_msg)

        except Exception as e:
            error_msg = f'Failed to check SoftHSM connectivity: {e}'
            context.output.write(context.output.error(error_msg))
            raise RuntimeError(error_msg) from e


# ============================================================================
# Database Initialization Strategies
# ============================================================================


class DatabaseNotInitializedStrategy(StartupStrategy):
    """Strategy for handling uninitialized database."""

    def __init__(self, init_strategy: InitializationStrategy | None = None) -> None:
        """Initialize with an initialization strategy.

        Args:
            init_strategy: The initialization strategy to use. Defaults to StandardInitializationStrategy.
        """
        self.init_strategy = init_strategy or StandardInitializationStrategy()

    def execute(self, context: StartupContext) -> None:
        """Initialize database with TLS setup."""
        context.output.write(self.get_description())
        self.init_strategy.initialize(context, with_tls=True)

    def get_description(self) -> str:
        """Get strategy description."""
        return 'Database not initialized - performing initial setup with TLS'


class DatabaseInitializedNoVersionStrategy(StartupStrategy):
    """Strategy for handling initialized database without version record."""

    def __init__(self, init_strategy: InitializationStrategy | None = None) -> None:
        """Initialize with an initialization strategy.

        Args:
            init_strategy: The initialization strategy to use. Defaults to StandardInitializationStrategy.
        """
        self.init_strategy = init_strategy or StandardInitializationStrategy()

    def execute(self, context: StartupContext) -> None:
        """Initialize database with TLS setup."""
        context.output.write(self.get_description())
        self.init_strategy.initialize(context, with_tls=True)

    def get_description(self) -> str:
        """Get strategy description."""
        return 'Database initialized but no version record - performing setup with TLS'


# ============================================================================
# Version Management Strategies
# ============================================================================


class VersionMatchStrategy(StartupStrategy):
    """Strategy for handling version match (normal startup)."""

    def __init__(
        self,
        restore_strategy: StartupStrategy,
        init_strategy: InitializationStrategy | None = None
    ) -> None:
        """Initialize with a restore strategy and initialization strategy.

        Args:
            restore_strategy: The strategy to use for restoration after initialization.
            init_strategy: The initialization strategy to use. Defaults to StandardInitializationStrategy.
        """
        self.restore_strategy = restore_strategy
        self.init_strategy = init_strategy or StandardInitializationStrategy()

    def execute(self, context: StartupContext) -> None:
        """Initialize Trustpoint and perform restoration."""
        context.output.write(self.get_description())
        self.init_strategy.initialize(context, with_tls=False)
        self.restore_strategy.execute(context)

    def get_description(self) -> str:
        """Get strategy description."""
        return 'Version match - normal startup'


class VersionUpgradeStrategy(StartupStrategy):
    """Strategy for handling version upgrade."""

    def __init__(
        self,
        restore_strategy: StartupStrategy,
        app_version: AppVersion,
        init_strategy: InitializationStrategy | None = None
    ) -> None:
        """Initialize with a restore strategy, app version, and initialization strategy.

        Args:
            restore_strategy: The strategy to use for restoration after upgrade.
            app_version: The AppVersion model instance to update.
            init_strategy: The initialization strategy to use. Defaults to StandardInitializationStrategy.
        """
        self.restore_strategy = restore_strategy
        self.app_version = app_version
        self.init_strategy = init_strategy or StandardInitializationStrategy()

    def execute(self, context: StartupContext) -> None:
        """Upgrade database version and perform restoration."""
        context.output.write(self.get_description())
        context.output.write(
            f'Updating app version from {context.db_version} to {context.current_version}'
        )
        self.init_strategy.initialize(context, with_tls=False)
        self.restore_strategy.execute(context)
        self.app_version.version = str(context.current_version)
        self.app_version.save()
        context.output.write(f'Trustpoint version updated to {context.current_version}')

    def get_description(self) -> str:
        """Get strategy description."""
        return f'Version upgrade detected: {self.app_version.version} -> (will be updated)'


# ============================================================================
# Restore Strategies - Software Storage
# ============================================================================


class RestoreSoftwareWizardCompletedStrategy(StartupStrategy):
    """Strategy: Software storage + Wizard completed - extract TLS only."""

    def execute(self, context: StartupContext) -> None:
        """Extract TLS certificates for software storage mode."""
        context.output.write(self.get_description())
        self.extract_tls_from_database(context)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> SOFTWARE Storage | Wizard COMPLETED'

    @staticmethod
    def unwrap_dek_for_token(
        context: StartupContext,
        token_label: str = DEFAULT_TOKEN_LABEL
    ) -> None:
        """Test KEK loading and unwrap DEK for the specified token to make it available in cache.

        This method follows the same logic as the unwrap_dek management command:
        1. Get the token (or return gracefully if not found - software storage case)
        2. Test KEK loading
        3. Unwrap DEK (only if encrypted_dek exists)

        Args:
            context: The startup context.
            token_label: The label of the PKCS11 token to unwrap DEK for.
        """
        context.output.write(f'Testing KEK and DEK for token: {token_label}')

        # Get the token
        try:
            token = PKCS11Token.objects.get(label=token_label)
        except ObjectDoesNotExist:
            context.output.write(
                context.output.warning(
                    f'Token "{token_label}" not found. '
                    f'This may be expected behavior if the token is not yet created.'
                )
            )
            return

        # Test 1: Load KEK
        context.output.write('Testing KEK loading...')
        try:
            # Get the KEK record
            if token.kek:
                kek_record = token.kek
            else:
                try:
                    kek_record = PKCS11Key.objects.get(
                        token_label=token.label,
                        key_label=token.KEK_ENCRYPTION_KEY_LABEL,
                        key_type=PKCS11Key.KeyType.AES
                    )
                except ObjectDoesNotExist:
                    context.output.write(
                        context.output.error(f'KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" not found in database')
                    )
                    return

            # Get the AES key instance
            aes_key = kek_record.get_pkcs11_key_instance(
                lib_path=token.module_path,
                user_pin=token.get_pin()
            )

            try:
                aes_key.load_key()
                context.output.write(
                    context.output.success(f'KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" loaded successfully')
                )
            finally:
                aes_key.close()

        except Exception as e:
            if 'no such key' in str(e).lower():
                context.output.write(
                    context.output.error(f'KEK "{token.KEK_ENCRYPTION_KEY_LABEL}" not found in HSM')
                )
            else:
                context.output.write(context.output.error(f'KEK loading failed: {e}'))
            raise

        # Test 2: Unwrap DEK (only if we have one)
        if not token.encrypted_dek:
            context.output.write(
                context.output.warning(f'No encrypted DEK found for token "{token.label}"')
            )
            return

        context.output.write('Testing DEK unwrapping...')
        try:
            # Clear any cached DEK to force unwrapping
            token.clear_dek_cache()

            dek = token.get_dek()

            # Verify the DEK
            if dek and len(dek) == DEK_EXPECTED_LENGTH:
                context.output.write(context.output.success(f'DEK unwrapped successfully ({len(dek)} bytes)'))
            else:
                expected = DEK_EXPECTED_LENGTH
                actual = len(dek) if dek else 0
                context.output.write(
                    context.output.error(f'Invalid DEK (expected {expected} bytes, got {actual})')
                )

        except Exception as e:
            context.output.write(context.output.error(f'DEK unwrapping failed: {e}'))
            raise

    @staticmethod
    def extract_tls_from_database(context: StartupContext) -> None:
        """Extract TLS certificates from database and write to Apache paths."""
        try:
            context.output.write('Extracting TLS certificates from database...')

            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
            tls_server_credential_model = active_tls.credential

            if not tls_server_credential_model:
                error_msg = _('TLS credential not found')
                context.output.write(context.output.error(error_msg))
                return

            private_key_pem = tls_server_credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = tls_server_credential_model.get_certificate_serializer().as_pem().decode()
            trust_store_pem = tls_server_credential_model.get_certificate_chain_serializer().as_pem().decode()

            NGINX_KEY_PATH.write_text(private_key_pem)
            NGINX_CERT_PATH.write_text(certificate_pem)

            # Only write chain file if there's actually a chain (not empty)
            if trust_store_pem.strip():
                NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)
            elif NGINX_CERT_CHAIN_PATH.exists():
                # Remove chain file if it exists but chain is empty
                NGINX_CERT_CHAIN_PATH.unlink()

            context.output.write(context.output.success('TLS certificates extracted successfully'))

        except (ValueError, KeyError, AttributeError) as e:
            error_msg = _('Error extracting TLS certificates: %s') % e
            context.output.write(context.output.error(error_msg))


class RestoreSoftwareWizardIncompleteStrategy(StartupStrategy):
    """Strategy: Software storage + Wizard incomplete - reset to beginning."""

    def __init__(self, tls_strategy: TlsCredentialStrategy | None = None) -> None:
        """Initialize with optional TLS credential strategy.

        Args:
            tls_strategy: The TLS credential strategy to use. Defaults to StandardTlsCredentialStrategy.
        """
        self.tls_strategy = tls_strategy or StandardTlsCredentialStrategy()

    def execute(self, context: StartupContext) -> None:
        """Reset wizard to WIZARD_SETUP_CRYPTO_STORAGE state and generate TLS certificates."""
        context.output.write(self.get_description())
        context.output.write('>>> Wizard incomplete - resetting to WIZARD_SETUP_CRYPTO_STORAGE')
        context.output.write('>>> Generating TLS certificates for wizard setup page')
        self.tls_strategy.generate_and_save_tls_credential(context)
        self._reset_wizard_state(context)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> SOFTWARE Storage | Wizard INCOMPLETE - RESETTING TO START'

    @staticmethod
    def _reset_wizard_state(context: StartupContext) -> None:
        """Reset wizard state to WIZARD_SETUP_CRYPTO_STORAGE."""
        script_path = Path('/etc/trustpoint/wizard/transition/wizard_reset_to_crypto_storage.sh')

        try:
            execute_shell_script(script_path)
            context.output.write(context.output.success('Wizard state reset to WIZARD_SETUP_CRYPTO_STORAGE'))

        except subprocess.CalledProcessError as exc:
            error_msg = (
                f'Auto restore script failed: '
                f'{RestoreSoftwareWizardIncompleteStrategy._map_exit_code_to_message(exc.returncode)}'
            )
            context.output.write(context.output.error(error_msg))

        except FileNotFoundError:
            error_msg = f'Auto restore script not found: {script_path}'
            context.output.write(context.output.error(error_msg))

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Wizard state directory does not exist.',
            2: 'Found multiple wizard state files; the wizard state seems to be corrupted.',
            3: 'Failed to create WIZARD_SETUP_CRYPTO_STORAGE state file',
        }
        return error_messages.get(return_code, 'An unknown error occurred during auto restore password processing.')


# ============================================================================
# Restore Strategies - SoftHSM Storage
# ============================================================================


class RestoreSoftHsmWizardCompletedDekCachedStrategy(StartupStrategy):
    """Strategy: SoftHSM + Wizard completed + DEK cached - extract TLS and unwrap DEK."""

    def execute(self, context: StartupContext) -> None:
        """Extract TLS certificates and unwrap DEK for application use."""
        context.output.write(self.get_description())
        context.output.write('>>> System already initialized with valid DEK - extracting TLS files')
        RestoreSoftwareWizardCompletedStrategy.extract_tls_from_database(context)
        context.output.write('>>> Unwrapping DEK for application use')
        RestoreSoftwareWizardCompletedStrategy.unwrap_dek_for_token(context)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> SOFTHSM Storage | Wizard COMPLETED | DEK CACHED'


class RestoreSoftHsmWizardCompletedDekNotCachedStrategy(StartupStrategy):
    """Strategy: SoftHSM + Wizard completed + DEK not cached - needs auto restore."""

    def execute(self, context: StartupContext) -> None:
        """Trigger auto restore flow for SoftHSM with DEK not cached."""
        context.output.write(self.get_description())
        context.output.write('>>> SoftHSM with DEK not cached - initiating auto restore flow')
        self._set_auto_restore_state(context)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> SOFTHSM Storage | Wizard COMPLETED | DEK NOT CACHED'

    @staticmethod
    def _set_auto_restore_state(context: StartupContext) -> None:
        """Transition to WIZARD_AUTO_RESTORE_PASSWORD state."""
        context.output.write('Transitioning to auto restore password entry')
        script_path = SCRIPT_WIZARD_AUTO_RESTORE_SET

        try:
            execute_shell_script(script_path)
            context.output.write(context.output.success('Transitioned to WIZARD_AUTO_RESTORE_PASSWORD state'))

        except subprocess.CalledProcessError as exc:
            error_msg = (
                f'Auto restore password state transition failed: '
                f'{RestoreSoftHsmWizardCompletedDekNotCachedStrategy._map_exit_code_to_message(exc.returncode)}'
            )
            context.output.write(context.output.error(error_msg))
            raise RuntimeError(error_msg) from exc

        except FileNotFoundError as e:
            error_msg = f'Auto restore password script not found: {script_path}'
            context.output.write(context.output.error(error_msg))
            raise RuntimeError(error_msg) from e

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_SETUP_CRYPTO_STORAGE state.',
            2: 'Found multiple wizard state files; the wizard state seems to be corrupted.',
            3: 'Failed to remove the WIZARD_SETUP_CRYPTO_STORAGE state file.',
            4: 'Failed to create the WIZARD_AUTO_RESTORE_PASSWORD state file.',
        }
        return error_messages.get(
            return_code,
            'An unknown error occurred during auto restore password state transition.'
        )


class RestoreSoftHsmNewKekWizardCompletedStrategy(StartupStrategy):
    """Strategy: SoftHSM + New KEK (old KEK lost) + Wizard completed - generate temp TLS, wait for backup password.

    This scenario occurs when:
    - Trustpoint container and SoftHSM are new (fresh installation)
    - But there's an existing database with encrypted data
    - The database was encrypted with a KEK that no longer exists on the new SoftHSM
    - The wizard was previously completed

    The strategy:
    1. Generates a temporary TLS certificate (since DB TLS cert is encrypted and inaccessible)
    2. Transitions to WIZARD_AUTO_RESTORE_PASSWORD state
    3. Waits for user to input backup password
    4. BackupAutoRestorePasswordView will:
       - Generate a new KEK on the new SoftHSM
       - Decrypt the DEK using the backup password
       - Re-wrap the DEK with the new KEK
       - Extract and activate the actual TLS certificate from the database
       - Complete the wizard
    """

    def __init__(self, tls_strategy: TlsCredentialStrategy | None = None) -> None:
        """Initialize with optional TLS credential strategy.

        Args:
            tls_strategy: The TLS credential strategy to use.
                Defaults to StandardTlsCredentialStrategy with save_to_db=False
                to avoid database operations when DEK is not accessible.
        """
        self.tls_strategy = tls_strategy or StandardTlsCredentialStrategy(save_to_db=False)

    def execute(self, context: StartupContext) -> None:
        """Generate temporary TLS certificate and trigger auto restore flow."""
        context.output.write(self.get_description())
        context.output.write('>>> New SoftHSM detected with encrypted database')
        context.output.write('>>> Old KEK is unavailable - backup password required')
        context.output.write('>>> Generating temporary TLS certificate for initial access')

        self.tls_strategy.generate_and_save_tls_credential(context)

        context.output.write('>>> Transitioning to auto restore flow')
        context.output.write('>>> User must provide backup password to:')
        context.output.write('>>>   1. Generate new KEK on new SoftHSM')
        context.output.write('>>>   2. Decrypt DEK with backup password')
        context.output.write('>>>   3. Re-wrap DEK with new KEK')
        context.output.write('>>>   4. Activate actual TLS certificate from database')

        RestoreSoftHsmWizardCompletedDekNotCachedStrategy._set_auto_restore_state(context)  # noqa: SLF001

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> SOFTHSM Storage | NEW KEK (OLD KEK LOST) | Wizard COMPLETED | REQUIRES BACKUP PASSWORD'


class RestoreSoftHsmWizardIncompleteDekCachedStrategy(StartupStrategy):
    """Strategy: SoftHSM + Wizard incomplete + DEK cached - reset to beginning."""

    def __init__(self, tls_strategy: TlsCredentialStrategy | None = None) -> None:
        """Initialize with optional TLS credential strategy.

        Args:
            tls_strategy: The TLS credential strategy to use. Defaults to StandardTlsCredentialStrategy.
        """
        self.tls_strategy = tls_strategy or StandardTlsCredentialStrategy()

    def execute(self, context: StartupContext) -> None:
        """Reset wizard to WIZARD_SETUP_CRYPTO_STORAGE state and generate TLS certificates."""
        context.output.write(self.get_description())
        context.output.write('>>> Wizard incomplete - resetting to WIZARD_SETUP_CRYPTO_STORAGE')
        context.output.write('>>> Generating TLS certificates for wizard setup page')
        self.tls_strategy.generate_and_save_tls_credential(context)
        RestoreSoftwareWizardIncompleteStrategy._reset_wizard_state(context)  # noqa: SLF001

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> SOFTHSM Storage | Wizard INCOMPLETE | DEK CACHED - RESETTING TO START'


class RestoreSoftHsmWizardIncompleteDekNotCachedStrategy(StartupStrategy):
    """Strategy: SoftHSM + Wizard incomplete + DEK not cached - reset to beginning."""

    def __init__(self, tls_strategy: TlsCredentialStrategy | None = None) -> None:
        """Initialize with optional TLS credential strategy.

        Args:
            tls_strategy: The TLS credential strategy to use.
                Defaults to StandardTlsCredentialStrategy with save_to_db=False
                to generate temporary TLS for wizard reset.
        """
        self.tls_strategy = tls_strategy or StandardTlsCredentialStrategy(save_to_db=False)

    def execute(self, context: StartupContext) -> None:
        """Reset wizard to WIZARD_SETUP_CRYPTO_STORAGE state and generate TLS certificates."""
        context.output.write(self.get_description())
        context.output.write('>>> Wizard incomplete - resetting to WIZARD_SETUP_CRYPTO_STORAGE')
        context.output.write('>>> Generating TLS certificates for wizard setup page')
        self.tls_strategy.generate_and_save_tls_credential(context)
        RestoreSoftwareWizardIncompleteStrategy._reset_wizard_state(context)  # noqa: SLF001

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> SOFTHSM Storage | Wizard INCOMPLETE | DEK NOT CACHED - RESETTING TO START'


# ============================================================================
# Restore Strategies - Physical HSM Storage
# ============================================================================


class RestorePhysicalHsmWizardCompletedDekCachedStrategy(StartupStrategy):
    """Strategy: Physical HSM + Wizard completed + DEK cached - NOT SUPPORTED."""

    def execute(self, context: StartupContext) -> None:
        """Raise error as Physical HSM is not yet supported."""
        context.output.write(self.get_description())
        error_msg = (
            'Physical HSM storage is not yet supported. '
            'Please use SOFTWARE or SOFTHSM storage methods.'
        )
        context.output.write(context.output.error(error_msg))
        raise NotImplementedError(error_msg)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> PHYSICAL HSM Storage | Wizard COMPLETED | DEK CACHED | NOT SUPPORTED'


class RestorePhysicalHsmWizardCompletedDekNotCachedStrategy(StartupStrategy):
    """Strategy: Physical HSM + Wizard completed + DEK not cached - NOT SUPPORTED."""

    def execute(self, context: StartupContext) -> None:
        """Raise error as Physical HSM is not yet supported."""
        context.output.write(self.get_description())
        error_msg = (
            'Physical HSM storage is not yet supported. '
            'Please use SOFTWARE or SOFTHSM storage methods.'
        )
        context.output.write(context.output.error(error_msg))
        raise NotImplementedError(error_msg)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> PHYSICAL HSM Storage | Wizard COMPLETED | DEK NOT CACHED | NOT SUPPORTED'


class RestorePhysicalHsmWizardIncompleteDekCachedStrategy(StartupStrategy):
    """Strategy: Physical HSM + Wizard incomplete + DEK cached - NOT SUPPORTED."""

    def execute(self, context: StartupContext) -> None:
        """Raise error as Physical HSM is not yet supported."""
        context.output.write(self.get_description())
        error_msg = 'Physical HSM storage is not yet supported. Please use SOFTWARE or SOFTHSM storage methods.'
        context.output.write(context.output.error(error_msg))
        raise NotImplementedError(error_msg)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> PHYSICAL HSM Storage | Wizard INCOMPLETE | DEK CACHED - NOT SUPPORTED'


class RestorePhysicalHsmWizardIncompleteDekNotCachedStrategy(StartupStrategy):
    """Strategy: Physical HSM + Wizard incomplete + DEK not cached - NOT SUPPORTED."""

    def execute(self, context: StartupContext) -> None:
        """Raise error as Physical HSM is not yet supported."""
        context.output.write(self.get_description())
        error_msg = 'Physical HSM storage is not yet supported. Please use SOFTWARE or SOFTHSM storage methods.'
        context.output.write(context.output.error(error_msg))
        raise NotImplementedError(error_msg)

    def get_description(self) -> str:
        """Get strategy description."""
        return '>>> PHYSICAL HSM Storage | Wizard INCOMPLETE | DEK NOT CACHED - NOT SUPPORTED'


# ============================================================================
# Strategy Selector
# ============================================================================


class StartupStrategySelector:
    """Selector for determining the appropriate startup strategy."""

    @staticmethod
    def select_restore_strategy(context: StartupContext) -> StartupStrategy:
        """Select the appropriate restore strategy based on context.

        Args:
            context: The startup context with all relevant information.

        Returns:
            The appropriate StartupStrategy instance.
        """
        StartupStrategySelector._log_strategy_selection(context)

        if context.is_software_storage:
            return StartupStrategySelector._select_software_strategy(context)

        if context.is_softhsm_storage:
            return StartupStrategySelector._select_softhsm_strategy(context)

        if context.is_physical_hsm_storage:
            return StartupStrategySelector._select_physical_hsm_strategy(context)

        error_msg = f'Unexpected storage configuration: {context.storage_type}'
        raise ValueError(error_msg)

    @staticmethod
    def _log_strategy_selection(context: StartupContext) -> None:
        """Log the current configuration for strategy selection."""
        context.output.write('=== Determining Restore Strategy ===')
        storage_display = context.storage_type.value if context.storage_type else 'None'
        context.output.write(f'Storage Type: {storage_display}')
        context.output.write(f'Wizard State: {context.wizard_state_enum.value}')
        if context.is_hsm_storage:
            dek_state = context.dek_cache_state.value if context.dek_cache_state else 'N/A'
            context.output.write(f'DEK Cache State: {dek_state}')

    @staticmethod
    def _select_software_strategy(context: StartupContext) -> StartupStrategy:
        """Select strategy for SOFTWARE storage."""
        if context.is_wizard_completed:
            return RestoreSoftwareWizardCompletedStrategy()
        return RestoreSoftwareWizardIncompleteStrategy()

    @staticmethod
    def _select_softhsm_strategy(context: StartupContext) -> StartupStrategy:
        """Select strategy for SOFTHSM storage."""
        # Check for new KEK scenario FIRST (before checking wizard state)
        # This is important because the wizard state might be inconsistent if
        # the database is from a previous installation
        if context.is_new_kek_scenario:
            return RestoreSoftHsmNewKekWizardCompletedStrategy()

        if context.is_wizard_completed:
            # Standard scenarios for completed wizard
            if context.is_dek_cached:
                return RestoreSoftHsmWizardCompletedDekCachedStrategy()
            return RestoreSoftHsmWizardCompletedDekNotCachedStrategy()

        # Wizard incomplete
        if context.is_dek_cached:
            return RestoreSoftHsmWizardIncompleteDekCachedStrategy()
        return RestoreSoftHsmWizardIncompleteDekNotCachedStrategy()

    @staticmethod
    def _select_physical_hsm_strategy(context: StartupContext) -> StartupStrategy:
        """Select strategy for PHYSICAL_HSM storage."""
        if context.is_wizard_completed:
            if context.is_dek_cached:
                return RestorePhysicalHsmWizardCompletedDekCachedStrategy()
            return RestorePhysicalHsmWizardCompletedDekNotCachedStrategy()
        # Wizard incomplete
        if context.is_dek_cached:
            return RestorePhysicalHsmWizardIncompleteDekCachedStrategy()
        return RestorePhysicalHsmWizardIncompleteDekNotCachedStrategy()

    @staticmethod
    def select_version_strategy(
        context: StartupContext,
        app_version: AppVersion
    ) -> StartupStrategy:
        """Select the appropriate version management strategy.

        Args:
            context: The startup context with version information.
            app_version: The AppVersion model instance.

        Returns:
            The appropriate StartupStrategy instance.

        Raises:
            RuntimeError: If version downgrade is detected.
        """
        if context.db_version == context.current_version:
            restore_strategy = StartupStrategySelector.select_restore_strategy(context)
            return VersionMatchStrategy(restore_strategy)

        if context.db_version is not None and context.current_version < context.db_version:
            error_msg = (
                f'Current app version {context.current_version} is lower than '
                f'the version {context.db_version} in the DB. '
                'This is not supported. '
                'Please update the Trustpoint container or remove the postgres volume '
                'to restore another backup.'
            )
            raise RuntimeError(error_msg)

        # Version upgrade
        restore_strategy = StartupStrategySelector.select_restore_strategy(context)
        return VersionUpgradeStrategy(restore_strategy, app_version)

    @staticmethod
    def select_startup_strategy(
        *,
        db_initialized: bool,
        has_version: bool,
        context: StartupContext | None = None,
        app_version: AppVersion | None = None
    ) -> StartupStrategy:
        """Select the top-level startup strategy.

        Args:
            db_initialized: Whether the database is initialized.
            has_version: Whether an app version record exists.
            context: The startup context (required if db is initialized).
            app_version: The AppVersion model instance (required if db is initialized).

        Returns:
            The appropriate StartupStrategy instance.
        """
        if not db_initialized:
            return DatabaseNotInitializedStrategy()

        if not has_version:
            return DatabaseInitializedNoVersionStrategy()

        if context is None or app_version is None:
            error_msg = 'Context and app_version required for version management'
            raise ValueError(error_msg)

        return StartupStrategySelector.select_version_strategy(context, app_version)
