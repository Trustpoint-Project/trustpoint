"""Management command to check and update the Trustpoint database version."""

import subprocess
from pathlib import Path

from django.conf import settings as django_settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand
from django.db.utils import OperationalError, ProgrammingError
from django.utils.translation import gettext as _
from packaging.version import InvalidVersion, Version
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard import SetupWizardState

from management.apache_paths import APACHE_CERT_CHAIN_PATH, APACHE_CERT_PATH, APACHE_KEY_PATH
from management.models import AppVersion, KeyStorageConfig


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.manage_startup()

    def manage_startup(self) -> None:
        """Checks current state of trustpoint and acts accordingly."""
        self.stdout.write('=== Starting Trustpoint Startup Sequence ===')
        try:
            app_version = AppVersion.objects.first()
            current = django_settings.APP_VERSION
            self.stdout.write(f'App version from DB: {app_version.version if app_version else "None"}')
            self.stdout.write(f'Current app version: {current}')
        except (ProgrammingError, OperationalError):
            # If the AppVersion table does not exist, we assume the DB is not initialized
            db_error_msg: str = 'AppVersion table not found. DB probably not initialized'
            self.stdout.write(self.style.ERROR(db_error_msg))
            call_command('inittrustpoint', '--tls')
            return

        if not app_version:
            db_error_msg2: str = 'DB AppVersion not found. DB probably not initialized'
            self.stdout.write(self.style.ERROR(db_error_msg2))
            call_command('inittrustpoint', '--tls')
            return

        db_version, current_version = self._parse_versions(app_version.version, current)

        if db_version == current_version:
            self.stdout.write('Version match detected - initializing Trustpoint')
            call_command('inittrustpoint')
            self._handle_restore_with_auto_restore_check()
        elif current_version < db_version:
            error_msg = (
                f'Current app version {current} is lower than the version {db_version} in the DB. '
                'This is not supported. '
                'Please update the Trustpoint container or remove the postgres volume to restore another backup.')
            raise CommandError(error_msg)
        else: # Current Trustpoint container version is newer than DB version, update the app version
            self.stdout.write(f'Version upgrade detected: {db_version} -> {current}')
            self.stdout.write(f'Updating app version from {db_version} to {current}')
            call_command('inittrustpoint')
            self._handle_restore_with_auto_restore_check()
            app_version.version = current
            app_version.save()
            self.stdout.write(f'Trustpoint version updated to {current}')

    def _handle_restore_with_auto_restore_check(self) -> None:
        """Handle restore process and check if auto restore is needed for SOFTHSM.

        For SOFTWARE storage type, normal restore is performed.
        For SOFTHSM/PHYSICAL_HSM storage type with empty DEK, trigger auto restore flow if wizard is completed.
        For systems already initialized (DEK present), extract TLS files but skip full restoration.
        """
        self.stdout.write('=== Checking Restore Requirements ===')
        # Check wizard completion status
        wizard_completed = self._is_wizard_completed()

        needs_backup_recovery = self._needs_backup_password_recovery()

        # Check if wizard is completed and if storage type requires backup password
        if wizard_completed and needs_backup_recovery:
            self.stdout.write('>>> Branch 1: Wizard completed + HSM mode')
            dek_empty = self._is_dek_empty()
            self.stdout.write(f'DEK empty check result: {dek_empty}')
            if dek_empty:
                self.stdout.write('>>> SOFTHSM/HSM with empty DEK - initiating auto restore flow')
                self._set_auto_restore_state()
            else:
                # System is already initialized with a valid DEK
                # Extract TLS files from database but skip wizard restoration
                self.stdout.write('>>> System already initialized with valid DEK - extracting TLS files only')
                self._extract_tls_from_database()
        elif not wizard_completed and needs_backup_recovery:
            # Wizard not completed but HSM is configured - check if DEK is empty
            self.stdout.write('>>> Branch 2: Wizard not completed + HSM mode - checking DEK status')
            dek_empty = self._is_dek_empty()
            if dek_empty:
                self.stdout.write('>>> HSM configured but DEK empty - initiating auto restore flow')
                self._set_auto_restore_state()
            else:
                self.stdout.write('>>> HSM configured with DEK present - completing wizard setup')
                self._extract_tls_from_database()
                self._complete_wizard_setup()
        elif not wizard_completed:
            # Normal restore for non-completed wizard (software mode or initial setup)
            self.stdout.write('>>> Branch 3: Wizard not completed + Software mode')
            self.stdout.write('>>> Note: Skipping restore - wizard needs to be completed first')
            # Don't run trustpointrestore when wizard is incomplete as it expects specific states
        else:
            # Software mode with completed wizard - extract TLS files
            self.stdout.write('>>> Branch 4: Wizard completed + Software mode - extracting TLS files')
            self._extract_tls_from_database()

    def _needs_backup_password_recovery(self) -> bool:
        """Check if the storage type requires backup password recovery.

        Returns:
            True if storage type is SOFTHSM or PHYSICAL_HSM, False otherwise.
        """
        self.stdout.write('Checking storage type configuration...')
        try:
            config = KeyStorageConfig.objects.first()
            if not config:
                self.stdout.write(self.style.WARNING('No KeyStorageConfig found'))
                return False
            self.stdout.write(f'Storage type: {config.storage_type}')
        except Exception as e:  # noqa: BLE001
            self.stdout.write(self.style.WARNING(f'Error checking storage type: {e}'))
            return False
        else:
            needs_recovery = config.storage_type in (
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM
            )
            self.stdout.write(f'Storage requires backup recovery: {needs_recovery}')
            return needs_recovery

    def _is_wizard_completed(self) -> bool:
        """Check if the setup wizard has been completed."""
        self.stdout.write('Checking wizard completion state...')
        try:
            current_state = SetupWizardState.get_current_state()
            self.stdout.write(f'Current wizard state: {current_state}')
        except RuntimeError as e:
            self.stdout.write(self.style.WARNING(f'Could not determine wizard state: {e}'))
            return False
        else:
            is_completed = current_state == SetupWizardState.WIZARD_COMPLETED
            self.stdout.write(f'Wizard is completed: {is_completed}')
            return is_completed

    def _is_dek_empty(self) -> bool:
        """Check if the DEK (Data Encryption Key) is accessible.

        Returns:
            True if DEK is not accessible (empty or KEK unavailable), False if DEK can be unwrapped.
        """
        self.stdout.write('Checking DEK accessibility...')
        dek_inaccessible = True  # Default: assume DEK is not accessible

        try:
            config = KeyStorageConfig.objects.first()
            if not config or not config.hsm_config:
                self.stdout.write(self.style.WARNING('No HSM configuration found'))
                return dek_inaccessible

            token = config.hsm_config
            self.stdout.write(f'Token label: {token.label}')
            self.stdout.write(f'encrypted_dek present: {bool(token.encrypted_dek)}')
            self.stdout.write(f'bek_encrypted_dek present: {bool(token.bek_encrypted_dek)}')

            # If no encrypted DEK at all, it's empty
            if not token.encrypted_dek and not token.bek_encrypted_dek:
                self.stdout.write('>>> No DEK found - backup password required')
                return dek_inaccessible

            # Try to get the DEK from cache (doesn't trigger unwrapping)
            cached_dek = token.get_dek_cache()
            if cached_dek:
                self.stdout.write('>>> DEK available in cache - system operational')
                return False

            # Try to unwrap the DEK to see if KEK is accessible
            self.stdout.write('Attempting to unwrap DEK to verify KEK accessibility...')
            try:
                dek = token.get_dek()
                if dek:
                    self.stdout.write('>>> DEK successfully unwrapped - KEK is accessible')
                    dek_inaccessible = False
            except Exception as unwrap_error:  # noqa: BLE001
                self.stdout.write(f'>>> DEK unwrap failed: {unwrap_error}')
                self.stdout.write('>>> KEK unavailable - backup password required')
                dek_inaccessible = True

        except Exception as e:  # noqa: BLE001
            self.stdout.write(self.style.WARNING(f'Error checking DEK status: {e}'))
            dek_inaccessible = True

        return dek_inaccessible

    def _extract_tls_from_database(self) -> None:
        """Extract TLS certificates from database and write them to Apache paths.

        This is a lightweight version of trustpointrestore that only extracts
        TLS files without running the full wizard restoration process.
        """
        try:
            self.stdout.write('Extracting TLS certificates from database...')

            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
            tls_server_credential_model = active_tls.credential

            if not tls_server_credential_model:
                error_msg = _('TLS credential not found')
                self.stdout.write(self.style.ERROR(error_msg))
                return

            private_key_pem = tls_server_credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = tls_server_credential_model.get_certificate_serializer().as_pem().decode()
            trust_store_pem = tls_server_credential_model.get_certificate_chain_serializer().as_pem().decode()

            APACHE_KEY_PATH.write_text(private_key_pem)
            APACHE_CERT_PATH.write_text(certificate_pem)

            # Only write chain file if there's actually a chain (not empty)
            if trust_store_pem.strip():
                APACHE_CERT_CHAIN_PATH.write_text(trust_store_pem)
            elif APACHE_CERT_CHAIN_PATH.exists():
                # Remove chain file if it exists but chain is empty
                APACHE_CERT_CHAIN_PATH.unlink()

            self.stdout.write(self.style.SUCCESS('TLS certificates extracted successfully'))

        except (ValueError, KeyError, AttributeError) as e:
            error_msg = _('Error extracting TLS certificates: %s') % e
            self.stdout.write(self.style.ERROR(error_msg))

    def _complete_wizard_setup(self) -> None:
        """Complete the wizard setup by calling the transition script.

        This method is used when the DEK is accessible but the wizard is in an incomplete state.
        It transitions the wizard to WIZARD_COMPLETED state.
        """
        try:
            self.stdout.write('Completing wizard setup...')

            result = subprocess.run(
                ['/usr/bin/sudo', '/etc/trustpoint/wizard/transition/wizard_complete_setup.sh'],
                check=True,
                capture_output=True,
                text=True
            )

            self.stdout.write(self.style.SUCCESS('Wizard setup completed successfully'))
            if result.stdout:
                self.stdout.write(f'Script output: {result.stdout}')

        except subprocess.CalledProcessError as e:
            error_msg = f'Error completing wizard setup: {e}'
            if e.stderr:
                error_msg += f'\nStderr: {e.stderr}'
            self.stdout.write(self.style.ERROR(error_msg))

        except ObjectDoesNotExist:
            error_msg = _('TLS credential not found in database')
            self.stdout.write(self.style.ERROR(error_msg))

        except (ProgrammingError, OperationalError) as e:
            error_msg = _('Database error while extracting TLS credentials')
            self.stdout.write(self.style.ERROR(f'{error_msg}: {e}'))

        except Exception as e:  # noqa: BLE001
            self.stdout.write(self.style.ERROR(f'Failed to extract TLS certificates: {e}'))

    def _set_auto_restore_state(self) -> None:
        """Transition to WIZARD_AUTO_RESTORE_PASSWORD state for auto restore.

        During auto restore, the PKCS11Token configuration was already restored from the database.
        The user only needs to provide the backup password to decrypt the DEK.
        """
        self.stdout.write('Transitioning to auto restore password entry')

        script_path = Path('/etc/trustpoint/wizard/transition/wizard_auto_restore_password_set.sh')

        try:
            if not (script_path.is_file() and script_path.is_absolute()
                    and script_path.match('/etc/trustpoint/wizard/transition/*.sh')):
                error_msg = f'Invalid or untrusted script path: {script_path}'
                self.stdout.write(self.style.ERROR(error_msg))
                raise CommandError(error_msg)

            # Execute the script using sudo as configured in sudoers
            command = ['sudo', str(script_path)]
            subprocess.run(command, check=True, capture_output=True, text=True)  # noqa: S603
            self.stdout.write(self.style.SUCCESS('Transitioned to WIZARD_AUTO_RESTORE_PASSWORD state'))
        except subprocess.CalledProcessError as e:
            error_msg = f'Failed to set auto restore password state: {e.stderr}'
            self.stdout.write(self.style.ERROR(error_msg))
            raise CommandError(error_msg) from e
        except FileNotFoundError as e:
            error_msg = f'Auto restore password script not found: {script_path}'
            self.stdout.write(self.style.ERROR(error_msg))
            raise CommandError(error_msg) from e
            raise CommandError(error_msg) from e

    def _parse_versions(self, db_version_str: str, current_version_str: str) -> tuple[Version, Version]:
        """Parse the version strings into Version objects."""
        try:
            db_version = Version(db_version_str)
        except InvalidVersion as e:
            exc_msg = f'Invalid version format {db_version_str} in the database AppVersion.'
            raise CommandError(exc_msg) from e

        try:
            current_version = Version(current_version_str)
        except InvalidVersion as e:
            exc_msg = f'Current Trustpoint version format {current_version_str} is invalid.'
            raise CommandError(exc_msg) from e

        return db_version, current_version
