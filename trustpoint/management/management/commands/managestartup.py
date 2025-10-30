"""Management command to check and update the Trustpoint database version."""

import subprocess
from pathlib import Path

from django.conf import settings as django_settings
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand
from django.db.utils import OperationalError, ProgrammingError
from packaging.version import InvalidVersion, Version
from setup_wizard import SetupWizardState

from management.models import AppVersion, KeyStorageConfig


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.manage_startup()

    def manage_startup(self) -> None:
        """Checks current state of trustpoint and acts accordingly."""
        try:
            app_version = AppVersion.objects.first()
            current = django_settings.APP_VERSION
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
            call_command('inittrustpoint')
            self._handle_restore_with_auto_restore_check()
        elif current_version < db_version:
            error_msg = (
                f'Current app version {current} is lower than the version {db_version} in the DB. '
                'This is not supported. '
                'Please update the Trustpoint container or remove the postgres volume to restore another backup.')
            raise CommandError(error_msg)
        else: # Current Trustpoint container version is newer than DB version, update the app version
            self.stdout.write(f'Updating app version from {db_version} to {current}')
            call_command('inittrustpoint')
            self._handle_restore_with_auto_restore_check()
            app_version.version = current
            app_version.save()
            self.stdout.write(f'Trustpoint version updated to {current}')

    def _handle_restore_with_auto_restore_check(self) -> None:
        """Handle restore process and check if auto restore is needed for SOFTHSM.

        For SOFTWARE storage type, normal restore is performed.
        For SOFTHSM/PHYSICAL_HSM storage type, trigger auto restore flow if wizard is completed.
        """
        # Check if wizard is completed and if storage type requires backup password
        if self._is_wizard_completed() and self._needs_backup_password_recovery():
            self.stdout.write('SOFTHSM/HSM detected - initiating auto restore flow')
            self._set_auto_restore_state()
        else:
            # Normal restore for SOFTWARE or non-completed wizard
            call_command('trustpointrestore')

    def _needs_backup_password_recovery(self) -> bool:
        """Check if the storage type requires backup password recovery.

        Returns:
            True if storage type is SOFTHSM or PHYSICAL_HSM, False otherwise.
        """
        try:
            config = KeyStorageConfig.objects.first()
            if not config:
                self.stdout.write(self.style.WARNING('No KeyStorageConfig found'))
                return False
        except Exception as e:  # noqa: BLE001
            self.stdout.write(self.style.WARNING(f'Error checking storage type: {e}'))
            return False
        else:
            return config.storage_type in (
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM
            )

    def _is_wizard_completed(self) -> bool:
        """Check if the setup wizard has been completed."""
        try:
            current_state = SetupWizardState.get_current_state()
        except RuntimeError:
            self.stdout.write(self.style.WARNING('Could not determine wizard state'))
            return False
        else:
            return current_state == SetupWizardState.WIZARD_COMPLETED

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
