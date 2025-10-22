"""Management command to restore the Trustpoint container (Apache TLS + wizard)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes
from django.conf import settings as django_settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db.utils import OperationalError, ProgrammingError
from django.utils.translation import gettext as _
from packaging.version import InvalidVersion, Version
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.views import APACHE_CERT_CHAIN_PATH, APACHE_CERT_PATH, APACHE_KEY_PATH, SCRIPT_WIZARD_RESTORE

from management.models import AppVersion

if TYPE_CHECKING:
    from typing import Any


class Command(BaseCommand):
    """A Django management command to restore the Trustpoint container.

    This restores the Apache TLS certificate and the wizard state.
    It is unrelated to the restore of a database backup.
    """

    help = 'Restores Trustpoint container.'

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--filepath', type=str, required=False, help='Optional gzipped dump file')

    def handle(self, **options: Any) -> None:
        """Entrypoint for the command."""
        dump_path = options.get('filepath', '')
        if dump_path:
            dump_version_str = self._extract_version_from_dump(dump_path)
            current_str = django_settings.APP_VERSION
            try:
                db_v = Version(dump_version_str)
            except InvalidVersion as e:
                msg = f'Invalid version format in dump: {dump_version_str}'
                raise CommandError(msg) from e
            try:
                cur_v = Version(current_str)
            except InvalidVersion as e:
                msg = f'Invalid current app version: {current_str}'
                raise CommandError(msg) from e

            if cur_v != db_v and db_v.is_prerelease:
                msg = f'It is not allowed to restore pre release {db_v} version into release version {cur_v}.\n'
                msg += 'Contact trustpoint to find solution.'
                raise InvalidVersion(msg)

            if cur_v >= db_v:
                call_command('dbrestore', '-z', '--noinput', '-I', dump_path)
                self.stdout.write('Finished restoring')
                if cur_v > db_v:
                    call_command('migrate')
            else:
                error_msg = (
                    f'Current app version {cur_v} is lower than the version {db_v} in the DB. '
                    'This is not supported. '
                    'Please update the Trustpoint container or remove the postgres volume to restore another backup.'
                )
                raise CommandError(error_msg)

        self.restore_trustpoint()

    def _extract_version_from_dump(self, dump_path: str) -> str:
        p = Path(dump_path)
        if not p.exists() or not p.is_file():
            msg = f'Backup file not found: {dump_path}'
            raise CommandError(msg)

        qp = "'" + str(p).replace("'", "'\"'\"'") + "'"
        cmd = (
            f'gunzip -c {qp} '
            '| pg_restore -a -t management_appversion -f - '
            "| sed -n '/^COPY .*management_appversion /,/^\\\\\\./p' "
            "| sed '1d;$d' | cut -f2 | head -n1"
        )
        r = subprocess.run(['bash', '-lc', cmd], check=False, capture_output=True, text=True)  # noqa: S603
        if r.returncode != 0:
            msg = f'Extractor failed: {r.stderr.strip() or r.stdout.strip() or "unknown error"}'
            raise CommandError(msg)
        out = r.stdout.strip()
        if not out:
            msg = 'Could not extract version from dump.'
            raise CommandError(msg)
        return out

    def restore_trustpoint(self) -> None:
        """Restore trustpoint (Apache TLS and wizard state) if DB is there."""
        current = django_settings.APP_VERSION
        try:
            self.stdout.write('Starting with restoration')
            app_version = AppVersion.objects.first()
            if not app_version:
                error_msg = _('Appversion table not found. DB probably not initialized')
                self.stdout.write(self.style.ERROR(error_msg))
                return

            if app_version.version != current:
                error_msg = (
                    f'Appversion in DB {app_version.version} does not match current version {current}. '
                    'Please run the inittrustpoint command before attempting TLS restoration.'
                )
                self.stdout.write(self.style.ERROR(error_msg))
                return

            self.stdout.write('Matching version in database found.')
            self.stdout.write('Extrating tls cert and preparing for restoration of apache config...')

            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
            tls_server_credential_model = active_tls.credential

            private_key_pem = tls_server_credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = tls_server_credential_model.get_certificate_serializer().as_pem().decode()
            trust_store_pem = tls_server_credential_model.get_certificate_chain_serializer().as_pem().decode()

            APACHE_KEY_PATH.write_text(private_key_pem)
            APACHE_CERT_PATH.write_text(certificate_pem)
            APACHE_CERT_CHAIN_PATH.write_text(trust_store_pem)

            self.stdout.write('Finished with preparation.')

            script = SCRIPT_WIZARD_RESTORE

            script_path = Path(script).resolve()

            if not script_path.exists():
                err_msg = f'State bump script not found: {script_path}'
                raise FileNotFoundError(err_msg)
            if not script_path.is_file():
                err_msg = f'The script path {script_path} is not a valid file.'
                raise ValueError(err_msg)

            command = ['sudo', str(script_path)]

            result = subprocess.run(command, capture_output=True, text=True, check=True)  # noqa: S603

            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, str(script_path))

            self.stdout.write('Restoration successful.')
            sha256_fingerprint = active_tls.credential.get_certificate().fingerprint(hashes.SHA256())
            formatted = ':'.join(f'{b:02X}' for b in sha256_fingerprint)
            self.stdout.write(f'TLS SHA256 fingerprint: {(formatted)}')

        except (ProgrammingError, OperationalError):
            error_msg = _('Appversion table not found. DB probably not initialized')
            self.stdout.write(self.style.ERROR(error_msg))

        except ObjectDoesNotExist:
            error_msg = _('TLS cert not found in DB')
            self.stdout.write(self.style.ERROR(error_msg))
