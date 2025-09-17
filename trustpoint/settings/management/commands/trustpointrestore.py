"""Management command to restore the Trustpoint container (Nginx TLS + wizard)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.conf import settings as django_settings
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand
from django.db.utils import OperationalError, ProgrammingError
from django.utils.translation import gettext as _
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.views import NGINX_CERT_CHAIN_PATH, NGINX_CERT_PATH, NGINX_KEY_PATH, SCRIPT_WIZARD_RESTORE

from settings.models import AppVersion

if TYPE_CHECKING:
    from typing import Any



class Command(BaseCommand):
    """A Django management command to restore the Trustpoint container.

    This restores the Nginx TLS certificate and the wizard state.
    It is unrelated to the restore of a database backup.
    """

    help = 'Restores Trustpoint container.'

    def handle(self, **_options: Any) -> None:
        """Entrypoint for the command."""
        self.restore_trustpoint()

    def restore_trustpoint(self) -> None:
        """Restore trustpoint (Nginx TLS and wizard state) if DB is there."""
        current = django_settings.APP_VERSION
        try:
            self.stdout.write('Starting with restoration')
            app_version = AppVersion.objects.first()
            if not app_version:
                error_msg = _('Appversion table not found. DB probably not initialized')
                self.stdout.write(self.style.ERROR(error_msg))
                return

            if app_version.version != current:
                error_msg = (f'Appversion in DB {app_version.version} does not match current version {current}. '
                             'Please run the inittrustpoint command before attempting TLS restoration.')
                self.stdout.write(self.style.ERROR(error_msg))
                return

            self.stdout.write('Matching version in database found.')
            self.stdout.write('Extrating tls cert and preparing for restoration of nginx config...')

            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
            tls_server_credential_model = active_tls.credential

            private_key_pem = tls_server_credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = tls_server_credential_model.get_certificate_serializer().as_pem().decode()
            trust_store_pem = tls_server_credential_model.get_certificate_chain_serializer().as_pem().decode()

            NGINX_KEY_PATH.write_text(private_key_pem)
            NGINX_CERT_PATH.write_text(certificate_pem)
            NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)

            self.stdout.write('Finished with preparation.')

            script = SCRIPT_WIZARD_RESTORE

            self.stdout.write('1')

            script_path = Path(script).resolve()

            if not script_path.exists():
                err_msg = f'State bump script not found: {script_path}'
                raise FileNotFoundError(err_msg)
            if not script_path.is_file():
                err_msg = f'The script path {script_path} is not a valid file.'
                raise ValueError(err_msg)
            self.stdout.write('2')
            command = ['sudo', str(script_path)]
            self.stdout.write('5')
            result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
            self.stdout.write(f'Script stdout: {result.stdout}')
            self.stdout.write(f'Script stderr: {result.stderr}')
            self.stdout.write(f'Script return code: {result.returncode}')
            self.stdout.write('4')
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, str(script_path))
            self.stdout.write('3')
            self.stdout.write('Restoration successful.')

        except (ProgrammingError, OperationalError):
            error_msg = _('Appversion table not found. DB probably not initialized')
            self.stdout.write(self.style.ERROR(error_msg))

        except ObjectDoesNotExist:
            error_msg = _('TLS cert not found in DB')
            self.stdout.write(self.style.ERROR(error_msg))
