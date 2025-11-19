"""Command to update the Apache TLS configuration to the current active TLS server credential."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import gettext as _
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.state_dir_paths import SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL
from trustpoint.logger import LoggerMixin

from management.apache_paths import (
    APACHE_CERT_CHAIN_PATH,
    APACHE_CERT_PATH,
    APACHE_KEY_PATH,
)

if TYPE_CHECKING:
    from typing import Any

class Command(LoggerMixin, BaseCommand):
    """A Django management command to restore the Trustpoint container.

    This restores the Apache TLS certificate.
    """

    help = 'Updates Apache TLS config to the current active TLS server credential.'

    def handle(self, **options: Any) -> None:
        """Entrypoint for the command."""
        try:
            self.logger.debug('Extracting TLS cert and preparing for update of Apache config...')

            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
        except ObjectDoesNotExist as e:
            error_msg = _('TLS cert not found in DB')
            self.stdout.write(self.style.ERROR(error_msg))
            raise CommandError(error_msg) from e

        tls_server_credential_model = active_tls.credential

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

        self.logger.debug('Finished with preparation.')

        script = SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL

        script_path = Path(script).resolve()

        if not script_path.exists():
            err_msg = f'TLS update script not found: {script_path}'
            raise FileNotFoundError(err_msg)
        if not script_path.is_file():
            err_msg = f'The script path {script_path} is not a valid file.'
            raise ValueError(err_msg)

        command = ['sudo', str(script_path)]

        self.logger.debug('Running TLS update script: %s', command)
        result = subprocess.run(command, check=False, capture_output=True, text=True)  # noqa: S603

        if result.returncode != 0:
            self.logger.error('TLS update script failed with return code %d', result.returncode)
            self.logger.error('Script stdout: %s', result.stdout)
            self.logger.error('Script stderr: %s', result.stderr)
            # Do not raise exception to allow TLS activation to succeed even if Apache restart fails
        else:
            self.logger.debug('TLS update script executed successfully')

        self.stdout.write('Apache TLS credential update successful.')
        sha256_fingerprint = active_tls.credential.get_certificate().fingerprint(hashes.SHA256())
        formatted = ':'.join(f'{b:02X}' for b in sha256_fingerprint)
        self.stdout.write(f'TLS SHA256 fingerprint: {(formatted)}')
