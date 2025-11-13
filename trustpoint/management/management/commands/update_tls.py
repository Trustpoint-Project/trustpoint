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
from setup_wizard.views import (
    APACHE_CERT_CHAIN_PATH,
    APACHE_CERT_PATH,
    APACHE_KEY_PATH,
    SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL,
)

if TYPE_CHECKING:
    from typing import Any

class Command(BaseCommand):
    """A Django management command to restore the Trustpoint container.

    This restores the Apache TLS certificate.
    """

    help = 'Updates Apache TLS config to the current active TLS server credential.'

    def handle(self, **options: Any) -> None:
        """Entrypoint for the command."""
        try:
            self.stdout.write('Extrating tls cert and preparing for update of apache config...')

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
        APACHE_CERT_CHAIN_PATH.write_text(trust_store_pem)

        self.stdout.write('Finished with preparation.')

        script = SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL

        script_path = Path(script).resolve()

        if not script_path.exists():
            err_msg = f'TLS update script not found: {script_path}'
            raise FileNotFoundError(err_msg)
        if not script_path.is_file():
            err_msg = f'The script path {script_path} is not a valid file.'
            raise ValueError(err_msg)

        command = ['sudo', str(script_path)]

        result = subprocess.run(command, capture_output=True, text=True, check=True)  # noqa: S603

        if result.returncode != 0:
            self.stdout.write(self.style.ERROR(result.stderr))
            self.stdout.write(result.stdout)
            raise subprocess.CalledProcessError(result.returncode, str(script_path))

        self.stdout.write('Apache TLS credential update successful.')
        sha256_fingerprint = active_tls.credential.get_certificate().fingerprint(hashes.SHA256())
        formatted = ':'.join(f'{b:02X}' for b in sha256_fingerprint)
        self.stdout.write(f'TLS SHA256 fingerprint: {(formatted)}')
