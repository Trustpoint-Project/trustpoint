# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Command to update the Nginx TLS configuration to the current active TLS server credential."""

from __future__ import annotations

import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.translation import gettext as _

from management.nginx_paths import (
    NGINX_CERT_CHAIN_PATH,
    NGINX_CERT_PATH,
    NGINX_KEY_PATH,
)
from management.tls_files import write_tls_pem_files
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from trustpoint.logger import LoggerMixin

SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL = Path('/etc/trustpoint/wizard/update_tls.sh')


class Command(LoggerMixin, BaseCommand):
    """A Django management command to restore the Trustpoint container.

    This restores the Nginx TLS certificate.
    """

    help = 'Updates Nginx TLS config to the current active TLS server credential.'

    @transaction.atomic
    def handle(self, **_options: object) -> None:
        """Entrypoint for the command."""
        try:
            self.logger.debug('Extracting TLS cert and preparing for update of Nginx config...')

            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.select_for_update().get(id=1)
        except ObjectDoesNotExist as e:
            error_msg = _('TLS cert not found in DB')
            self.stdout.write(self.style.ERROR(error_msg))
            raise CommandError(error_msg) from e

        tls_server_credential_model = active_tls.credential
        if tls_server_credential_model is None:
            error_msg = _('Active TLS server credential has no credential set')
            self.stdout.write(self.style.ERROR(error_msg))
            raise CommandError(error_msg)

        script_path = SCRIPT_UPDATE_TLS_SERVER_CREDENTIAL.resolve()

        if not script_path.exists():
            err_msg = f'TLS update script not found: {script_path}'
            raise FileNotFoundError(err_msg)
        if not script_path.is_file():
            err_msg = f'The script path {script_path} is not a valid file.'
            raise ValueError(err_msg)

        paths = (NGINX_KEY_PATH, NGINX_CERT_PATH, NGINX_CERT_CHAIN_PATH)
        previous_files = {path: path.read_bytes() if path.is_file() else None for path in paths}
        try:
            write_tls_pem_files(
                tls_server_credential_model,
                key_path=NGINX_KEY_PATH,
                cert_path=NGINX_CERT_PATH,
                chain_path=NGINX_CERT_CHAIN_PATH,
            )
            command = ['sudo', str(script_path)]
            result = subprocess.run(command, check=False, capture_output=True, text=True)  # noqa: S603
            if result.returncode != 0:
                self.logger.error('TLS update script failed: %s', result.stderr)
                message = 'Nginx TLS credential update failed.'
                raise CommandError(message)  # noqa: TRY301
        except Exception:
            for path, content in previous_files.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(content)
            raise

        self.stdout.write('Nginx TLS credential update successful.')
        sha256_fingerprint = tls_server_credential_model.get_certificate().fingerprint(hashes.SHA256())
        formatted = ':'.join(f'{b:02X}' for b in sha256_fingerprint)
        self.stdout.write(f'TLS SHA256 fingerprint: {(formatted)}')
