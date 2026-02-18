"""This module defines a Django management command to generate a TLS credential for use in the dev environment."""

import ipaddress

from cryptography.hazmat.primitives import hashes
from django.core.management.base import BaseCommand, CommandParser
from management.nginx_paths import NGINX_CERT_CHAIN_PATH, NGINX_CERT_PATH, NGINX_KEY_PATH, NGINX_PATH
from pki.models.credential import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.tls_credential import TlsServerCredentialGenerator

from trustpoint.logger import LoggerMixin


class Command(BaseCommand, LoggerMixin):
    """[DEV ONLY]: A Django management command to create and store tls credential in dev env."""

    help = 'Creates TLS cert'

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--write_out', action='store_true', help=f'Tls cred will be write to {NGINX_PATH}.')

    def handle(self, **options: dict[str, str]) -> None:
        """Entrypoint for the command.

        Args:
            **options: A variable-length argument.
        """
        self.tls_cred(**options)

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout.

        Parameters
        ----------
        message : str
            The message to log and print.
        level : str
            The logging level ('info', 'warning', 'error', etc.).
        """
        # Log the message
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(message)

        # Write to stdout
        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'success':
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(message)

    def tls_cred(self, **options: dict[str, str]) -> None:
        """Generate a new TLS Server Credential and set it as the active credential in Trustpoint.

        For use in the non-NGINX development environment.
        """
        try:
            self.log_and_stdout('Generating TLS Server Credential...')
            # Generate the TLS Server Credential
            generator = TlsServerCredentialGenerator(
                ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')],
                ipv6_addresses=[],
                domain_names=[],
            )
            tls_server_credential = generator.generate_tls_server_credential()
            self.log_and_stdout('TLS Server Credential generated successfully')
            self.log_and_stdout('Saving credential to database...')

            trustpoint_tls_server_credential = CredentialModel.save_credential_serializer(
                credential_serializer=tls_server_credential,
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
            )

            active_tls, created = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
            self.log_and_stdout(f'ActiveTrustpoint TLS record {"created" if created else "retrieved"}')
            active_tls.credential = trustpoint_tls_server_credential
            active_tls.save()
            self.log_and_stdout('Credential saved to database successfully')

            private_key_pem = active_tls.credential.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = active_tls.credential.get_certificate_serializer().as_pem().decode()
            trust_store_pem = active_tls.credential.get_certificate_chain_serializer().as_pem().decode()

            if options.get('write_out'):
                self.log_and_stdout(f'Writing TLS files to {NGINX_PATH}...')
                NGINX_KEY_PATH.write_text(private_key_pem)
                self.log_and_stdout(f'Written private key to: {NGINX_KEY_PATH}')
                NGINX_CERT_PATH.write_text(certificate_pem)
                self.log_and_stdout(f'Written certificate to: {NGINX_CERT_PATH}')

                # Only write chain file if there's actually a chain (not empty)
                if trust_store_pem.strip():
                    NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)
                    self.log_and_stdout(f'Written certificate chain to: {NGINX_CERT_CHAIN_PATH}')
                elif NGINX_CERT_CHAIN_PATH.exists():
                    # Remove chain file if it exists but chain is empty
                    NGINX_CERT_CHAIN_PATH.unlink()
                    self.log_and_stdout(f'Removed empty certificate chain file: {NGINX_CERT_CHAIN_PATH}')

            sha256_fingerprint = active_tls.credential.get_certificate().fingerprint(hashes.SHA256())
            formatted = ':'.join(f'{b:02X}' for b in sha256_fingerprint)
            self.log_and_stdout(f'TLS SHA256 fingerprint: {formatted}', level='success')

        except Exception as e:
            self.log_and_stdout(f'TLS credential generation failed: {e}', level='error')
            raise
