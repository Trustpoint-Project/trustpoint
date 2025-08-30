"""This module defines a Django management command to generate a TLS credential for use in the dev environment."""

import ipaddress
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from django.core.management.base import BaseCommand, CommandParser
from pki.models.credential import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.tls_credential import TlsServerCredentialGenerator
from setup_wizard.views import APACHE_PATH

APACHE_KEY_PATH = APACHE_PATH / Path('apache-tls-server-key.key')
APACHE_CERT_PATH = APACHE_PATH / Path('apache-tls-server-cert.pem')
APACHE_CERT_CHAIN_PATH = APACHE_PATH / Path('apache-tls-server-cert-chain.pem')


class Command(BaseCommand):
    """[DEV ONLY]: A Django management command to create and store tls credential in dev env."""

    help = 'Creates TLS cert'

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--write_out', action='store_true', help=f'Tls cred will be write to {APACHE_PATH}.')

    def handle(self, **options: dict[str, str]) -> None:
        """Entrypoint for the command.

        Args:
            **options: A variable-length argument.
        """
        self.tls_cred(**options)

    def tls_cred(self, **options: dict[str, str]) -> None:
            """Generate a new TLS Server Credential and set it as the active credential in Trustpoint.

            For use in the non-Apache development environment.
            """
            try:
                # Generate the TLS Server Credential
                generator = TlsServerCredentialGenerator(
                    ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')],
                    ipv6_addresses=[],
                    domain_names=[],
                )
                tls_server_credential = generator.generate_tls_server_credential()

                trustpoint_tls_server_credential = CredentialModel.save_credential_serializer(
                    credential_serializer=tls_server_credential,
                    credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
                )

                active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
                active_tls.credential = trustpoint_tls_server_credential
                active_tls.save()

                private_key_pem = active_tls.credential.get_private_key_serializer().as_pkcs8_pem().decode()
                certificate_pem = active_tls.credential.get_certificate_serializer().as_pem().decode()
                trust_store_pem = active_tls.credential.get_certificate_chain_serializer().as_pem().decode()

                if options.get('write_out'):
                    APACHE_KEY_PATH.write_text(private_key_pem)
                    APACHE_CERT_PATH.write_text(certificate_pem)
                    APACHE_CERT_CHAIN_PATH.write_text(trust_store_pem)


                sha256_fingerprint = active_tls.credential.get_certificate().fingerprint(hashes.SHA256())
                formatted = ':'.join(f'{b:02X}' for b in sha256_fingerprint)
                self.stdout.write(f'TLS SHA256 fingerprint: {(formatted)}')


            except Exception as e:  # noqa: BLE001
                print(f'tls cred exeption {e}')  # noqa: T201
