"""This module defines a Django management command to generate a TLS credential for use in the dev environment."""

import ipaddress
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand
from pki.models.credential import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.tls_credential import TlsServerCredentialGenerator

APACHE_PATH = Path(__file__).parent.parent.parent / 'docker/trustpoint/apache/tls'
APACHE_KEY_PATH = APACHE_PATH / Path('apache-tls-server-key.key')
APACHE_CERT_PATH = APACHE_PATH / Path('apache-tls-server-cert.pem')
APACHE_CERT_CHAIN_PATH = APACHE_PATH / Path('apache-tls-server-cert-chain.pem')


class Command(BaseCommand):
    """[DEV ONLY]: A Django management command to create and store tls credential in dev env."""

    help = 'Creates TLS cert'

    def handle(self, **options: Any) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            **options: A variable-length argument.
        """
        self.tls_cred()

    def tls_cred(self) -> None:
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

            except Exception as e:  # noqa: BLE001
                print(f'tls cred exeption {e}')  # noqa: T201
