"""This module defines a Django management command to delete all existing notifications."""

import ipaddress
from pathlib import Path
from typing import Any

from django.conf import settings as django_settings
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db.models.signals import post_migrate
from django.db.utils import OperationalError, ProgrammingError
from pki.models.credential import CredentialModel
from pki.models.truststore import (
    ActiveTrustpointTlsServerCredentialModel,
    TrustpointTlsServerCredentialModel,
)
from settings.models import AppVersion
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
            """Update app version if pyproject.toml is different than verison in db."""
            try:
                # Generate the TLS Server Credential
                generator = TlsServerCredentialGenerator(
                    ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')],
                    ipv6_addresses=[],
                    domain_names=[],
                )
                tls_server_credential = generator.generate_tls_server_credential()

                tls_server_credential_model = CredentialModel.save_credential_serializer(
                    credential_serializer=tls_server_credential,
                    credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
                )

                trustpoint_tls_server_credential, _ = TrustpointTlsServerCredentialModel.objects.get_or_create(
                    certificate=tls_server_credential_model.certificate,
                    defaults={'private_key_pem': tls_server_credential_model.get_private_key_serializer().as_pkcs8_pem()},
                )

                active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
                active_tls.credential = trustpoint_tls_server_credential
                active_tls.save()

                # trustpoint_tls_server_credential_model = CredentialModel.objects.get(
                #     credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
                # )

                # private_key_pem = trustpoint_tls_server_credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
                # certificate_pem = trustpoint_tls_server_credential_model.get_certificate_serializer().as_pem().decode()
                # trust_store_pem = trustpoint_tls_server_credential_model.get_certificate_chain_serializer().as_pem().decode()

                # APACHE_KEY_PATH.write_text(private_key_pem)
                # APACHE_CERT_PATH.write_text(certificate_pem)
                # APACHE_CERT_CHAIN_PATH.write_text(trust_store_pem)
            except Exception as e:  # noqa: BLE001
                print(f'tls cred exeption {e}')  # noqa: T201
