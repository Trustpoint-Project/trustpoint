"""Django management command for creating the Management CA."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.management.base import BaseCommand

from pki.models import CaModel

from .base_commands import CertificateCreationCommandMixin

MANAGEMENT_CA_NAME = 'Management CA'


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Create the local, backend-managed Management CA."""

    help = 'Creates the Management CA if it does not already exist.'

    def handle(self, *_args: object, **_options: object) -> None:
        """Create a NIST P-256 root CA using the configured crypto backend."""
        if CaModel.objects.filter(unique_name=MANAGEMENT_CA_NAME).exists():
            self.stdout.write(f'{MANAGEMENT_CA_NAME} already exists.')
            return

        private_key = self.create_backend_ec_private_key(
            alias='management-ca',
            curve=ec.SECP256R1(),
        )
        certificate, _ = self.create_root_ca(
            MANAGEMENT_CA_NAME,
            private_key=private_key,
            hash_algorithm=hashes.SHA256(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=certificate,
            chain=[],
            private_key=private_key,
            unique_name=MANAGEMENT_CA_NAME,
            ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
        )

        self.stdout.write(self.style.SUCCESS(f'Created {MANAGEMENT_CA_NAME}.'))
