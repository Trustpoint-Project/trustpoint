"""Django management command for adding issuing CA test data."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.management.base import BaseCommand

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Adds a Root CA and three issuing CAs to the database."""

    help = 'Adds a RSA 2048 / SHA256 Root CA and an issuing CAs to the database for testing purposes.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Adds a Root CA and an issuing CAs to the database."""
        rsa2_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_root, _ = self.create_root_ca(
            'Root-CA RSA-2048-SHA256 - Test - Fixture', private_key=rsa2_root_ca_key, hash_algorithm=hashes.SHA256()
        )
        rsa2_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa2_issuing_ca_key,
            issuer_cn='Root-CA RSA-2048-SHA256 - Test - Fixture',
            subject_cn='Issuing CA A - Test - Fixture',
            hash_algorithm=hashes.SHA256(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa2_issuing_ca,
            private_key=rsa2_issuing_ca_key,
            chain=[rsa2_root],
            unique_name='issuing-ca-a-test-fixture',
        )
