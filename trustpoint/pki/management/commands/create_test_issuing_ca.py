"""Command to create a test Issuing CA and some example end-entity certificates."""

from __future__ import annotations

import random

from cryptography import x509
from django.core.management.base import BaseCommand

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Executes the command."""
        key_usage_extension = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            decipher_only=False,
            encipher_only=False,
        )

        root_1, root_1_key = self.create_root_ca('root_ca')
        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'root_ca', 'issuing_ca', validity_days=50)

        self.store_issuing_ca(issuing_1, [root_1], issuing_1_key, 'issuing_ca.p12')
        self.save_issuing_ca(issuing_1, [root_1], issuing_1_key, 'issuing_ca')

        ee_certs = {}
        ee_keys = {}
        for i in range(10):
            random_integer = random.randint(20, 80)  # noqa: S311
            sign = random.choice([1, -1])  # noqa: S311
            validity_days = random_integer * sign
            ee, key = self.create_ee(
                issuer_private_key=issuing_1_key,
                issuer_name=issuing_1.subject,
                subject_name=f'EE {i}',
                extensions=[(key_usage_extension, False)],
                validity_days=validity_days,
            )
            ee_certs[f'ee{i}'] = ee
            ee_keys[f'key{i}'] = key

        self.store_ee_certs(ee_certs)
        self.store_ee_keys(ee_keys)
        self.save_ee_certs(ee_certs)

        self.create_csr(10)
