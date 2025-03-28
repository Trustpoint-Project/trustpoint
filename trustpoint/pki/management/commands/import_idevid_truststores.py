"""Imports Truststores from specific PEM files in tests/data/idevid_hierarchies."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.core.management.base import BaseCommand
from pki.models import CertificateModel, TruststoreModel, TruststoreOrderModel


class Command(BaseCommand):
    """Imports Truststores from specific PEM files in tests/data/idevid_hierarchies."""

    help = 'Imports Truststores from specific PEM files in tests/data/idevid_hierarchies'

    TRUSTSTORE_RELATIVE_PATHS = MappingProxyType(
        {
            'ecc1/ecc1_chain.pem': 'EC-256',
            'ecc2/ecc2_chain.pem': 'EC-283',
            'ecc3/ecc3_chain.pem': 'EC-570',
            'rsa2/rsa2_chain.pem': 'RSA-2048',
            'rsa3/rsa3_chain.pem': 'RSA-3072',
            'rsa4/rsa4_chain.pem': 'RSA-4096',
        }
    )

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Execute the command."""
        base_path = Path(__file__).resolve().parent.joinpath('../../../../tests/data/idevid_hierarchies').resolve()

        for relative_path, unique_name in self.TRUSTSTORE_RELATIVE_PATHS.items():
            pem_path = Path(base_path / relative_path)

            if not Path.exists(pem_path):
                self.stderr.write(self.style.ERROR(f'File not found: {pem_path}'))
                continue

            try:
                with pem_path.open('rb') as f:
                    pem_content = f.read()

                certificates = x509.load_pem_x509_certificates(pem_content)

                self._save_trust_store(
                    unique_name=f'idevid-truststore-{unique_name}',
                    intended_usage=TruststoreModel.IntendedUsage.IDEVID,
                    certificates=certificates,
                )

                self.stdout.write(self.style.SUCCESS(f'Imported Truststore: {unique_name}'))
            except Exception as e:  # noqa: BLE001
                self.stderr.write(self.style.ERROR(f'Failed to import {pem_path}: {e}'))

    @staticmethod
    def _save_trust_store(
        unique_name: str, intended_usage: TruststoreModel.IntendedUsage, certificates: list[x509.Certificate]
    ) -> TruststoreModel:
        saved_certs = []

        for certificate in certificates:
            sha256_fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
            try:
                saved_certs.append(CertificateModel.objects.get(sha256_fingerprint=sha256_fingerprint))
            except CertificateModel.DoesNotExist:
                saved_certs.append(CertificateModel.save_certificate(certificate))

        trust_store_model = TruststoreModel(unique_name=unique_name, intended_usage=intended_usage)
        trust_store_model.save()

        for number, certificate in enumerate(saved_certs):
            TruststoreOrderModel.objects.create(order=number, certificate=certificate, trust_store=trust_store_model)

        return trust_store_model
