"""Management command for generating a long test PKI chain."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from django.core.management.base import BaseCommand
from pki.models import CertificateModel

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for generating a long test PKI chain."""

    help = 'Generate a long certificate chain with 4 Intermediate CAs.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Executes the command."""
        root_1, root_1_key = self.create_root_ca('Root CA A')

        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA A', 'Intermediate CA A')
        issuing_2, issuing_2_key = self.create_issuing_ca(issuing_1_key, 'Intermediate CA A', 'Intermediate CA B')
        issuing_3, issuing_3_key = self.create_issuing_ca(issuing_2_key, 'Intermediate CA B', 'Intermediate CA C')
        issuing_4, issuing_4_key = self.create_issuing_ca(issuing_3_key, 'Intermediate CA C', 'Intermediate CA D')
        issuing_5, issuing_5_key = self.create_issuing_ca(issuing_4_key, 'Intermediate CA D', 'Issuing CA')

        ee_1, _ee_key = self.create_ee(issuing_5_key, 'Issuing CA', 'EE A1')

        p12 = pkcs12.serialize_key_and_certificates(
            b'my p12',
            issuing_5_key,
            issuing_5,
            [root_1, issuing_1, issuing_2, issuing_3, issuing_4],
            encryption_algorithm=BestAvailableEncryption(b'testing321'),
        )

        with Path(Path(__file__).parent.parent.parent / 'p12.p12').open('wb') as f:
            f.write(p12)
        CertificateModel.save_certificate(root_1)
        CertificateModel.save_certificate(issuing_1)
        CertificateModel.save_certificate(issuing_2)
        CertificateModel.save_certificate(issuing_3)
        CertificateModel.save_certificate(issuing_4)
        CertificateModel.save_certificate(issuing_5)
        CertificateModel.save_certificate(ee_1)
