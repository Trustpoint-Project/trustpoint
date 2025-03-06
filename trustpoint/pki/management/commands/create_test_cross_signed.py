"""Something."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pki.models import CertificateModel

from .base_commands import CertificateCreationCommandMixin
from django.core.management.base import BaseCommand


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def handle(self, *args, **kwargs) -> None:
        root_1, root_1_key = self.create_root_ca('Root CA A')
        root_2, root_2_key = self.create_root_ca('Root CA B')

        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA A', 'Issuing CA')
        issuing_2, issuing_2_key = self.create_issuing_ca(root_2_key, 'Root CA B', 'Issuing CA', issuing_1_key)

        ee_1, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE A1')
        ee_2, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE A2')
        ee_3, _ = self.create_ee(issuing_2_key, 'Issuing CA', 'EE B1')
        ee_4, _ = self.create_ee(issuing_2_key, 'Issuing CA', 'EE B1')

        CertificateModel.save_certificate(root_1)
        CertificateModel.save_certificate(root_2)
        CertificateModel.save_certificate(issuing_1)
        CertificateModel.save_certificate(issuing_2)
        CertificateModel.save_certificate(ee_1)
        CertificateModel.save_certificate(ee_2)
        CertificateModel.save_certificate(ee_3)
        CertificateModel.save_certificate(ee_4)
