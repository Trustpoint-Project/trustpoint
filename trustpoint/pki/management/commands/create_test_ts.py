"""A."""

from __future__ import annotations

from itertools import product
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pki.models import CertificateModel

from .base_commands import CertificateCreationCommandMixin
from django.core.management.base import BaseCommand
from . import Algorithm


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Just some stuff for manual testing.'

    def handle(self, *args, **kwargs) -> None:
        base_path = Path(__file__).parent.parent.parent.parent.parent.resolve()
        path = base_path / Path('tests/data/certs')

        cert_types = ['root-ca', 'issuing-ca', 'ee']
        names = [f'{algo.value}-{cert_type}' for algo, cert_type in product(Algorithm, cert_types)]
        for name in names:
            cert = path / Path(f'{name}-cert.pem')
            if name.endswith('ee'):
                key = path / Path(f'{name}-key.pem')
                with open(key, 'rb') as f:
                    key_pem = f.read()
                ext_key = serialization.load_pem_private_key(key_pem, password=None)
            else:
                ext_key = None

            with open(cert, 'rb') as f:
                cert_pem = f.read()

            ext_cert = x509.load_pem_x509_certificate(cert_pem)
            CertificateModel.save_certificate(ext_cert)

    print('\nDONE\n')
