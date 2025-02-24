"""Django management command for adding issuing CA test data."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.management.base import BaseCommand

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Adds a Root CA and three issuing CAs to the database."""

    help = 'Adds a Root CA and three issuing CAs to the database.'

    def handle(self, *_args: tuple, **_kwargs: dict) -> None:
        """Adds a Root CA and three issuing CAs to the database."""
        rsa2_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_root, _ = self.create_root_ca(
            'Root-CA RSA-2048-SHA256', private_key=rsa2_root_ca_key, hash_algorithm=hashes.SHA256())
        rsa2_issuing_ca, rsa2_issuing_ca_key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa2_issuing_ca_key,
            issuer_cn='Root-CA RSA-2048-SHA256',
            subject_cn='Issuing CA A',
            hash_algorithm=hashes.SHA256())
        self.save_issuing_ca(
            issuing_ca_cert=rsa2_issuing_ca,
            private_key=rsa2_issuing_ca_key,
            chain=[rsa2_root],
            unique_name='issuing-ca-a')

        rsa3_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        rsa3_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        rsa3_root, _ = self.create_root_ca(
            'Root-CA RSA-3072-SHA256', private_key=rsa3_root_ca_key, hash_algorithm=hashes.SHA256())
        rsa3_issuing_ca, rsa3_issuing_ca_key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa3_issuing_ca_key,
            issuer_cn='Root-CA RSA-3072-SHA256',
            subject_cn='Issuing CA B',
            hash_algorithm=hashes.SHA256())
        self.save_issuing_ca(
            issuing_ca_cert=rsa3_issuing_ca,
            private_key=rsa3_issuing_ca_key,
            chain=[rsa3_root],
            unique_name='issuing-ca-b')

        rsa4_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        rsa4_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        rsa4_root, _ = self.create_root_ca(
            'Root-CA RSA-4096-SHA256', private_key=rsa4_root_ca_key, hash_algorithm=hashes.SHA512())
        rsa4_issuing_ca, rsa4_issuing_ca_key = self.create_issuing_ca(
            issuer_private_key=rsa4_root_ca_key,
            private_key=rsa4_issuing_ca_key,
            issuer_cn='Root-CA RSA-4096-SHA256',
            subject_cn='Issuing CA C',
            hash_algorithm=hashes.SHA512())
        self.save_issuing_ca(
            issuing_ca_cert=rsa4_issuing_ca,
            private_key=rsa4_issuing_ca_key,
            chain=[rsa4_root],
            unique_name='issuing-ca-c')

        ecc1_root_ca_key = ec.generate_private_key(curve=ec.SECP256R1())
        ecc1_issuing_ca_key = ec.generate_private_key(curve=ec.SECP256R1())
        ecc1_root, _ = self.create_root_ca(
            'Root-CA SECP256R1-SHA256', private_key=ecc1_root_ca_key, hash_algorithm=hashes.SHA256())
        ecc1_issuing_ca, ecc1_issuing_ca_key = self.create_issuing_ca(
            issuer_private_key=ecc1_root_ca_key,
            private_key=ecc1_issuing_ca_key,
            issuer_cn='Root-CA SECP256R1-SHA256',
            subject_cn='Issuing CA D',
            hash_algorithm=hashes.SHA256())
        self.save_issuing_ca(
            issuing_ca_cert=ecc1_issuing_ca,
            private_key=ecc1_issuing_ca_key,
            chain=[ecc1_root],
            unique_name='issuing-ca-d')

        ecc2_root_ca_key = ec.generate_private_key(curve=ec.SECT283R1())
        ecc2_issuing_ca_key = ec.generate_private_key(curve=ec.SECT283R1())
        ecc2_root, _ = self.create_root_ca(
            'Root-CA SECT283R1-SHA256', private_key=ecc2_root_ca_key, hash_algorithm=hashes.SHA256())
        ecc2_issuing_ca, ecc2_issuing_ca_key = self.create_issuing_ca(
            issuer_private_key=ecc2_root_ca_key,
            private_key=ecc2_issuing_ca_key,
            issuer_cn='Root-CA SECT283R1-SHA256',
            subject_cn='Issuing CA E',
            hash_algorithm=hashes.SHA256())
        self.save_issuing_ca(
            issuing_ca_cert=ecc2_issuing_ca,
            private_key=ecc2_issuing_ca_key,
            chain=[ecc2_root],
            unique_name='issuing-ca-e')

        ecc3_root_ca_key = ec.generate_private_key(curve=ec.SECT571R1())
        ecc3_issuing_ca_key = ec.generate_private_key(curve=ec.SECT571R1())
        ecc3_root, _ = self.create_root_ca(
            'Root-CA SECT571R1-SHA256', private_key=ecc3_root_ca_key, hash_algorithm=hashes.SHA3_512())
        ecc3_issuing_ca, ecc3_issuing_ca_key = self.create_issuing_ca(
            issuer_private_key=ecc3_root_ca_key,
            private_key=ecc3_issuing_ca_key,
            issuer_cn='Root-CA SECT571R1-SHA256',
            subject_cn='Issuing CA F',
            hash_algorithm=hashes.SHA3_512())
        self.save_issuing_ca(
            issuing_ca_cert=ecc3_issuing_ca,
            private_key=ecc3_issuing_ca_key,
            chain=[ecc3_root],
            unique_name='issuing-ca-f')
