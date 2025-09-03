"""Django management command for adding issuing CA test data."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.management.base import BaseCommand

from trustpoint.logger import LoggerMixin

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, BaseCommand, LoggerMixin):
    """Adds a Root CA and three issuing CAs to the database."""

    help = 'Adds a Root CA and three issuing CAs to the database.'

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout.

        Parameters
        ----------
        message : str
            The message to log and print.
        level : str
            The logging level ('info', 'warning', 'error', etc.).
        """
        # Log the message
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(message)

        # Write to stdout
        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'info':
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(message)

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Adds a Root CA and three issuing CAs to the database."""
        self.log_and_stdout('Creating RSA-2048 Root CA and Issuing CA A...')
        rsa2_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_root, _ = self.create_root_ca(
            'Root-CA RSA-2048-SHA256', private_key=rsa2_root_ca_key, hash_algorithm=hashes.SHA256()
        )
        rsa2_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa2_issuing_ca_key,
            issuer_cn='Root-CA RSA-2048-SHA256',
            subject_cn='Issuing CA A',
            hash_algorithm=hashes.SHA256(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa2_issuing_ca,
            private_key=rsa2_issuing_ca_key,
            chain=[rsa2_root],
            unique_name='issuing-ca-a',
        )

        self.log_and_stdout('Creating RSA-3072 Root CA and Issuing CA B...')
        rsa3_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        rsa3_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        rsa3_root, _ = self.create_root_ca(
            'Root-CA RSA-3072-SHA256', private_key=rsa3_root_ca_key, hash_algorithm=hashes.SHA256()
        )
        rsa3_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa3_root_ca_key,
            private_key=rsa3_issuing_ca_key,
            issuer_cn='Root-CA RSA-3072-SHA256',
            subject_cn='Issuing CA B',
            hash_algorithm=hashes.SHA256(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa3_issuing_ca,
            private_key=rsa3_issuing_ca_key,
            chain=[rsa3_root],
            unique_name='issuing-ca-b',
        )

        self.log_and_stdout('Creating RSA-4096 Root CA and Issuing CA C...')
        rsa4_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        rsa4_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        rsa4_root, _ = self.create_root_ca(
            'Root-CA RSA-4096-SHA256', private_key=rsa4_root_ca_key, hash_algorithm=hashes.SHA512()
        )
        rsa4_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa4_root_ca_key,
            private_key=rsa4_issuing_ca_key,
            issuer_cn='Root-CA RSA-4096-SHA256',
            subject_cn='Issuing CA C',
            hash_algorithm=hashes.SHA512(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa4_issuing_ca,
            private_key=rsa4_issuing_ca_key,
            chain=[rsa4_root],
            unique_name='issuing-ca-c',
        )

        self.log_and_stdout('Creating SECP256R1 Root CA and Issuing CA D...')
        ecc1_root_ca_key = ec.generate_private_key(curve=ec.SECP256R1())
        ecc1_issuing_ca_key = ec.generate_private_key(curve=ec.SECP256R1())
        ecc1_root, _ = self.create_root_ca(
            'Root-CA SECP256R1-SHA256', private_key=ecc1_root_ca_key, hash_algorithm=hashes.SHA256()
        )
        ecc1_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc1_root_ca_key,
            private_key=ecc1_issuing_ca_key,
            issuer_cn='Root-CA SECP256R1-SHA256',
            subject_cn='Issuing CA D',
            hash_algorithm=hashes.SHA256(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=ecc1_issuing_ca,
            private_key=ecc1_issuing_ca_key,
            chain=[ecc1_root],
            unique_name='issuing-ca-d',
        )

        self.log_and_stdout('Creating SECP384R1 Root CA and Issuing CA E...')
        ecc2_root_ca_key = ec.generate_private_key(curve=ec.SECP384R1())
        ecc2_issuing_ca_key = ec.generate_private_key(curve=ec.SECP384R1())
        ecc2_root, _ = self.create_root_ca(
            'Root-CA SECP384R1-SHA256', private_key=ecc2_root_ca_key, hash_algorithm=hashes.SHA256()
        )
        ecc2_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc2_root_ca_key,
            private_key=ecc2_issuing_ca_key,
            issuer_cn='Root-CA SECP384R1-SHA256',
            subject_cn='Issuing CA E',
            hash_algorithm=hashes.SHA256(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=ecc2_issuing_ca,
            private_key=ecc2_issuing_ca_key,
            chain=[ecc2_root],
            unique_name='issuing-ca-e',
        )

        self.log_and_stdout('Creating SECP521R1 Root CA and Issuing CA F...')
        ecc3_root_ca_key = ec.generate_private_key(curve=ec.SECP521R1())
        ecc3_issuing_ca_key = ec.generate_private_key(curve=ec.SECP521R1())
        ecc3_root, _ = self.create_root_ca(
            'Root-CA SECP521R1-SHA256', private_key=ecc3_root_ca_key, hash_algorithm=hashes.SHA3_512()
        )
        ecc3_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc3_root_ca_key,
            private_key=ecc3_issuing_ca_key,
            issuer_cn='Root-CA SECP521R1-SHA256',
            subject_cn='Issuing CA F',
            hash_algorithm=hashes.SHA3_512(),
        )
        self.save_issuing_ca(
            issuing_ca_cert=ecc3_issuing_ca,
            private_key=ecc3_issuing_ca_key,
            chain=[ecc3_root],
            unique_name='issuing-ca-f',
        )

        self.log_and_stdout('All issuing CAs have been created successfully!')