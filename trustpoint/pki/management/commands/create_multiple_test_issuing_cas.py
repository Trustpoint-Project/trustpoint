"""Django management command for adding issuing CA test data."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.management.base import BaseCommand
from management.models import KeyStorageConfig
from pki.models import CaModel

from trustpoint.logger import LoggerMixin

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, BaseCommand, LoggerMixin):
    """Adds a Root CA, Intermediate CAs, and Issuing CAs to the database."""

    help = 'Adds a Root CA, Intermediate CAs, and Issuing CAs to the database.'

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

    def get_ca_type_from_storage_config(self) -> CaModel.CaTypeChoice:
        """Determine the CA type based on the crypto storage configuration.

        Returns:
            CaModel.CaTypeChoice: The appropriate CA type.
        """
        try:
            config = KeyStorageConfig.get_config()
            if config.storage_type in [
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM
            ]:
                return CaModel.CaTypeChoice.LOCAL_PKCS11
            return CaModel.CaTypeChoice.LOCAL_UNPROTECTED
        except KeyStorageConfig.DoesNotExist:
            self.log_and_stdout(
                'KeyStorageConfig not found, defaulting to LOCAL_UNPROTECTED',
                level='warning'
            )
            return CaModel.CaTypeChoice.LOCAL_UNPROTECTED

    def generate_empty_crl(
        self,
        ca_cert: x509.Certificate,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        hash_algorithm: hashes.HashAlgorithm = hashes.SHA256(),
        crl_validity_hours: int = 2400,
    ) -> str:
        """Generate an empty CRL for a CA.

        Args:
            ca_cert: The CA certificate.
            private_key: The private key of the CA.
            hash_algorithm: The hash algorithm to use.
            crl_validity_hours: Validity period in hours.

        Returns:
            str: The CRL in PEM format.
        """
        from pki.util.crl import generate_empty_crl  # noqa: PLC0415
        return generate_empty_crl(ca_cert, private_key, hash_algorithm, crl_validity_hours)

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Adds a Root CA and three issuing CAs to the database."""
        # Determine CA type based on storage configuration
        ca_type = self.get_ca_type_from_storage_config()
        self.log_and_stdout(f'Using CA type: {ca_type}')

        self.log_and_stdout('Creating RSA-2048 Root CA, Intermediate CA, and Issuing CA A...')
        rsa2_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_int_ca_key_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_int_ca_key_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_issuing_ca_key_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa2_issuing_ca_key_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_validity_days: int = 7300
        intermediate_validity_days: int = 5475
        issuing_validity_days: int = 3650
        rsa2_root, _ = self.create_root_ca(
            'Root-CA RSA-2048-SHA256',
            private_key=rsa2_root_ca_key,
            hash_algorithm=hashes.SHA256(),
            validity_days=root_validity_days,
            path_length=2,  # Allow 2 non-self-issued intermediate CAs (intermediate + issuing)
        )
        rsa2_root_crl = self.generate_empty_crl(rsa2_root, rsa2_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        rsa2_root_ca = self.save_keyless_ca(
            root_ca_cert=rsa2_root,
            unique_name='root-ca-rsa-2048-sha256',
            crl_pem=rsa2_root_crl,
        )

        rsa2_int_ca_1, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa2_int_ca_key_1,
            issuer_cn='Root-CA RSA-2048-SHA256',
            subject_cn='Intermediate CA A-1',
            hash_algorithm=hashes.SHA256(),
            validity_days=intermediate_validity_days,
            path_length=1,
        )
        rsa2_int_ca_crl = self.generate_empty_crl(rsa2_int_ca_1, rsa2_int_ca_key_1, hashes.SHA256(), crl_validity_hours=intermediate_validity_days * 24)
        rsa2_int_ca_model_1 = self.save_keyless_ca(
            root_ca_cert=rsa2_int_ca_1,
            unique_name='intermediate-ca-a-1',
            crl_pem=rsa2_int_ca_crl,
        )
        rsa2_int_ca_model_1.parent_ca = rsa2_root_ca
        rsa2_int_ca_model_1.save()

        rsa2_int_ca_2, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_root_ca_key,
            private_key=rsa2_int_ca_key_2,
            issuer_cn='Root-CA RSA-2048-SHA256',
            subject_cn='Intermediate CA A-2',
            hash_algorithm=hashes.SHA256(),
            validity_days=intermediate_validity_days,
            path_length=1, 
        )
        rsa2_int_ca_crl_2 = self.generate_empty_crl(rsa2_int_ca_2, rsa2_int_ca_key_2, hashes.SHA256(), crl_validity_hours=intermediate_validity_days * 24)
        rsa2_int_ca_model_2 = self.save_keyless_ca(
            root_ca_cert=rsa2_int_ca_2,
            unique_name='intermediate-ca-a-2',
            crl_pem=rsa2_int_ca_crl_2,
        )
        rsa2_int_ca_model_2.parent_ca = rsa2_root_ca
        rsa2_int_ca_model_2.save()

        rsa2_issuing_ca_1, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_int_ca_key_1,
            private_key=rsa2_issuing_ca_key_1,
            issuer_cn='Intermediate CA A-1',
            subject_cn='Issuing CA A-1',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa2_issuing_ca_1,
            private_key=rsa2_issuing_ca_key_1,
            chain=[rsa2_root, rsa2_int_ca_1],
            unique_name='issuing-ca-a-1',
            ca_type=ca_type,
            parent_ca=rsa2_int_ca_model_1,
        )

        rsa2_issuing_ca_2, _key = self.create_issuing_ca(
            issuer_private_key=rsa2_int_ca_key_2,
            private_key=rsa2_issuing_ca_key_2,
            issuer_cn='Intermediate CA A-2',
            subject_cn='Issuing CA A-2',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa2_issuing_ca_2,
            private_key=rsa2_issuing_ca_key_2,
            chain=[rsa2_root, rsa2_int_ca_2],
            unique_name='issuing-ca-a-2',
            ca_type=ca_type,
            parent_ca=rsa2_int_ca_model_2,
        )

        self.log_and_stdout('Creating RSA-3072 Root CA and Issuing CA B...')
        rsa3_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        rsa3_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        rsa3_root, _ = self.create_root_ca(
            'Root-CA RSA-3072-SHA256', private_key=rsa3_root_ca_key, hash_algorithm=hashes.SHA256(), validity_days=root_validity_days
        )
        rsa3_root_crl = self.generate_empty_crl(rsa3_root, rsa3_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        rsa3_root_ca = self.save_keyless_ca(
            root_ca_cert=rsa3_root,
            unique_name='root-ca-rsa-3072-sha256',
            crl_pem=rsa3_root_crl,
        )
        rsa3_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa3_root_ca_key,
            private_key=rsa3_issuing_ca_key,
            issuer_cn='Root-CA RSA-3072-SHA256',
            subject_cn='Issuing CA B',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa3_issuing_ca,
            private_key=rsa3_issuing_ca_key,
            chain=[rsa3_root],
            unique_name='issuing-ca-b',
            ca_type=ca_type,
            parent_ca=rsa3_root_ca,
        )

        self.log_and_stdout('Creating RSA-4096 Root CA and Issuing CA C...')
        rsa4_root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        rsa4_issuing_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        rsa4_root, _ = self.create_root_ca(
            'Root-CA RSA-4096-SHA256', private_key=rsa4_root_ca_key, hash_algorithm=hashes.SHA512(), validity_days=root_validity_days
        )
        rsa4_root_crl = self.generate_empty_crl(rsa4_root, rsa4_root_ca_key, hashes.SHA512(), crl_validity_hours=root_validity_days * 24)
        rsa4_root_ca = self.save_keyless_ca(
            root_ca_cert=rsa4_root,
            unique_name='root-ca-rsa-4096-sha256',
            crl_pem=rsa4_root_crl,
        )
        rsa4_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=rsa4_root_ca_key,
            private_key=rsa4_issuing_ca_key,
            issuer_cn='Root-CA RSA-4096-SHA256',
            subject_cn='Issuing CA C',
            hash_algorithm=hashes.SHA512(),
            validity_days=issuing_validity_days,
        )
        self.save_issuing_ca(
            issuing_ca_cert=rsa4_issuing_ca,
            private_key=rsa4_issuing_ca_key,
            chain=[rsa4_root],
            unique_name='issuing-ca-c',
            ca_type=ca_type,
            parent_ca=rsa4_root_ca,
        )

        self.log_and_stdout('Creating SECP256R1 Root CA and Issuing CA D...')
        ecc1_root_ca_key = ec.generate_private_key(curve=ec.SECP256R1())
        ecc1_issuing_ca_key = ec.generate_private_key(curve=ec.SECP256R1())
        ecc1_root, _ = self.create_root_ca(
            'Root-CA SECP256R1-SHA256', private_key=ecc1_root_ca_key, hash_algorithm=hashes.SHA256(), validity_days=root_validity_days
        )
        ecc1_root_crl = self.generate_empty_crl(ecc1_root, ecc1_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        ecc1_root_ca = self.save_keyless_ca(
            root_ca_cert=ecc1_root,
            unique_name='root-ca-secp256r1-sha256',
            crl_pem=ecc1_root_crl,
        )
        ecc1_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc1_root_ca_key,
            private_key=ecc1_issuing_ca_key,
            issuer_cn='Root-CA SECP256R1-SHA256',
            subject_cn='Issuing CA D',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        self.save_issuing_ca(
            issuing_ca_cert=ecc1_issuing_ca,
            private_key=ecc1_issuing_ca_key,
            chain=[ecc1_root],
            unique_name='issuing-ca-d',
            ca_type=ca_type,
            parent_ca=ecc1_root_ca,
        )

        self.log_and_stdout('Creating SECP384R1 Root CA and Issuing CA E...')
        ecc2_root_ca_key = ec.generate_private_key(curve=ec.SECP384R1())
        ecc2_issuing_ca_key = ec.generate_private_key(curve=ec.SECP384R1())
        ecc2_root, _ = self.create_root_ca(
            'Root-CA SECP384R1-SHA256', private_key=ecc2_root_ca_key, hash_algorithm=hashes.SHA256(), validity_days=root_validity_days
        )
        ecc2_root_crl = self.generate_empty_crl(ecc2_root, ecc2_root_ca_key, hashes.SHA256(), crl_validity_hours=root_validity_days * 24)
        ecc2_root_ca = self.save_keyless_ca(
            root_ca_cert=ecc2_root,
            unique_name='root-ca-secp384r1-sha256',
            crl_pem=ecc2_root_crl,
        )
        ecc2_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc2_root_ca_key,
            private_key=ecc2_issuing_ca_key,
            issuer_cn='Root-CA SECP384R1-SHA256',
            subject_cn='Issuing CA E',
            hash_algorithm=hashes.SHA256(),
            validity_days=issuing_validity_days,
        )
        self.save_issuing_ca(
            issuing_ca_cert=ecc2_issuing_ca,
            private_key=ecc2_issuing_ca_key,
            chain=[ecc2_root],
            unique_name='issuing-ca-e',
            ca_type=ca_type,
            parent_ca=ecc2_root_ca,
        )

        self.log_and_stdout('Creating SECP521R1 Root CA and Issuing CA F...')
        ecc3_root_ca_key = ec.generate_private_key(curve=ec.SECP521R1())
        ecc3_issuing_ca_key = ec.generate_private_key(curve=ec.SECP521R1())
        ecc3_root, _ = self.create_root_ca(
            'Root-CA SECP521R1-SHA256', private_key=ecc3_root_ca_key, hash_algorithm=hashes.SHA3_512(), validity_days=root_validity_days
        )
        ecc3_root_crl = self.generate_empty_crl(ecc3_root, ecc3_root_ca_key, hashes.SHA3_512(), crl_validity_hours=root_validity_days * 24)
        ecc3_root_ca = self.save_keyless_ca(
            root_ca_cert=ecc3_root,
            unique_name='root-ca-secp521r1-sha256',
            crl_pem=ecc3_root_crl,
        )
        ecc3_issuing_ca, _key = self.create_issuing_ca(
            issuer_private_key=ecc3_root_ca_key,
            private_key=ecc3_issuing_ca_key,
            issuer_cn='Root-CA SECP521R1-SHA256',
            subject_cn='Issuing CA F',
            hash_algorithm=hashes.SHA3_512(),
            validity_days=issuing_validity_days,
        )
        self.save_issuing_ca(
            issuing_ca_cert=ecc3_issuing_ca,
            private_key=ecc3_issuing_ca_key,
            chain=[ecc3_root],
            unique_name='issuing-ca-f',
            ca_type=ca_type,
            parent_ca=ecc3_root_ca,
        )

        self.log_and_stdout('All issuing CAs have been created successfully!')