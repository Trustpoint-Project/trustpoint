"""Contains common functionality for PKI management commands."""

# ruff: noqa: T201  # print is fine in management commands

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)
from cryptography.x509.oid import NameOID
from pki.models import CertificateModel
from pki.util.x509 import CertificateGenerator

if TYPE_CHECKING:
    from trustpoint_core.crypto_types import PrivateKey


class CertificateCreationCommandMixin(CertificateGenerator):
    """Mixin for management commands that create certificates."""

    @classmethod
    def store_issuing_ca(
        cls, issuing_ca_cert: x509.Certificate, chain: list[x509.Certificate], private_key: PrivateKey, filename: str
    ) -> None:
        """Store the Issuing CA certificate and private key in a PKCS12 file."""
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')
        issuing_ca_path = tests_data_path / Path(filename)
        tests_data_path.mkdir(exist_ok=True)
        print('\nSaving Issuing CA and Certificates\n')

        p12 = pkcs12.serialize_key_and_certificates(
            name=b'',
            key=private_key,
            cert=issuing_ca_cert,
            cas=chain,
            encryption_algorithm=BestAvailableEncryption(b'testing321'),
        )

        with Path(issuing_ca_path).open('wb') as f:
            f.write(p12)

        print(f'Issuing CA: {issuing_ca_path}')
        print('Issuing CA - Password: testing321\n')

    @staticmethod
    def store_ee_certs(certs: dict[str, x509.Certificate]) -> None:
        """Store the end entity certificates as .pem files."""
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')

        for name, cert in certs.items():
            cert_path = tests_data_path / Path(f'{name}.pem')
            with Path(cert_path).open('wb') as f:
                f.write(cert.public_bytes(encoding=Encoding.PEM))
            print(f'Stored EE certificate: {cert_path}')

    @staticmethod
    def store_ee_keys(keys: dict[str, PrivateKey]) -> None:
        """Store the end entity keys as .pem files."""
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')

        for name, key in keys.items():
            key_path = tests_data_path / Path(f'{name}.pem')
            with Path(key_path).open('wb') as f:
                f.write(
                    key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=NoEncryption(),
                    )
                )
            print(f'Stored EE certificate: {key_path}')

    @staticmethod
    def save_ee_certs(certs: dict[str, x509.Certificate]) -> None:
        """Save the end entity certificates in the database."""
        for name, cert in certs.items():
            print(f'Saving EE certificate in DB: {name}')
            CertificateModel.save_certificate(cert)

    @staticmethod
    def create_csr(number: int) -> None:
        """Create a number of test Certificate Signing Requests."""
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')
        for i in range(number):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, f'CSR Cert {i}'),
                    ]
                )
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            csr = builder.sign(private_key, hashes.SHA256())

            with Path(tests_data_path / Path(f'csr{i}.pem')).open('wb') as f:
                f.write(csr.public_bytes(encoding=Encoding.PEM))
