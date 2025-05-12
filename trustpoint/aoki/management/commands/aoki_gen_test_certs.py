"""Generates a testing IDevID PKI and associated Owner Certificate PKI for AOKI testing."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.core.management.base import BaseCommand
from pki.util.x509 import CertificateGenerator

if TYPE_CHECKING:
    from typing import Any

    from trustpoint_core.key_types import PrivateKey

TEST_SERIAL_NUMBER = '4211'

CURRENT_DIR = Path(__file__).parent.resolve()
CERTS_DIR = (CURRENT_DIR / '../../tests/certs/').resolve()
CERTS_DIR.mkdir(parents=True, exist_ok=True)

# ruff: noqa: T201  # use of print is fine in this simple generator script


class Command(BaseCommand):
    """Command to check for certificates using insufficient RSA key lengths."""

    help = 'Check certificates with insufficient key lengths.'

    def handle(self, *args: Any, **kwargs: Any) -> None:
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        del args, kwargs  # Unused
        idevid_cert = AokiTestCertGenerator.generate_idevid_pki()
        AokiTestCertGenerator.generate_owner_id_cert(idevid_cert)
        print('Certificates generated successfully.')


def write_private_key(key: PrivateKey, file: Path) -> None:
    """Write the private key to a PEM file."""
    with file.open('wb') as key_file:
        key_file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

def write_cert_pem(cert: x509.Certificate, file: Path) -> None:
    """Write the certificate to a PEM file."""
    with file.open('wb') as cert_file:
        cert_file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))


class AokiTestCertGenerator:
    """Generates a testing IDevID PKI and associated Owner Certificate PKI for AOKI testing."""

    @staticmethod
    def generate_idevid_pki() -> x509.Certificate:
        """Generates a testing IDevID PKI."""
        # Generate the IDevID test CA
        root_ca_cert, root_ca_key = CertificateGenerator.create_root_ca(
            'IDevID_Test_Root_CA'
        )
        # write the root CA certificate and key to files
        write_cert_pem(root_ca_cert, CERTS_DIR / 'idevid_ca.pem')
        write_private_key(root_ca_key, CERTS_DIR / 'idevid_ca_pk.pem')

        # Generate the IDevID test cert
        idevid_cert, idevid_key = CertificateGenerator.create_ee(
            issuer_private_key=root_ca_key,
            issuer_cn='IDevID_Test_Root_CA',
            subject_name=x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'IDevID_Test'),
                    x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, TEST_SERIAL_NUMBER),
                ]
            ),
            private_key=None,
            extensions=[
                (x509.SubjectAlternativeName([x509.UniformResourceIdentifier('test_idevid.alt')]), False),
            ],
            validity_days=99999,
        )
        write_cert_pem(idevid_cert, CERTS_DIR / 'idevid.pem')
        write_private_key(idevid_key, CERTS_DIR / 'idevid_pk.pem')
        return idevid_cert

    @staticmethod
    def generate_owner_id_cert(idevid_cert: x509.Certificate) -> None:
        """Generate the DeviceOwnerID certificate."""
        # It is RECOMMENDED that the same CA is used as for the IDevID cert,
        # but here a separate CA is used to ascertain they can be different
        owner_ca_cert, owner_ca_key = CertificateGenerator.create_root_ca(
            'Owner_Test_Root_CA'
        )
        write_cert_pem(owner_ca_cert, CERTS_DIR / 'ownerid_ca.pem')
        write_private_key(owner_ca_key, CERTS_DIR / 'ownerid_ca_pk.pem')

        idevid_x509_sn = hex(idevid_cert.serial_number)[2:].zfill(16)
        idevid_sha256_fingerprint = idevid_cert.fingerprint(hashes.SHA256()).hex()
        # Build URI string "aoki.<idevid_subj_sn>.owner.<idevid_x509_sn>.<idevid_sha256_fingerprint>.alt"
        # If the IDevID Subject Serial Number is not present, '_' shall be used as a placeholder
        idevid_san_uri = f'{TEST_SERIAL_NUMBER}.aoki.owner.{idevid_x509_sn}.{idevid_sha256_fingerprint}.alt'
        print(f'DeviceOwnerID SAN URI: {idevid_san_uri}')
        ownerid_cert, ownerid_key = CertificateGenerator.create_ee(
            issuer_private_key=owner_ca_key,
            issuer_cn='Owner_Test_Root_CA',
            subject_name=x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'DevOwnerID_Test'),
                    x509.NameAttribute(x509.NameOID.PSEUDONYM, 'DevOwnerID'),
                ]
            ),
            private_key=None,
            extensions=[
                (x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(idevid_san_uri)
                ]), False),
                # SAN should be critical for an OwnerID cert,
                # but then the subject name should be empty according to RFC 5280
            ],
            validity_days=99999,
        )
        write_cert_pem(ownerid_cert, CERTS_DIR / 'owner_id.pem')
        write_private_key(ownerid_key, CERTS_DIR / 'owner_id_pk.pem')

