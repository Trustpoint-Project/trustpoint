"""Generates a testing IDevID PKI and associated Owner Certificate PKI for AOKI testing."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pki.util.x509 import CertificateGenerator

TEST_SERIAL_NUMBER = 4211


class AokiTestCertGenerator:
    """Generates a testing IDevID PKI and associated Owner Certificate PKI for AOKI testing."""

    @staticmethod
    def generate_idevid_pki() -> None:
        """Generates a testing IDevID PKI."""
        # Generate the IDevID test CA
        root_ca_cert, root_ca_key = CertificateGenerator.create_root_ca(
            'IDevID_Test_Root_CA', key_size=2048
        )
        # write the root CA certificate and key to files
        with Path('certs/idevid_ca.pem').open('wb') as f:
            f.write(root_ca_cert.public_bytes())
        with Path('certs/idevid_ca_key.pem').open('wb') as f:
            f.write(root_ca_key.private_bytes())
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
        with Path('certs/idevid.pem').open('wb') as f:
            f.write(idevid_cert.public_bytes())
        with Path('certs/idevid_pk.pem').open('wb') as f:
            f.write(idevid_key.private_bytes())
        # Generate the Device Owner ID cert
        # It is RECOMMENDED that the same CA is used as for the IDevID cert,
        # but here a separate CA is used to ascertain they can be different
        owner_ca_cert, owner_ca_key = CertificateGenerator.create_root_ca(
            'Owner_Test_Root_CA', key_size=2048
        )
        with Path('certs/owner_ca.pem').open('wb') as f:
            f.write(owner_ca_cert.public_bytes())
        with Path('certs/owner_ca_key.pem').open('wb') as f:
            f.write(owner_ca_key.private_bytes())
        idevid_x509_sn = idevid_cert.serial_number
        idevid_sha256_fingerprint = idevid_cert.fingerprint(hashes.SHA256()).hex()
        idevid_san_uri = idevid_x509_sn + idevid_sha256_fingerprint + 'owner.aoki.alt'
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
                ]), True),
            ],
            validity_days=99999,
        )

if __name__ == '__main__':
    AokiTestCertGenerator.generate_idevid_pki()
