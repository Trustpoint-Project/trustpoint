"""Test data generator module that creates keys and certificate for testing of TOKI zero-touch onboarding."""

from pathlib import Path

from tests import generate_certificate, generate_key
from trustpoint_devid_module.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
)
from trustpoint_devid_module.util import SignatureSuite
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import secrets

DATA_DIR = Path(__file__).parent / Path('data')

if __name__ == '__main__':
    if not DATA_DIR.exists():
        DATA_DIR.mkdir()

    keys = []
    signature_suite = SignatureSuite.SECP256R1_SHA256
    key = generate_key(signature_suite)
    keys.append((key, signature_suite))
    key_bytes = PrivateKeySerializer(key).as_pkcs8_pem()

    owner_key = generate_key(signature_suite)
    owner_key_bytes = PrivateKeySerializer(owner_key).as_pkcs8_pem()

    # signature_suite_filename_prefix = f'{signature_suite.key_type_name}_'
    signature_suite_filename_prefix = ''

    with Path(DATA_DIR / f'{signature_suite_filename_prefix}idevid_private.key').open('wb') as f:
        f.write(key_bytes)

    with Path(DATA_DIR / f'{signature_suite_filename_prefix}owner_private.key').open('wb') as f:
        f.write(owner_key_bytes)

    # TODO(AlexHx8472): Remove code duplication.
    for key, signature_suite in keys:
        root_ca_key = generate_key(signature_suite)
        root_ca_certificate = generate_certificate(
            ca=True,
            public_key=root_ca_key.public_key(),
            private_key=root_ca_key,
            subject_cn=f'{signature_suite.value} Root CA',
            issuer_cn=f'{signature_suite.value} Root CA',
        )

        with Path(DATA_DIR / f'{signature_suite_filename_prefix}root_ca.pem').open('wb') as f:
            f.write(CertificateSerializer(root_ca_certificate).as_pem())

        # TODO(AlexHx8472): Remove code duplication.
        issuing_ca_key = generate_key(signature_suite)
        issuing_ca_certificate = generate_certificate(
            ca=True,
            public_key=issuing_ca_key.public_key(),
            private_key=root_ca_key,
            subject_cn=f'{signature_suite.value} Issuing CA',
            issuer_cn=f'{signature_suite.value} Root CA',
        )

        with Path(DATA_DIR / f'{signature_suite_filename_prefix}issuing_ca.pem').open('wb') as f:
            f.write(CertificateSerializer(issuing_ca_certificate).as_pem())

        idevid_serial_number = f'tpidevid-{secrets.token_hex(16)}'

        idevid_certificate = generate_certificate(
            ca=False,
            public_key=key.public_key(),
            private_key=issuing_ca_key,
            subject_cn='',
            issuer_cn=f'{signature_suite.value} Issuing CA',
            subject_name=x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'IDevID Testing Certificate'),
                    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'IDevID'),
                    x509.NameAttribute(NameOID.SERIAL_NUMBER, idevid_serial_number),
                ]
            ),
        )

        idevid_fingerprint = idevid_certificate.fingerprint(hashes.SHA256()).hex()

        with Path(DATA_DIR / f'{signature_suite_filename_prefix}idevid_cert.pem').open('wb') as f:
            f.write(CertificateSerializer(idevid_certificate).as_pem())

        with Path(DATA_DIR / f'{signature_suite_filename_prefix}idevid_cert_chain.pem').open('wb') as f:
            cert_chain = [issuing_ca_certificate, idevid_certificate]
            f.write(CertificateCollectionSerializer(cert_chain).as_pem())

        owner_certificate = generate_certificate(
            ca=False,
            public_key=owner_key.public_key(),
            private_key=issuing_ca_key,
            subject_cn='',
            issuer_cn=f'{signature_suite.value} Issuing CA',
            subject_name=x509.Name(
                [
                    # TODO(Air): This seems hacky. Maybe better to add custom extension to reference the IDevID.
                    # or just use a voucher instead of an actual certificate.
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Testing Ownership Certificate'),
                    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, 'Owner'),
                    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, f'idevid-fingerprint:{idevid_fingerprint}'),
                    x509.NameAttribute(NameOID.SERIAL_NUMBER, idevid_serial_number),
                ]
            ),
        )

        with Path(DATA_DIR / f'{signature_suite_filename_prefix}owner_cert.pem').open('wb') as f:
            f.write(CertificateSerializer(owner_certificate).as_pem())

        with Path(DATA_DIR / f'{signature_suite_filename_prefix}owner_cert_chain.pem').open('wb') as f:
            cert_chain = [issuing_ca_certificate, owner_certificate]
            f.write(CertificateCollectionSerializer(cert_chain).as_pem())
