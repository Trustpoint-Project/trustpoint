"""Handles certificate creation for Issuing CA certificates."""

from __future__ import annotations

import datetime
import logging
from typing import TYPE_CHECKING

from trustpoint_core.serializer import CredentialSerializer
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.x509.oid import NameOID

from pki.models import IssuingCaModel
from pki.util.keys import CryptographyUtils

if TYPE_CHECKING:
    from trustpoint_core.types import PrivateKey

logger = logging.getLogger(__name__)

class CertificateGenerator:
    """Methods for generating X.509 certificates."""

    @staticmethod
    def create_root_ca(cn: str,
            validity_days: int = 7300,
            private_key: None | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = None,
            hash_algorithm: None | HashAlgorithm = None) -> tuple[x509.Certificate, PrivateKey]:
        """Creates a root CA certificate. (for testing and AutoGenPKI)"""
        return CertificateGenerator.create_issuing_ca(None, cn, cn, private_key, validity_days, hash_algorithm)

    @staticmethod
    def create_issuing_ca(  # noqa: PLR0913
            issuer_private_key: None | PrivateKey,
            issuer_cn: str,
            subject_cn: str,
            private_key: None | PrivateKey = None,
            validity_days: int = 3650,
            hash_algorithm: None | HashAlgorithm = None
    ) -> tuple[x509.Certificate, PrivateKey]:
        """Creates an issuing CA certificate + key pair."""
        one_day = datetime.timedelta(1, 0, 0)
        if private_key is None:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
        if issuer_private_key is None:
            # If issuer private key is not provided, make self-signed (aka root CA)
            issuer_private_key = private_key
            issuer_cn = subject_cn

        if hash_algorithm is None:
            hash_algorithm = SHA256()

        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        ]))
        builder = builder.not_valid_before(datetime.datetime.now(tz=datetime.UTC) - one_day)
        builder = builder.not_valid_after(datetime.datetime.now(tz=datetime.UTC) + (one_day * validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()), critical=False
        )

        certificate = builder.sign(
            private_key=issuer_private_key, algorithm=hash_algorithm,
        )
        return certificate, private_key

    @staticmethod
    def create_ee(  # noqa: PLR0913
            issuer_private_key: PrivateKey,
            issuer_cn: str,
            subject_cn: str,
            private_key: None | PrivateKey = None,
            key_usage_extension: x509.KeyUsage=None,
            validity_days: int = 365) -> tuple[x509.Certificate, PrivateKey]:
        """Creates a generic end entity certificate + key pair."""
        one_day = datetime.timedelta(1, 0, 0)
        if private_key is None:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

        not_valid_before = datetime.datetime.now(tz=datetime.UTC)
        not_valid_after = not_valid_before + (one_day * validity_days)
        # Note: There was an if-else with strange logic for negative validity days here
        # I do not understand the concept of negative validity days
        # Logic??: not_valid_after = now + (one_day * validity_days / 2)

        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        ]))
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        if key_usage_extension:
            builder = builder.add_extension(key_usage_extension, critical=False)

        hash_algorithm = CryptographyUtils.get_hash_algorithm_for_private_key(issuer_private_key)

        certificate = builder.sign(
            private_key=issuer_private_key, algorithm=hash_algorithm,
        )
        return certificate, private_key

    @staticmethod
    def save_issuing_ca(
            issuing_ca_cert: x509.Certificate,
            chain: list[x509.Certificate],
            private_key: PrivateKey,
            unique_name: str ='issuing_ca',
            ca_type: IssuingCaModel.IssuingCaTypeChoice = IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED
        ) -> IssuingCaModel:
        """Saves an Issuing CA certificate to the database."""
        issuing_ca_credential_serializer = CredentialSerializer(
            (
                private_key,
                issuing_ca_cert,
                chain,
            )
        )

        issuing_ca = IssuingCaModel.create_new_issuing_ca(
            unique_name=unique_name,
            credential_serializer=issuing_ca_credential_serializer,
            issuing_ca_type=ca_type
        )

        logger.info("Issuing CA '%s' saved successfully.", unique_name)

        return issuing_ca
