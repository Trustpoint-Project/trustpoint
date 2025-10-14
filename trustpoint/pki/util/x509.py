"""Handles certificate creation for Issuing CA certificates."""

from __future__ import annotations

import base64
import datetime
import itertools
import logging
import urllib
from typing import TYPE_CHECKING, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.x509.oid import NameOID
from trustpoint_core.serializer import CredentialSerializer

from pki.models import IssuingCaModel
from pki.util.keys import CryptographyUtils

if TYPE_CHECKING:
    from django.http import HttpRequest
    from trustpoint_core.crypto_types import PrivateKey

logger = logging.getLogger(__name__)


class CertificateGenerator:
    """Methods for generating X.509 certificates."""

    @staticmethod
    def create_root_ca(
        cn: str,
        validity_days: int = 7300,
        private_key: None | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = None,
        hash_algorithm: None | HashAlgorithm = None,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """Creates a root CA certificate for testing and AutoGenPKI."""
        return CertificateGenerator.create_issuing_ca(None, cn, cn, private_key, validity_days, hash_algorithm)

    @staticmethod
    def create_issuing_ca(  # noqa: PLR0913
        issuer_private_key: None | PrivateKey,
        issuer_cn: str,
        subject_cn: str,
        private_key: None | PrivateKey = None,
        validity_days: int = 3650,
        hash_algorithm: None | HashAlgorithm = None,
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
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.now(tz=datetime.UTC) - one_day)
        builder = builder.not_valid_after(datetime.datetime.now(tz=datetime.UTC) + (one_day * validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()), critical=False
        )

        certificate = builder.sign(
            private_key=issuer_private_key,
            algorithm=hash_algorithm,
        )
        return certificate, private_key

    @staticmethod
    def create_ee(  # noqa: PLR0913
        issuer_private_key: PrivateKey,
        issuer_cn: str,
        subject_name: str | x509.Name,
        private_key: None | PrivateKey = None,
        extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
        validity_days: int = 365,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """Creates a generic end entity certificate + key pair."""
        one_day = datetime.timedelta(1, 0, 0)
        if private_key is None:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        not_valid_before = datetime.datetime.now(tz=datetime.UTC) - one_day
        not_valid_after = not_valid_before + (one_day * validity_days)

        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        if isinstance(subject_name, str):
            builder = builder.subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
                    ]
                )
            )
        elif isinstance(subject_name, x509.Name):
            builder = builder.subject_name(subject_name)
        else:
            exc_msg = 'subject_name must be a string or x509.Name'
            raise TypeError(exc_msg)

        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
                ]
            )
        )

        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()), critical=False
        )
        for ext, critical in extensions or []:
            builder = builder.add_extension(ext, critical=critical)

        hash_algorithm = CryptographyUtils.get_hash_algorithm_for_private_key(issuer_private_key)

        certificate = builder.sign(
            private_key=issuer_private_key,
            algorithm=hash_algorithm,
        )
        return certificate, private_key
    
    @staticmethod
    def create_test_pki(chain_depth: int = 0) -> tuple[list[x509.Certificate], list[PrivateKey]]:
        """Get a test PKI chain with a specified depth (excluding root CA). depth=0 is a self-signed EE."""
        ee_extensions = [
            (x509.SubjectAlternativeName([x509.UniformResourceIdentifier('test_ee.alt')]), False),
            (x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), True),
        ]
        if (chain_depth == 0):
            # Create a self-signed EE
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            cert, _key = CertificateGenerator.create_ee(key, 'Test End Entity', 'Test End Entity', key, ee_extensions)
            return ([cert], [key])

        certs = []
        keys = []
        (root_cert, root_key) = CertificateGenerator.create_root_ca('Test Root CA')
        certs.append(root_cert)
        keys.append(root_key)
        parent_key = root_key
        parent_cn = 'Test Root CA'
        for i in range(chain_depth - 1):
            ca_cn = f'Test Intermediate CA {i + 1}'
            (cert, key) = CertificateGenerator.create_issuing_ca(
                parent_key, parent_cn, ca_cn
            )
            parent_key = key
            parent_cn = ca_cn
            certs.append(cert)
            keys.append(key)

        (cert, key) = CertificateGenerator.create_ee(
            parent_key, parent_cn, 'Test End Entity', None, ee_extensions
        )
        certs.append(cert)
        keys.append(key)
        return (certs, keys)

    @staticmethod
    def save_issuing_ca(
        issuing_ca_cert: x509.Certificate,
        chain: list[x509.Certificate],
        private_key: PrivateKey,
        unique_name: str = 'issuing_ca',
        ca_type: IssuingCaModel.IssuingCaTypeChoice = IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED,
    ) -> IssuingCaModel:
        """Saves an Issuing CA certificate to the database."""
        issuing_ca_credential_serializer = CredentialSerializer(
            private_key=private_key,
            certificate=issuing_ca_cert,
            additional_certificates=chain
        )

        issuing_ca = IssuingCaModel.create_new_issuing_ca(
            unique_name=unique_name, credential_serializer=issuing_ca_credential_serializer, issuing_ca_type=ca_type
        )

        logger.info("Issuing CA '%s' saved successfully.", unique_name)

        return cast(IssuingCaModel, issuing_ca)


class ClientCertificateAuthenticationError(Exception):
    """Exception raised for general client certificate authentication failures."""


class NginxTLSClientCertExtractor:
    """Extracts the TLS client certificate from nginx headers."""

    @staticmethod
    def get_client_cert_as_x509(request: HttpRequest) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Retrieve the client certificate from nginx headers."""
        cert_data = request.META.get('HTTP_X_SSL_CLIENT_CERT')

        if not cert_data:
            error_message = 'Missing X-SSL-Client-Cert header'
            raise ClientCertificateAuthenticationError(error_message)

        # URL-decode the certificate
        cert_data = urllib.parse.unquote(cert_data)

        try:
            client_cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'))
        except Exception as e:
            error_message = f'Invalid X-SSL-Client-Cert header: {e}'
            raise ClientCertificateAuthenticationError(error_message) from e

        return (client_cert, [])  # TODO(Air): Add back intermediate cert chain