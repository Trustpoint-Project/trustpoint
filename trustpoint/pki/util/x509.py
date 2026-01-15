"""Handles certificate creation for Issuing CA certificates."""

from __future__ import annotations

import datetime
import itertools
import logging
import urllib
from datetime import UTC
from typing import TYPE_CHECKING, get_args

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.serializer import CredentialSerializer, PrivateKeyLocation, PrivateKeyReference

from management.models import KeyStorageConfig
from pki.models import CaModel, IssuingCaModel
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
        private_key: None | PrivateKey = None,
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
        if not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
            err_msg = f'The hash algorithm must be one of {AllowedCertSignHashAlgos}, but found {type(hash_algorithm)}'
            raise TypeError(err_msg)

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
        is_root_ca = issuer_private_key == private_key
        path_length = 1 if is_root_ca else 0
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
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
        if not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
            err_msg = f'The hash algorithm must be one of {AllowedCertSignHashAlgos}, but found {type(hash_algorithm)}'
            raise TypeError(err_msg)

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
            ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            cert, _key = CertificateGenerator.create_ee(
                ee_key, 'Test End Entity', 'Test End Entity', ee_key, ee_extensions)
            return ([cert], [ee_key])

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
    def save_issuing_ca(  # noqa: PLR0913
        issuing_ca_cert: x509.Certificate,
        chain: list[x509.Certificate],
        private_key: PrivateKey,
        unique_name: str = 'issuing_ca',
        ca_type: IssuingCaModel.IssuingCaTypeChoice = IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED,
        parent_ca: CaModel | None = None,
    ) -> CaModel:
        """Saves an Issuing CA certificate to the database and returns the CaModel.

        Args:
            issuing_ca_cert: The issuing CA certificate.
            chain: List of intermediate certificates in the chain.
            private_key: The private key for the issuing CA.
            unique_name: Unique name for this CA.
            ca_type: The type of issuing CA.
            parent_ca: Optional parent CA in the hierarchy (the CA that issued this certificate).

        Returns:
            CaModel: The created CA model.
        """
        issuing_ca_credential_serializer = CredentialSerializer(
            private_key=private_key,
            certificate=issuing_ca_cert,
            additional_certificates=chain
        )

        # Determine private key location based on CA type and storage configuration
        if ca_type == IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED:
            # Unprotected local CAs always use software storage
            private_key_location = PrivateKeyLocation.SOFTWARE
        elif ca_type in [
            IssuingCaModel.IssuingCaTypeChoice.AUTOGEN_ROOT,
            IssuingCaModel.IssuingCaTypeChoice.AUTOGEN,
        ]:
            # Auto-generated CAs use the configured storage type
            try:
                config = KeyStorageConfig.get_config()
            except KeyStorageConfig.DoesNotExist as e:
                error_msg = (
                    f'Cannot create auto-generated CA "{unique_name}": KeyStorageConfig not found. '
                    'Please configure key storage first.'
                )
                logger.exception(error_msg)
                raise ValueError(error_msg) from e

            if config.storage_type in [
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM
            ]:
                private_key_location = PrivateKeyLocation.HSM_PROVIDED
            else:
                # Software storage
                private_key_location = PrivateKeyLocation.SOFTWARE
        else:
            # For protected CAs (LOCAL_PKCS11), HSM storage is required
            try:
                config = KeyStorageConfig.get_config()
            except KeyStorageConfig.DoesNotExist as e:
                error_msg = (
                    f'Cannot create protected CA "{unique_name}": KeyStorageConfig not found. '
                    'Protected CAs require HSM storage configuration.'
                )
                logger.exception(error_msg)
                raise ValueError(error_msg) from e

            if config.storage_type in [
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM
            ]:
                private_key_location = PrivateKeyLocation.HSM_PROVIDED
            else:
                error_msg = (
                    f'Cannot create protected CA "{unique_name}" with storage type "{config.storage_type}". '
                    f'Protected CAs require HSM storage (SoftHSM or Physical HSM), but current storage type is: '
                    f'{config.storage_type}'
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

        if not issuing_ca_credential_serializer.private_key:
            err_msg = 'Issuing CA credential serializer must have a private key before saving.'
            raise ValueError(err_msg)
        issuing_ca_credential_serializer.private_key_reference = (
            PrivateKeyReference.from_private_key(
                private_key=issuing_ca_credential_serializer.private_key,
                key_label=unique_name,
                location=private_key_location
            )
        )

        issuing_ca = IssuingCaModel.create_new_issuing_ca(
            credential_serializer=issuing_ca_credential_serializer,
            issuing_ca_type=ca_type
        )

        ca = CaModel.create_from_issuing(unique_name=unique_name, issuing_ca=issuing_ca)

        if parent_ca is not None:
            ca.parent_ca = parent_ca
            ca.save()

        logger.info("Issuing CA '%s' saved successfully.", unique_name)

        return ca

    @staticmethod
    def save_root_ca(
        root_ca_cert: x509.Certificate,
        unique_name: str = 'root_ca',
        crl_pem: str | None = None,
    ) -> CaModel:
        """Saves a keyless root CA certificate as a keyless CA to the database and returns the CaModel."""
        ca = CaModel.create_from_keyless(
            unique_name=unique_name,
            certificate=root_ca_cert,
            crl_pem=crl_pem,
        )

        logger.info("Keyless root CA '%s' saved successfully.", unique_name)

        return ca


class ClientCertificateAuthenticationError(Exception):
    """Exception raised for general client certificate authentication failures."""


class NginxTLSClientCertExtractor:
    """Extracts the TLS client certificate from the request."""

    @staticmethod
    def get_client_cert_as_x509(request: HttpRequest) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Retrieve the client certificate from the request and convert it to an x509.Certificate object.

        Args:
            request: Django HttpRequest containing the headers.

        Returns:
            x509.Certificate object.

        Raises:
            ClientCertificateAuthenticationError: if no client certificate found or it is not a valid PEM-encoded cert.
        """
        cert_data = request.META.get('HTTP_SSL_CLIENT_CERT')
        if not cert_data:
            error_message = 'Missing HTTP_SSL_CLIENT_CERT header'
            raise ClientCertificateAuthenticationError(error_message)
        # URL-decode the certificate
        cert_data = urllib.parse.unquote(cert_data)
        try:
            client_cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'))
        except Exception as e:
            error_message = f'Invalid HTTP_SSL_CLIENT_CERT header: {e}'
            raise ClientCertificateAuthenticationError(error_message) from e

         # Extract intermediate CAs from NGINX variables
        intermediate_cas = []

        for i in itertools.count():
            ca = request.META.get(f'SSL_CLIENT_CERT_CHAIN_{i}')
            if not ca:
                break
            try:
                ca_cert = x509.load_pem_x509_certificate(ca.encode('utf-8'))
            except Exception as e:
                error_message = f'Invalid SSL_CLIENT_CERT_CHAIN_{i} PEM: {e}'
                raise ClientCertificateAuthenticationError(error_message) from e
            intermediate_cas.append(ca_cert)

        return (client_cert, intermediate_cas)

class CertificateVerifier:
    """Methods for verifying client and server certificates."""

    @staticmethod
    def verify_server_cert(
        cert: x509.Certificate,
        subject: str,
        untrusted_intermediates: list[x509.Certificate] | None = None,
        verification_time: datetime.datetime | None = None
    ) -> list[x509.Certificate]:
        """Verifies a server's TLS certificate against a trusted certificate store.

        Args:
            cert (x509.Certificate): The DER- or PEM-encoded leaf server certificate to verify.
            subject (str): The expected DNS name or hostname to match against the certificate's
                Subject Alternative Name (SAN).
            untrusted_intermediates (list[x509.Certificate]): DER- or PEM-encoded intermediate certificates that are
                not trusted by default but provided to assist chain building.
            verification_time (datetime): Certificate verification time

        Returns:
            list[x509.Certificate]: A validated certificate chain from the leaf certificate up to a trusted root.

        Raises:
            VerificationError: If a valid chain cannot be constructed.
            UnsupportedGeneralNameType: If a valid chain exists, but contains an unsupported general name type.
        """
        trust_store = Store([cert])

        if verification_time is None:
            verification_time =  datetime.datetime.now(UTC)
        verifier = (
            PolicyBuilder()
            .store(trust_store)
            .time(verification_time)
            .build_server_verifier(x509.DNSName(subject))
        )

        if untrusted_intermediates is None:
            untrusted_intermediates = []

        return verifier.verify(cert, [])

