"""Handles certificate creation for Issuing CA certificates."""

from __future__ import annotations

import datetime
import itertools
import logging
import urllib
from datetime import UTC
from typing import TYPE_CHECKING, get_args

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.serializer import CredentialSerializer, PrivateKeyLocation, PrivateKeyReference

from management.models import KeyStorageConfig, SecurityConfig
from notifications.models import WeakECCCurve, WeakSignatureAlgorithm
from pki.models import CaModel
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
        path_length: int | None = None,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """Creates a root CA certificate for testing and AutoGenPKI.

        Args:
            cn: Common name for the root CA.
            validity_days: Validity period in days.
            private_key: Private key to use. If None, generates new RSA-2048 key.
            hash_algorithm: Hash algorithm to use for signing.
            path_length: Maximum number of CA certificates that may follow this
                        certificate. If None, defaults to 1.

        Returns:
            Tuple of (certificate, private_key).
        """
        return CertificateGenerator.create_issuing_ca(
            None, cn, cn, private_key, validity_days, hash_algorithm, path_length
        )

    @staticmethod
    def create_issuing_ca(  # noqa: PLR0913
        issuer_private_key: None | PrivateKey,
        issuer_cn: str,
        subject_cn: str,
        private_key: None | PrivateKey = None,
        validity_days: int = 3650,
        hash_algorithm: None | HashAlgorithm = None,
        path_length: int | None = None,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """Creates an issuing CA certificate + key pair.

        Args:
            issuer_private_key: Private key of the issuing CA. None for root CA.
            issuer_cn: Common name of the issuer.
            subject_cn: Common name of the subject.
            private_key: Private key to use. If None, generates new RSA-2048 key.
            validity_days: Validity period in days.
            hash_algorithm: Hash algorithm to use for signing.
            path_length: Maximum number of CA certificates that may follow this
                        certificate in a valid certification path. If None, defaults
                        to 1 for root CAs and 0 for intermediate CAs.

        Returns:
            Tuple of (certificate, private_key).
        """
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
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Trustpoint'),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, 'DE'),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Baden-Wuerttemberg'),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Trustpoint'),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, 'DE'),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Baden-Wuerttemberg'),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.now(tz=datetime.UTC) - one_day)
        builder = builder.not_valid_after(datetime.datetime.now(tz=datetime.UTC) + (one_day * validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        is_root_ca = issuer_private_key == private_key

        if path_length is None:
            path_length = 1 if is_root_ca else 0

        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
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
        issuer_name: x509.Name,
        subject_name: str | x509.Name,
        private_key: None | PrivateKey = None,
        extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
        validity_days: int = 365,
    ) -> tuple[x509.Certificate, PrivateKey]:
        """Creates a generic end entity certificate + key pair.

        Args:
            issuer_private_key: The private key of the issuer.
            issuer_name: The full issuer Name (must be x509.Name to ensure proper certificate chain matching).
            subject_name: The subject common name (str) or full subject Name.
            private_key: The private key for the EE. If None, generates new RSA-2048 key.
            extensions: List of (extension, critical) tuples to add.
            validity_days: Validity period in days.

        Returns:
            Tuple of (certificate, private_key).
        """
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

        builder = builder.issuer_name(issuer_name)

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
            ee_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test End Entity')])
            cert, _key = CertificateGenerator.create_ee(
                ee_key, ee_name, 'Test End Entity', ee_key, ee_extensions)
            return ([cert], [ee_key])

        certs = []
        keys = []
        (root_cert, root_key) = CertificateGenerator.create_root_ca('Test Root CA')
        certs.append(root_cert)
        keys.append(root_key)
        parent_key = root_key
        parent_cert = root_cert
        for i in range(chain_depth - 1):
            ca_cn = f'Test Intermediate CA {i + 1}'
            parent_cn = str(parent_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
            (cert, key) = CertificateGenerator.create_issuing_ca(
                parent_key, parent_cn, ca_cn
            )
            parent_key = key
            parent_cert = cert
            certs.append(cert)
            keys.append(key)

        (cert, key) = CertificateGenerator.create_ee(
            parent_key, parent_cert.subject, 'Test End Entity', None, ee_extensions
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
        ca_type: CaModel.CaTypeChoice = CaModel.CaTypeChoice.LOCAL_UNPROTECTED,
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
        if ca_type == CaModel.CaTypeChoice.LOCAL_UNPROTECTED:
            # Unprotected local CAs always use software storage
            private_key_location = PrivateKeyLocation.SOFTWARE
        elif ca_type in [
            CaModel.CaTypeChoice.AUTOGEN_ROOT,
            CaModel.CaTypeChoice.AUTOGEN,
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

        issuing_ca = CaModel.create_new_issuing_ca(
            credential_serializer=issuing_ca_credential_serializer,
            ca_type=ca_type,
            unique_name=unique_name,
            parent_ca=parent_ca
        )

        logger.info("Issuing CA '%s' saved successfully.", unique_name)

        return issuing_ca

    @staticmethod
    def save_keyless_ca(
        root_ca_cert: x509.Certificate,
        unique_name: str = 'root_ca',
        crl_pem: str | None = None,
    ) -> CaModel:
        """Saves a keyless root CA certificate as a keyless CA to the database and returns the CaModel."""
        ca = CaModel.create_keyless_ca(
            unique_name=unique_name,
            certificate_obj=root_ca_cert,
        )

        if crl_pem:
            ca.import_crl(crl_pem)

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
    """Methods for verifying client, server, and CA certificates."""

    @staticmethod
    def _check_rsa_key_size(certificate: x509.Certificate) -> None:
        """Check if an RSA certificate meets the minimum key size requirement.

        Non-RSA certificates (ECC, etc.) automatically pass this check.

        Args:
            certificate (x509.Certificate): The certificate to validate.

        Raises:
            ValueError: If the certificate is RSA but the key size is below the minimum,
                       or if SecurityConfig is not configured.
        """
        security_config = SecurityConfig.objects.first()
        if not security_config or not security_config.security_mode:
            msg = 'SecurityConfig or security_mode is not configured.'
            raise ValueError(msg)

        config_values = security_config.NOTIFICATION_CONFIGURATIONS.get(security_config.security_mode, {})
        if not config_values:
            msg = f'No configuration found for security mode: {security_config.security_mode}'
            raise ValueError(msg)

        public_key = certificate.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            minimum_key_size = config_values.get('rsa_minimum_key_size', 2048)
            if public_key.key_size < minimum_key_size:
                err_msg = (
                    f'RSA certificate key size ({public_key.key_size} bits) is below the minimum '
                    f'required by security policy ({minimum_key_size} bits).'
                )
                raise ValueError(err_msg)

    @staticmethod
    def _check_ecc_curve(certificate: x509.Certificate) -> None:
        """Check if an ECC certificate uses a weak curve according to security policy.

        RSA and other key types automatically pass this check.

        Args:
            certificate (x509.Certificate): The certificate to validate.

        Raises:
            ValueError: If the certificate uses an ECC curve listed as weak in security policy,
                       or if SecurityConfig is not configured.
        """
        security_config = SecurityConfig.objects.first()
        if not security_config or not security_config.security_mode:
            msg = 'SecurityConfig or security_mode is not configured.'
            raise ValueError(msg)

        config_values = security_config.NOTIFICATION_CONFIGURATIONS.get(security_config.security_mode, {})
        if not config_values:
            msg = f'No configuration found for security mode: {security_config.security_mode}'
            raise ValueError(msg)

        public_key = certificate.public_key()

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name
            weak_ecc_curve_oids = config_values.get('weak_ecc_curves', [])

            for weak_curve_oid in weak_ecc_curve_oids:
                # weak_curve_oid is a WeakECCCurve.ECCCurveChoices enum value
                weak_curve = WeakECCCurve.objects.filter(oid=weak_curve_oid).first()
                if weak_curve and weak_curve.oid == curve_name:
                    err_msg = (
                        f'ECC certificate uses a weak curve ({curve_name}) according to '
                        f'security policy ({security_config.get_security_mode_display()}).'
                    )
                    raise ValueError(err_msg)

    @staticmethod
    def _check_ca_key_usage(
        certificate: x509.Certificate,
        required_key_usage: x509.KeyUsage | None = None
    ) -> None:
        """Check if a certificate has valid CA key usage.

        Validates that the certificate has:
        - key_cert_sign: True (required for all CAs)
        - crl_sign: True (required for CA certificates)

        Args:
            certificate (x509.Certificate): The certificate to validate.
            required_key_usage (x509.KeyUsage | None): Optional exact key usage to match.

        Raises:
            ValueError: If key usage is invalid or missing.
        """
        try:
            cert_key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound as e:
            err_msg = 'Certificate is missing required KeyUsage extension.'
            raise ValueError(err_msg) from e

        key_usage = cert_key_usage.value

        if not key_usage.key_cert_sign:
            err_msg = 'Certificate does not have key_cert_sign usage: cannot be used as a CA.'
            raise ValueError(err_msg)

        if not key_usage.crl_sign:
            err_msg = 'Certificate does not have crl_sign usage: required for CA certificates.'
            raise ValueError(err_msg)

        if required_key_usage is not None and key_usage != required_key_usage:
            err_msg = (
                f'Certificate key usage does not match required key usage. '
                f'Expected: {required_key_usage}, Got: {key_usage}'
            )
            raise ValueError(err_msg)

    @staticmethod
    def _check_ca_basic_constraints(certificate: x509.Certificate) -> None:
        """Check if a certificate has valid CA basic constraints.

        Args:
            certificate (x509.Certificate): The certificate to validate.

        Raises:
            ValueError: If basic constraints are invalid or missing.
        """
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound as e:
            err_msg = 'Certificate is missing required BasicConstraints extension.'
            raise ValueError(err_msg) from e

        if not basic_constraints.value.ca:
            err_msg = 'Certificate is not a CA certificate: BasicConstraints.ca is False.'
            raise ValueError(err_msg)

    @staticmethod
    def _check_signature_algorithm(certificate: x509.Certificate) -> None:
        """Check if a certificate uses a weak signature algorithm according to security policy.

        Args:
            certificate (x509.Certificate): The certificate to validate.

        Raises:
            ValueError: If the certificate uses a signature algorithm listed as weak in security policy,
                       or if SecurityConfig is not properly configured.
        """
        security_config = SecurityConfig.objects.first()
        if not security_config or not security_config.security_mode:
            msg = 'SecurityConfig or security_mode is not configured.'
            raise ValueError(msg)

        config_values = security_config.NOTIFICATION_CONFIGURATIONS.get(security_config.security_mode, {})
        if not config_values:
            msg = f'No configuration found for security mode: {security_config.security_mode}'
            raise ValueError(msg)

        signature_algorithm_oid = certificate.signature_algorithm_oid
        weak_signature_algorithm_oids = config_values.get('weak_signature_algorithms', [])

        for weak_algo_oid in weak_signature_algorithm_oids:
            # weak_algo_oid is a WeakSignatureAlgorithm.SignatureChoices enum value
            weak_algo = WeakSignatureAlgorithm.objects.filter(oid=weak_algo_oid).first()
            if weak_algo and weak_algo.oid == str(signature_algorithm_oid):
                hash_algo = certificate.signature_hash_algorithm
                algo_name = (
                    hash_algo.__class__.__name__ if hash_algo else 'unknown'
                )
                err_msg = (
                    f'Certificate uses a weak signature algorithm ({algo_name}) according to '
                    f'security policy ({security_config.get_security_mode_display()}).'
                )
                raise ValueError(err_msg)

    @staticmethod
    def verify_server_cert(
        cert: x509.Certificate,
        subject: str,
        trusted_roots: list[x509.Certificate] | None = None,
        untrusted_intermediates: list[x509.Certificate] | None = None,
        verification_time: datetime.datetime | None = None
    ) -> list[x509.Certificate]:
        """Verifies a server's TLS certificate against a trusted certificate store.

        Performs full X.509 chain validation including:
        - Certificate validity (not before/not after)
        - Hostname verification (DNS name matching against SAN)
        - Chain building to a trusted root CA
        - Basic constraints and key usage extensions
        - RSA key size validation (if RSA certificate)
        - ECC curve strength validation (if ECC certificate)
        - Signature algorithm strength validation

        Args:
            cert (x509.Certificate): The leaf server certificate to verify.
            subject (str): The expected DNS name or hostname to match against the certificate's
                Subject Alternative Name (SAN) extension.
            trusted_roots (list[x509.Certificate] | None): List of trusted root CA certificates to use as the
                trust anchor. If None, the verification will fail as there is no trust anchor.
            untrusted_intermediates (list[x509.Certificate] | None): Intermediate certificates that are
                not trusted by default but provided to assist chain building. Used to help construct
                the certificate path from the leaf to a trusted root.
            verification_time (datetime.datetime | None): The time at which to verify the certificate validity.
                If None, defaults to the current UTC time.

        Returns:
            list[x509.Certificate]: A validated certificate chain from the leaf certificate up to a trusted root,
                ordered from leaf to root.

        Raises:
            VerificationError: If a valid chain cannot be constructed, the certificate is not valid at the
                verification time, or the subject name does not match the provided DNS name.
            UnsupportedGeneralNameType: If a valid chain exists, but contains an unsupported general name type
                in the Subject Alternative Name extension.
            ValueError: If the certificate is RSA but the key size is below the minimum required by security policy,
                if the ECC curve is weak according to security policy, or if the signature algorithm is weak.
        """
        CertificateVerifier._check_rsa_key_size(cert)
        CertificateVerifier._check_ecc_curve(cert)
        CertificateVerifier._check_signature_algorithm(cert)

        if trusted_roots is None:
            trusted_roots = []

        trust_store = Store(trusted_roots)

        if verification_time is None:
            verification_time = datetime.datetime.now(UTC)

        verifier = (
            PolicyBuilder()
            .store(trust_store)
            .time(verification_time)
            .build_server_verifier(x509.DNSName(subject))
        )

        if untrusted_intermediates is None:
            untrusted_intermediates = []

        return verifier.verify(cert, untrusted_intermediates)

    @staticmethod
    def _verify_cert_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
        """Verify that a certificate was signed by the given issuer certificate.

        Args:
            cert: The certificate whose signature is to be verified.
            issuer_cert: The issuer certificate containing the public key.

        Raises:
            ValueError: If the signature verification fails.
            TypeError: If the issuer public key type is unsupported.
        """
        issuer_public_key = issuer_cert.public_key()
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            try:
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except Exception as e:
                err_msg = f'Certificate signature verification failed: {e}'
                raise ValueError(err_msg) from e
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            try:
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            except Exception as e:
                err_msg = f'Certificate signature verification failed: {e}'
                raise ValueError(err_msg) from e
        else:
            err_msg = f'Unsupported issuer public key type: {type(issuer_public_key)}'
            raise TypeError(err_msg)

    @staticmethod
    def _try_verify_against_issuer(
        current: x509.Certificate,
        candidate: x509.Certificate,
        chain: list[x509.Certificate],
        trusted_roots: list[x509.Certificate],
        all_candidates: list[x509.Certificate],
    ) -> list[x509.Certificate] | None:
        """Try to verify current against a candidate issuer and recursively build the chain.

        Args:
            current: The certificate to verify.
            candidate: The potential issuer certificate.
            chain: The chain built so far.
            trusted_roots: Trusted root CA certificates.
            all_candidates: All intermediate + root candidates.

        Returns:
            The completed chain if successful, None otherwise.
        """
        if current.issuer != candidate.subject or candidate in chain:
            return None
        try:
            CertificateVerifier._verify_cert_signature(current, candidate)
        except (ValueError, TypeError):
            return None
        return CertificateVerifier._find_chain(candidate, [*chain, candidate], trusted_roots, all_candidates)

    @staticmethod
    def _find_chain(
        current: x509.Certificate,
        chain: list[x509.Certificate],
        trusted_roots: list[x509.Certificate],
        all_candidates: list[x509.Certificate],
    ) -> list[x509.Certificate] | None:
        """Recursively find a chain from current to a trusted root.

        Args:
            current: The current certificate being evaluated.
            chain: The chain built so far (leaf to current).
            trusted_roots: Trusted root CA certificates.
            all_candidates: All intermediate + root candidates.

        Returns:
            The completed chain if a trusted root is reached, None otherwise.
        """
        for root in trusted_roots:
            if current.issuer != root.subject:
                continue
            try:
                CertificateVerifier._verify_cert_signature(current, root)
            except (ValueError, TypeError):
                continue
            else:
                return [*chain, root] if current != root else chain

        for candidate in all_candidates:
            result = CertificateVerifier._try_verify_against_issuer(
                current, candidate, chain, trusted_roots, all_candidates
            )
            if result is not None:
                return result
        return None

    @staticmethod
    def _build_ca_chain(
        cert: x509.Certificate,
        trusted_roots: list[x509.Certificate],
        untrusted_intermediates: list[x509.Certificate],
    ) -> list[x509.Certificate]:
        """Build and verify a certificate chain from cert up to a trusted root.

        Args:
            cert: The CA certificate to verify.
            trusted_roots: Trusted root CA certificates.
            untrusted_intermediates: Untrusted intermediate certificates for chain building.

        Returns:
            The verified chain from leaf to trusted root.

        Raises:
            ValueError: If no valid chain can be built to a trusted root.
        """
        all_candidates = untrusted_intermediates + trusted_roots
        chain = CertificateVerifier._find_chain(cert, [cert], trusted_roots, all_candidates)
        if chain is None:
            err_msg = 'Could not build a valid certificate chain to a trusted root.'
            raise ValueError(err_msg)
        return chain

    @staticmethod
    def verify_ca_cert(
        cert: x509.Certificate,
        trusted_roots: list[x509.Certificate] | None = None,
        untrusted_intermediates: list[x509.Certificate] | None = None,
        verification_time: datetime.datetime | None = None,
        required_key_usage: x509.KeyUsage | None = None,
    ) -> list[x509.Certificate]:
        """Verifies a CA certificate against a trusted certificate store.

        Performs full X.509 chain validation including:
        - Certificate validity (not before/not after)
        - Chain building to a trusted root CA with signature verification
        - BasicConstraints extension validation (ca=True)
        - KeyUsage extension validation (key_cert_sign=True, crl_sign=True)
        - RSA key size validation (if RSA certificate)
        - ECC curve strength validation (if ECC certificate)
        - Signature algorithm strength validation

        Note: Unlike verify_server_cert, this method does NOT use PolicyBuilder as it
        only supports EE certificates. CA chain verification is performed manually via
        signature verification and issuer/subject name matching.

        Args:
            cert (x509.Certificate): The CA certificate to verify.
            trusted_roots (list[x509.Certificate] | None): List of trusted root CA certificates to use as the
                trust anchor. If None, defaults to empty list. For self-signed CAs, include the cert itself
                or set to [cert].
            untrusted_intermediates (list[x509.Certificate] | None): Intermediate CA certificates that are
                not trusted by default but provided to assist chain building. Used to help construct
                the certificate path from the leaf CA to a trusted root.
            verification_time (datetime.datetime | None): The time at which to verify the certificate validity.
                If None, defaults to the current UTC time.
            required_key_usage (x509.KeyUsage | None): Expected KeyUsage extension. If provided, the certificate's
                key usage must match exactly. If None, only validates required usages.

        Returns:
            list[x509.Certificate]: A validated certificate chain from the CA certificate up to a trusted root,
                ordered from leaf to root.

        Raises:
            ValueError: If the certificate lacks required CA extensions, security properties are
                insufficient, validity period is outside the verification time, or chain cannot be built.
        """
        # Validate CA extensions first
        CertificateVerifier._check_ca_basic_constraints(cert)
        CertificateVerifier._check_ca_key_usage(cert, required_key_usage)

        # Validate certificate security properties
        CertificateVerifier._check_rsa_key_size(cert)
        CertificateVerifier._check_ecc_curve(cert)
        CertificateVerifier._check_signature_algorithm(cert)

        if verification_time is None:
            verification_time = datetime.datetime.now(UTC)

        # Validate validity period
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if not (not_before <= verification_time <= not_after):
            err_msg = (
                f'Certificate is not valid at {verification_time}. '
                f'Valid from {not_before} to {not_after}.'
            )
            raise ValueError(err_msg)

        if trusted_roots is None:
            trusted_roots = []
        if untrusted_intermediates is None:
            untrusted_intermediates = []

        return CertificateVerifier._build_ca_chain(cert, trusted_roots, untrusted_intermediates)


