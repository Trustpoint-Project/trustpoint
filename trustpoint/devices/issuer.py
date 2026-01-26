"""Module for issuing and managing TLS and OPC UA credentials."""

from __future__ import annotations

import datetime
import re
from typing import TYPE_CHECKING, get_args

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos
from trustpoint_core.oid import SignatureSuite
from trustpoint_core.serializer import CredentialSerializer

from devices.models import DeviceModel, IssuedCredentialModel, OnboardingProtocol, OnboardingStatus
from pki.models.credential import CredentialModel
from pki.util.keys import KeyGenerator
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    import ipaddress

    from trustpoint_core.crypto_types import PublicKey

    from pki.models.domain import DomainModel


class SaveCredentialToDbMixin(LoggerMixin):
    """Mixin to handle saving credentials to the database."""

    @property
    def device(self) -> DeviceModel:
        """Abstract property that has to be implemented by the derived class."""
        raise NotImplementedError

    @property
    def domain(self) -> DomainModel:
        """Abstract property that has to be implemented by the derived class."""
        raise NotImplementedError

    def _save(
        self,
        credential: CredentialSerializer,
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        issued_using_cert_profile: str,
    ) -> IssuedCredentialModel:
        """Saves the issued credential in the database.

        Args:
            credential: The credential serializer instance.
            common_name: The common name for the credential.
            issued_credential_type: The type of issued credential.
            issued_using_cert_profile: The profile used for issuing the credential.

        Returns:
            The saved issued credential model.
        """
        self.logger.info(
            "Saving credential for device '%s' (ID: %s) "
            "in domain '%s' - CN: '%s', "
            "Type: %s, Profile: %s",
            self.device.common_name,
            self.device.pk,
            self.domain.unique_name,
            common_name,
            issued_credential_type.label,
            issued_using_cert_profile,
        )
        try:
            credential_model = CredentialModel.save_credential_serializer(
                credential_serializer=credential, credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
            )

            issued_credential_model = IssuedCredentialModel(
                issued_credential_type=issued_credential_type,
                issued_using_cert_profile=issued_using_cert_profile,
                common_name=common_name,
                credential=credential_model,
                device=self.device,
                domain=self.domain,
            )

            issued_credential_model.save()

        except Exception:
            self.logger.exception(
                "Failed to save credential for device '%s' (ID: %s)",
                self.device.common_name,
                self.device.pk,
            )
            raise
        else:
            self.logger.info(
                "Successfully saved IssuedCredentialModel (ID: %s) for device '%s'",
                issued_credential_model.pk,
                self.device.common_name
            )
            return issued_credential_model

    def _save_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        issued_using_cert_profile: str,
    ) -> IssuedCredentialModel:

        self.logger.info(
            "Saving keyless credential for device '%s' (ID: %s) "
            "in domain '%s' - CN: '%s', "
            "Type: %s, Profile: %s",
            self.device.common_name,
            self.device.pk,
            self.domain.unique_name,
            common_name,
            issued_credential_type.label,
            issued_using_cert_profile,
        )

        try:
            # check for existing issued credentials
            existing_credentials = IssuedCredentialModel.objects.filter(
                device=self.device,
                domain=self.domain,
                issued_credential_type=issued_credential_type,
                common_name=common_name,
            )
            for issued_credential in existing_credentials:
                cred_model: CredentialModel = issued_credential.credential
                if cred_model.certificate.subjects_match(certificate.subject):
                    # if the certificate already exists, we need to update the certificate (e.g. reenroll)
                    cred_model.update_keyless_credential(certificate, certificate_chain)
                    cred_model.save()
                    return issued_credential

            credential_model = CredentialModel.save_keyless_credential(
                certificate=certificate,
                certificate_chain=certificate_chain,
                credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
            )

            issued_credential_model = IssuedCredentialModel(
                issued_credential_type=issued_credential_type,
                issued_using_cert_profile=issued_using_cert_profile,
                common_name=common_name,
                credential=credential_model,
                device=self.device,
                domain=self.domain,
            )

            issued_credential_model.save()

        except Exception:
            self.logger.exception(
                "Failed to save keyless credential for device '%s' (ID: %s)",
                self.device.common_name,
                self.device.pk
            )
            raise

        self.logger.info(
            "Successfully saved keyless IssuedCredentialModel (ID: %s) for device '%s'",
            issued_credential_model.pk,
            self.device.common_name
        )
        return issued_credential_model



class CredentialSaver(SaveCredentialToDbMixin):
    """A basic class for saving credentials to the database."""
    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        """Initializes the Credential Saver.

        Args:
            device: The device for which the credential is saved.
            domain: The domain associated with the credential.
        """
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        """Gets the device associated with this credential saver.

        Returns:
            DeviceModel: The device linked to the issued credential.
        """
        return self._device

    @property
    def domain(self) -> DomainModel:
        """Gets the domain associated with this credential saver.

        Returns:
            DomainModel: The domain linked to the issued credential.
        """
        return self._domain

    def save_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        cert_profile_disp_name: str,
    ) -> IssuedCredentialModel:
        """Saves a keyless (i.e. private key stays on requesting device) credential to the database."""
        return self._save_keyless_credential(
            certificate, certificate_chain, common_name, issued_credential_type, cert_profile_disp_name)


class BaseTlsCredentialIssuer(SaveCredentialToDbMixin):
    """Base class for issuing TLS credentials.

    This class provides common functionality for creating and saving TLS certificates
    and key pairs for different use cases, including TLS client, server, domain, and
    OPC UA credentials.
    """

    _pseudonym: str
    _device: DeviceModel
    _domain: DomainModel

    _credential: None | CredentialSerializer = None
    _credential_model: None | CredentialModel = None
    _issued_application_credential_model: None | IssuedCredentialModel = None

    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        """Initializes the TLS Credential Issuer.

        Args:
            device: The device for which the credential is issued.
            domain: The domain associated with the credential.
        """
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        """Gets the device associated with this credential issuer.

        Returns:
            DeviceModel: The device linked to the issued credential.
        """
        return self._device

    @property
    def domain(self) -> DomainModel:
        """Gets the domain associated with this credential issuer.

        Returns:
            DomainModel: The domain linked to the issued credential.
        """
        return self._domain

    @property
    def serial_number(self) -> str:
        """Gets the serial number of the associated device.

        Returns:
            str: The serial number of the device.
        """
        return self.device.serial_number

    @property
    def domain_component(self) -> str:
        """Gets the unique name of the domain component.

        Returns:
            str: The unique name of the domain.
        """
        return self.domain.unique_name

    @property
    def pseudonym(self) -> str:
        """Gets the pseudonym associated with this issuer.

        Returns:
            str: The predefined pseudonym for the credential issuer.
        """
        return self._pseudonym

    @classmethod
    def get_fixed_values(cls, device: DeviceModel, domain: DomainModel) -> dict[str, str]:
        """Retrieves a dictionary of fixed values related to the device and domain.

        Args:
            device: The device for which credentials are issued.
            domain: The domain associated with the credentials.

        Returns:
            A dictionary containing the pseudonym, domain component,
            and serial number of the device.
        """
        return {
            'pseudonym': cls._pseudonym,
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

    def _raise_value_error(self, message: str) -> None:
        """Raises a ValueError with the given message.

        Args:
            message: The error message to include in the exception.

        Raises:
            ValueError: Always raised with the provided message.
        """
        raise ValueError(message)

    def _raise_type_error(self, message: str) -> None:
        """Raises a TypeError with the given message.

        Args:
            message: The error message to include in the exception.

        Raises:
            TypeError: Always raised with the provided message.
        """
        raise TypeError(message)

    def _build_certificate(
        self,
        common_name: str,
        public_key: PublicKey,
        validity_days: int,
        extra_extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    ) -> x509.Certificate:
        """Builds an X.509 certificate with the specified parameters.

        Args:
            common_name: The common name (CN) for the certificate subject.
            public_key: The public key associated with the certificate.
            validity_days: The number of days the certificate should be valid.
            extra_extensions: Additional extensions to be added.

        Returns:
            The generated X.509 certificate.
        """
        self.logger.info(
            "Building certificate for CN: '%s', validity: %s days, device: '%s' (ID: %s)",
            common_name,
            validity_days,
            self.device.common_name,
            self.device.pk
        )
        try:
            issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()
            issuer_certificate = issuing_credential.get_certificate()
            algorithm_identifier = SignatureSuite.from_certificate(
                issuer_certificate
            ).algorithm_identifier
            hash_algorithm_enum = algorithm_identifier.hash_algorithm
            if hash_algorithm_enum is None:
                err_msg = 'Failed to get hash algorithm.'
                self._raise_value_error(err_msg)
            hash_algorithm = hash_algorithm_enum.hash_algorithm()  # type: ignore[union-attr]

            if not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
                err_msg = (
                    f'The hash algorithm must be one of {AllowedCertSignHashAlgos}, '
                    f'but found {type(hash_algorithm)}'
                )
                self._raise_type_error(err_msg)

            allowed_hash_algorithm: AllowedCertSignHashAlgos = hash_algorithm  # type: ignore[assignment]

            one_day = datetime.timedelta(days=1)

            certificate_builder = x509.CertificateBuilder()
            certificate_builder = certificate_builder.subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
                        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'Trustpoint'),
                        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'DE'),
                        #x509.NameAttribute(x509.NameOID.PSEUDONYM, self.pseudonym),
                        #x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
                        #x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number),
                        #x509.NameAttribute(x509.NameOID.USER_ID, str(self.device.pk)),
                    ]
                )
            )
            certificate_builder = certificate_builder.issuer_name(
                issuing_credential.get_certificate().subject
            )
            certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC) - one_day)
            certificate_builder = certificate_builder.not_valid_after(
                datetime.datetime.now(datetime.UTC) + (one_day * validity_days)
            )
            certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
            certificate_builder = certificate_builder.public_key(public_key)

            default_extensions = {
                x509.BasicConstraints: (x509.BasicConstraints(ca=False, path_length=None), False),
                x509.KeyUsage: (
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=True,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    True,
                ),
                x509.AuthorityKeyIdentifier: (
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        issuing_credential.get_private_key_serializer().public_key_serializer.as_crypto()
                    ),
                    False,
                ),
                x509.SubjectKeyIdentifier: (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
            }

            if extra_extensions:
                for ext, critical in extra_extensions:
                    default_extensions[type(ext)] = (ext, critical)

            for ext, critical in default_extensions.values():
                certificate_builder = certificate_builder.add_extension(ext, critical)

            certificate = certificate_builder.sign(
                private_key=issuing_credential.get_private_key_serializer().as_crypto(),
                algorithm=allowed_hash_algorithm,
            )

        except Exception:
            self.logger.exception(
                "Failed to build certificate for CN: '%s'",
                common_name,
            )
            raise
        else:
            self.logger.info(
                "Successfully built certificate for CN: '%s' for device '%s'",
                common_name,
                self.device.common_name
            )
            return certificate


class LocalTlsClientCredentialIssuer(BaseTlsCredentialIssuer):
    """Handles issuing TLS client credentials."""

    _pseudonym = 'Trustpoint Application Credential - TLS Client'

    def issue_tls_client_credential(self, common_name: str, validity_days: int) -> IssuedCredentialModel:
        """Issues a TLS client credential.

        Args:
            common_name: The common name for the certificate.
            validity_days: The validity period in days.
            public_key: The public key to be included in the certificate.

        Returns:
            The issued credential model.
        """
        private_key = KeyGenerator.generate_private_key(domain=self.domain)
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()

        san_uri = re.sub(r'[^a-zA-Z0-9_.-]', '', common_name) + '.alt'
        certificate = self._build_certificate(
            common_name,
            private_key.public_key_serializer.as_crypto(),
            validity_days,
            [
                (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False),
                # TODO(Air): This is a workaround for cryptography < 45.0.0 requiring # noqa: FIX002
                #  a SAN to verify the (IDevID) cert.
                (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]), False),
            ],
        )
        credential = CredentialSerializer(
            private_key=private_key.as_crypto(),
            certificate=certificate,
            additional_certificates=[
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
        )
        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'TLS Client',
        )

    def issue_tls_client_certificate(
        self, common_name: str, validity_days: int, public_key: PublicKey
    ) -> IssuedCredentialModel:
        """Issues a TLS client certificate without a private key.

        Args:
            common_name: Certificate common name.
            validity_days: Certificate validity period.
            public_key: Public key for the certificate.

        Returns:
            The issued TLS client certificate.
        """
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()

        san_uri = re.sub(r'[^a-zA-Z0-9_.-]', '', common_name) + '.alt'
        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [
                (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False),
                # TODO (Air): This is a workaround for cryptography < 45.0.0 requiring # noqa: FIX002
                #  a SAN to verify the certificate.
                (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]), False),
            ],
        )
        return self._save_keyless_credential(
            certificate,
            [
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'TLS Client',
        )


class LocalTlsServerCredentialIssuer(BaseTlsCredentialIssuer):
    """Handles issuing TLS server credentials."""

    _pseudonym = 'Trustpoint Application Credential - TLS Server'

    def _build_san_extension(
        self,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
    ) -> x509.SubjectAlternativeName:
        """Builds the Subject Alternative Name (SAN) extension."""
        return x509.SubjectAlternativeName(
            [
                *map(x509.IPAddress, ipv4_addresses),
                *map(x509.IPAddress, ipv6_addresses),
                *map(x509.DNSName, domain_names),
            ]
        )

    def issue_tls_server_credential(  # noqa: PLR0913
        self,
        common_name: str,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
        validity_days: int,
        *,
        san_critical: bool = False,
    ) -> IssuedCredentialModel:
        """Issues a TLS server credential with a private key.

        Generates a TLS server certificate and private key, including SAN extensions,
        and saves the credential in the database.

        Args:
            common_name: Certificate common name.
            ipv4_addresses: IPv4 addresses for SAN.
            ipv6_addresses: IPv6 addresses for SAN.
            domain_names: Domain names for SAN.
            validity_days: Certificate validity period.
            san_critical: Whether SAN is critical. Defaults to False.

        Returns:
            The issued TLS server credential.
        """
        private_key = KeyGenerator.generate_private_key(domain=self.domain)
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()

        san_extension = self._build_san_extension(ipv4_addresses, ipv6_addresses, domain_names)

        certificate = self._build_certificate(
            common_name,
            private_key.public_key_serializer.as_crypto(),
            validity_days,
            [(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False), (san_extension, san_critical)],
        )
        cert_chain = (
            issuing_credential.get_credential_serializer().get_full_chain_as_crypto()
        )
        credential = CredentialSerializer(
            private_key=private_key.as_crypto(), certificate=certificate, additional_certificates=cert_chain
        )
        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'TLS Server',
        )

    def issue_tls_server_certificate(  # noqa: PLR0913
        self,
        common_name: str,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
        validity_days: int,
        public_key: PublicKey,
        *,
        san_critical: bool = False,
    ) -> IssuedCredentialModel:
        """Issues a TLS server certificate without a private key.

        Args:
            common_name: Certificate common name.
            ipv4_addresses: IPv4 addresses for SAN.
            ipv6_addresses: IPv6 addresses for SAN.
            domain_names: Domain names for SAN.
            validity_days: Certificate validity period.
            public_key: Public key for the certificate.
            san_critical: Whether SAN is critical. Defaults to False.

        Returns:
            The issued TLS server certificate.
        """
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()

        san_extension = self._build_san_extension(ipv4_addresses, ipv6_addresses, domain_names)

        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False), (san_extension, san_critical)],
        )
        return self._save_keyless_credential(
            certificate,
            [
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'TLS Server'
        )


class LocalDomainCredentialIssuer(BaseTlsCredentialIssuer):
    """Handles issuing domain credentials."""

    DOMAIN_CREDENTIAL_CN = 'Trustpoint Domain Credential'

    _pseudonym = DOMAIN_CREDENTIAL_CN

    def issue_domain_credential(
        self,
        application_uri: str | None = None,
        extra_extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    ) -> IssuedCredentialModel:
        """Issues a domain credential for a device.

        Args:
            application_uri: Optional application URI to include in the certificate.
            extra_extensions: Optional list of additional certificate extensions to include.
                If provided, these will override the default extensions (except BasicConstraints).

        Returns:
            The issued domain credential model.
        """
        private_key = KeyGenerator.generate_private_key(domain=self.domain)
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()

        if extra_extensions is None:
            extensions = [(x509.BasicConstraints(ca=False, path_length=None), True)]
            if application_uri:
                extensions.append(
                    (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)]), False)
                )
        else:
            extensions = [(x509.BasicConstraints(ca=False, path_length=None), True)]
            extensions.extend(extra_extensions)
            if application_uri:
                has_san = any(isinstance(ext, x509.SubjectAlternativeName) for ext, _ in extra_extensions)
                if not has_san:
                    extensions.append(
                        (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)]), False)
                    )

        certificate = self._build_certificate(
            common_name=self._pseudonym,
            public_key=private_key.public_key_serializer.as_crypto(),
            validity_days=365,
            extra_extensions=extensions,
        )

        cert_chain = (
            issuing_credential.get_credential_serializer()
            .get_full_chain_as_crypto()
        )
        credential = CredentialSerializer(
            private_key=private_key.as_crypto(), certificate=certificate, additional_certificates=cert_chain
        )

        issued_domain_credential = self._save(
            credential=credential,
            common_name=self._pseudonym,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            issued_using_cert_profile='Trustpoint Domain Credential',
        )

        # Only mark as onboarded if NOT OPC UA GDS Push
        # For GDS Push, onboarding is complete only after server certificate is updated
        if (
            self.device.onboarding_config
            and self.device.onboarding_config.onboarding_protocol
            != OnboardingProtocol.OPC_GDS_PUSH
        ):
            self.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            self.device.onboarding_config.save()

        self.device.save()

        return issued_domain_credential

    def issue_domain_credential_certificate(
        self,
        public_key: PublicKey,
        extra_extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    ) -> IssuedCredentialModel:
        """Issues a domain credential certificate.

        Args:
            public_key: The public key associated with the issued certificate.
            extra_extensions: Optional list of additional certificate extensions to include.
                If provided, these will override the default extensions (except BasicConstraints).

        Returns:
            The issued domain credential certificate model.
        """
        # TODO(AlexHx8472): Check matching public_key and signature suite.  # noqa: FIX002

        if extra_extensions is None:
            # Use default extensions
            extensions = [(x509.BasicConstraints(ca=False, path_length=None), True)]
        else:
            # Use provided extensions, but ensure BasicConstraints is always included
            extensions = [(x509.BasicConstraints(ca=False, path_length=None), True)]
            extensions.extend(extra_extensions)

        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()

        certificate = self._build_certificate(
            common_name=self._pseudonym,
            public_key=public_key,
            validity_days=365,
            extra_extensions=extensions,
        )

        issued_domain_credential = self._save_keyless_credential(
            certificate=certificate,
            certificate_chain=[
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
            common_name=self._pseudonym,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            issued_using_cert_profile='Trustpoint Domain Credential'
        )

        # Only mark as onboarded if NOT OPC UA GDS Push
        # For GDS Push, onboarding is complete only after server certificate is updated
        if (
            self.device.onboarding_config
            and self.device.onboarding_config.onboarding_protocol
            != OnboardingProtocol.OPC_GDS_PUSH
        ):
            self.device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            self.device.onboarding_config.save()

        self.device.save()

        return issued_domain_credential


class OpcUaServerCredentialIssuer(BaseTlsCredentialIssuer):
    """Issues OPC UA server credentials."""

    _pseudonym = 'Trustpoint OPC UA Server Credential'

    def _build_san_extension(
        self,
        application_uri: str,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
    ) -> x509.SubjectAlternativeName:
        """Builds the Subject Alternative Name (SAN) extension for OPC UA server certificates."""
        return x509.SubjectAlternativeName(
            [
                x509.UniformResourceIdentifier(application_uri),
                *map(x509.IPAddress, ipv4_addresses),
                *map(x509.IPAddress, ipv6_addresses),
                *map(x509.DNSName, domain_names),
            ]
        )

    def _get_key_usage(self, public_key: PublicKey) -> x509.KeyUsage:
        """Determines Key Usage based on RSA vs ECC."""
        if isinstance(public_key, rsa.RSAPublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        err_msg = 'Unsupported key type for OPC UA Server Certificate'
        raise ValueError(err_msg)

    def _validate_application_uri(self, application_uri: str | list[str]) -> None:
        """Validates the Uniform resource identifier according to OPC UA specification."""
        if isinstance(application_uri, list) and len(application_uri) == 0:
            error_message = 'Application URI cannot be empty'
            raise ValueError(error_message)

        if isinstance(application_uri, list) and len(application_uri) > 1:
            errror_message = 'Application URI cannot be longer than 1 item'
            raise ValueError(errror_message)

    def issue_opc_ua_server_credential(  # noqa: PLR0913
        self,
        common_name: str,
        application_uri: str,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
        validity_days: int = 365,
    ) -> IssuedCredentialModel:
        """Issues an OPC UA server credential (certificate + private key) following OPC UA security standards."""
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()

        self._validate_application_uri(application_uri)

        private_key = KeyGenerator.generate_private_key(domain=self.domain)
        public_key = private_key.public_key_serializer.as_crypto()
        san_extension = self._build_san_extension(application_uri, ipv4_addresses, ipv6_addresses, domain_names)
        key_usage = self._get_key_usage(public_key)

        certificate = self._build_certificate(
            common_name,
            private_key.public_key_serializer.as_crypto(),
            validity_days,
            [
                (key_usage, True),
                (
                    x509.ExtendedKeyUsage(
                        [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
                    ),
                    False,
                ),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False),
            ],
        )

        cert_chain = (
            issuing_credential
            .get_credential_serializer()
            .get_full_chain_as_crypto()
        )
        credential = CredentialSerializer(
            private_key=private_key.as_crypto(), certificate=certificate, additional_certificates=cert_chain
        )

        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'OPC UA Server'
        )

    def issue_opc_ua_server_certificate(  # noqa: PLR0913
        self,
        common_name: str,
        application_uri: str | list[str],
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
        validity_days: int,
        public_key: PublicKey,
    ) -> IssuedCredentialModel:
        """Issues an OPC UA server certificate (no private key) following OPC UA security standards."""
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()
        self._validate_application_uri(application_uri)
        if isinstance(application_uri, list):
            application_uri = application_uri[0]

        san_extension = self._build_san_extension(application_uri, ipv4_addresses, ipv6_addresses, domain_names)
        key_usage = self._get_key_usage(public_key)

        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [
                (key_usage, True),
                (
                    x509.ExtendedKeyUsage(
                        [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
                    ),
                    False,
                ),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False),
            ],
        )

        return self._save_keyless_credential(
            certificate,
            [
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'OPC UA Server',
        )


class OpcUaClientCredentialIssuer(BaseTlsCredentialIssuer):
    """Issues OPC UA client credentials."""

    _pseudonym = 'Trustpoint OPC UA Client Credential'

    def _build_san_extension(self, application_uri: str) -> x509.SubjectAlternativeName:
        """Builds the Subject Alternative Name (SAN) extension for OPC UA client certificates."""
        return x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)])

    def _get_key_usage(self, public_key: PublicKey) -> x509.KeyUsage:
        """Determines Key Usage based on RSA vs ECC."""
        if isinstance(public_key, rsa.RSAPublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        err_msg = 'Unsupported key type for OPC UA Client Certificate'
        raise ValueError(err_msg)

    def _validate_application_uri(self, application_uri: str | list[str]) -> None:
        """Validates the Uniform resource identifier according to OPC UA specification."""
        if isinstance(application_uri, list) and len(application_uri) == 0:
            error_message = 'Application URI cannot be empty'
            raise ValueError(error_message)

        if isinstance(application_uri, list) and len(application_uri) > 1:
            error_message = 'Application URI cannot be longer than 1 item'
            raise ValueError(error_message)

    def issue_opc_ua_client_credential(
        self, common_name: str, application_uri: str | list[str], validity_days: int = 365
    ) -> IssuedCredentialModel:
        """Issues an OPC UA client credential (certificate + private key) following OPC UA security standards."""
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()
        self._validate_application_uri(application_uri)
        if isinstance(application_uri, list):
            application_uri = application_uri[0]

        private_key = KeyGenerator.generate_private_key(domain=self.domain)
        public_key = private_key.public_key_serializer.as_crypto()
        san_extension = self._build_san_extension(application_uri)
        key_usage = self._get_key_usage(public_key)

        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [
                (key_usage, True),
                (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False),
            ],
        )

        cert_chain = (
            issuing_credential.get_credential_serializer().get_full_chain_as_crypto()
        )
        credential = CredentialSerializer(
            private_key=private_key.as_crypto(), certificate=certificate, additional_certificates=cert_chain
        )

        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'OPC UA Client',
        )

    def issue_opc_ua_client_certificate(
        self, common_name: str, application_uri: str | list[str], validity_days: int, public_key: PublicKey
    ) -> IssuedCredentialModel:
        """Issues an OPC UA client certificate (no private key) following OPC UA security standards."""
        issuing_credential = self.domain.get_issuing_ca_or_value_error().get_credential()
        self._validate_application_uri(application_uri)
        if isinstance(application_uri, list):
            application_uri = application_uri[0]

        san_extension = self._build_san_extension(application_uri)
        key_usage = self._get_key_usage(public_key)

        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [
                (key_usage, True),
                (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False),
            ],
        )

        return self._save_keyless_credential(
            certificate,
            [
                issuing_credential.get_certificate(),
                *issuing_credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            'OPC UA Client',
        )
