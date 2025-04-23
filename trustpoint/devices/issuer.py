"""Module for issuing and managing TLS and OPC UA credentials."""

from __future__ import annotations

import datetime
import re
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pki.models.credential import CredentialModel
from pki.util.keys import KeyGenerator
from trustpoint_core import oid  # type: ignore[import-untyped]
from trustpoint_core.serializer import CredentialSerializer  # type: ignore[import-untyped]

from devices.models import DeviceModel, IssuedCredentialModel

if TYPE_CHECKING:
    import ipaddress

    from pki.models.domain import DomainModel


class SaveCredentialToDbMixin:
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
        issued_credential_purpose: IssuedCredentialModel.IssuedCredentialPurpose,
    ) -> IssuedCredentialModel:
        """Saves the issued credential in the database.

        Args:
            credential (CredentialSerializer): The credential serializer instance.
            common_name (str): The common name for the credential.
            issued_credential_type (IssuedCredentialModel.IssuedCredentialType): The type of issued credential.
            issued_credential_purpose (IssuedCredentialModel.IssuedCredentialPurpose):
                The purpose of the issued credential.

        Returns:
            IssuedCredentialModel: The saved issued credential model.
        """
        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential, credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
        )

        issued_credential_model = IssuedCredentialModel(
            issued_credential_type=issued_credential_type,
            issued_credential_purpose=issued_credential_purpose,
            common_name=common_name,
            credential=credential_model,
            device=self.device,
            domain=self.domain,
        )

        issued_credential_model.save()

        return issued_credential_model

    def _save_keyless_credential(
        self,
        certificate: x509.Certificate,
        certificate_chain: list[x509.Certificate],
        common_name: str,
        issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
        issued_credential_purpose: IssuedCredentialModel.IssuedCredentialPurpose,
    ) -> IssuedCredentialModel:
        # check for existing issued credentials
        existing_credentials = IssuedCredentialModel.objects.filter(
            device=self.device,
            domain=self.domain,
            issued_credential_type=issued_credential_type,
            issued_credential_purpose=issued_credential_purpose,
            common_name=common_name,
        )
        for issued_credential in existing_credentials:
            cred_model: CredentialModel = issued_credential.credential
            if cred_model.certificate.subjects_match(certificate):
                # if the certificate already exists, we need to update the certificate (e.g. reenroll)
                cred_model.update_keyless_credential(
                    certificate, certificate_chain
                )
                cred_model.save()
                return issued_credential

        credential_model = CredentialModel.save_keyless_credential(
            certificate=certificate,
            certificate_chain=certificate_chain,
            credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL,
        )

        issued_credential_model = IssuedCredentialModel(
            issued_credential_type=issued_credential_type,
            issued_credential_purpose=issued_credential_purpose,
            common_name=common_name,
            credential=credential_model,
            device=self.device,
            domain=self.domain,
        )

        issued_credential_model.save()

        return issued_credential_model


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
            device (DeviceModel): The device for which the credential is issued.
            domain (DomainModel): The domain associated with the credential.
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
            device (DeviceModel): The device for which credentials are issued.
            domain (DomainModel): The domain associated with the credentials.

        Returns:
            dict[str, str]: A dictionary containing the pseudonym, domain component,
            and serial number of the device.
        """
        return {
            'pseudonym': cls._pseudonym,
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

    def _build_certificate(
        self,
        common_name: str,
        public_key: oid.PublicKey,
        validity_days: int,
        extra_extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    ) -> x509.Certificate:
        """Builds an X.509 certificate with the specified parameters.

        Args:
            common_name (str): The common name (CN) for the certificate subject.
            public_key (oid.PublicKey): The public key associated with the certificate.
            validity_days (int): The number of days the certificate should be valid.
            extra_extensions (list[tuple[x509.ExtensionType, bool]], optional): Additional extensions to be added.

        Returns:
            x509.Certificate: The generated X.509 certificate.
        """
        issuing_credential = self.domain.issuing_ca.credential
        issuer_certificate = issuing_credential.get_certificate()
        hash_algorithm = oid.SignatureSuite.from_certificate(
            issuer_certificate
        ).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(days=1)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(x509.NameOID.PSEUDONYM, self.pseudonym),
                    x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
                    x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number),
                    x509.NameAttribute(x509.NameOID.USER_ID, str(self.device.pk)),
                ]
            )
        )
        certificate_builder = certificate_builder.issuer_name(
            self.domain.issuing_ca.credential.get_certificate().subject
        )
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
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

        return certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm,
        )


class LocalTlsClientCredentialIssuer(BaseTlsCredentialIssuer):
    """Handles issuing TLS client credentials."""

    _pseudonym = 'Trustpoint Application Credential - TLS Client'

    def issue_tls_client_credential(self, common_name: str, validity_days: int) -> IssuedCredentialModel:
        """Issues a TLS client credential.

        Args:
            common_name (str): The common name for the certificate.
            validity_days (int): The validity period in days.
            public_key (oid.PublicKey): The public key to be included in the certificate.

        Returns:
            IssuedCredentialModel: The issued credential model.
        """
        private_key = KeyGenerator.generate_private_key(domain=self.domain)

        san_uri = re.sub(r'[^a-zA-Z0-9_.-]', '', common_name) + '.alt'
        certificate = self._build_certificate(
            common_name,
            private_key.public_key_serializer.as_crypto(),
            validity_days,
            [
                (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False),
                # TODO(Air): This is a workaround for cryptography < 45.0.0 requiring a SAN to verify the (IDevID) cert.
                (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]), False),
            ],
        )
        credential = CredentialSerializer(
            (
                private_key,
                certificate,
                [
                    self.domain.issuing_ca.credential.get_certificate(),
                    *self.domain.issuing_ca.credential.get_certificate_chain(),
                ],
            )
        )
        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT,
        )

    def issue_tls_client_certificate(
        self, common_name: str, validity_days: int, public_key: oid.PublicKey
    ) -> IssuedCredentialModel:
        """Issues a TLS client certificate without a private key.

        Args:
            common_name (str): Certificate common name.
            validity_days (int): Certificate validity period.
            public_key (oid.PublicKey): Public key for the certificate.

        Returns:
            IssuedCredentialModel: The issued TLS client certificate.
        """
        san_uri = re.sub(r'[^a-zA-Z0-9_.-]', '', common_name) + '.alt'
        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [
                (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False),
                # TODO (Air): This is a workaround for cryptography < 45.0.0 requiring a SAN to verify the certificate.
                (x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]), False),
            ],
        )
        return self._save_keyless_credential(
            certificate,
            [
                self.domain.issuing_ca.credential.get_certificate(),
                *self.domain.issuing_ca.credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT,
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
            common_name (str): Certificate common name.
            ipv4_addresses (list[ipaddress.IPv4Address]): IPv4 addresses for SAN.
            ipv6_addresses (list[ipaddress.IPv6Address]): IPv6 addresses for SAN.
            domain_names (list[str]): Domain names for SAN.
            validity_days (int): Certificate validity period.
            san_critical (bool, optional): Whether SAN is critical. Defaults to False.

        Returns:
            IssuedCredentialModel: The issued TLS server credential.
        """
        private_key = KeyGenerator.generate_private_key(domain=self.domain)
        san_extension = self._build_san_extension(ipv4_addresses, ipv6_addresses, domain_names)

        certificate = self._build_certificate(
            common_name,
            private_key.public_key_serializer.as_crypto(),
            validity_days,
            [(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False), (san_extension, san_critical)],
        )
        credential = CredentialSerializer(
            (
                private_key,
                certificate,
                [
                    self.domain.issuing_ca.credential.get_certificate(),
                    *self.domain.issuing_ca.credential.get_certificate_chain(),
                ],
            )
        )
        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER,
        )

    def issue_tls_server_certificate(  # noqa: PLR0913
        self,
        common_name: str,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
        validity_days: int,
        public_key: oid.PublicKey,
        *,
        san_critical: bool = False,
    ) -> IssuedCredentialModel:
        """Issues a TLS server certificate without a private key.

        Args:
            common_name (str): Certificate common name.
            ipv4_addresses (list[ipaddress.IPv4Address]): IPv4 addresses for SAN.
            ipv6_addresses (list[ipaddress.IPv6Address]): IPv6 addresses for SAN.
            domain_names (list[str]): Domain names for SAN.
            validity_days (int): Certificate validity period.
            public_key (oid.PublicKey): Public key for the certificate.
            san_critical (bool, optional): Whether SAN is critical. Defaults to False.

        Returns:
            IssuedCredentialModel: The issued TLS server certificate.
        """
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
                self.domain.issuing_ca.credential.get_certificate(),
                *self.domain.issuing_ca.credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER,
        )


class LocalDomainCredentialIssuer(BaseTlsCredentialIssuer):
    """Handles issuing domain credentials."""

    _pseudonym = 'Trustpoint Domain Credential'

    def issue_domain_credential(self) -> IssuedCredentialModel:
        """Issues a domain credential for a device.

        Returns:
            IssuedCredentialModel: The issued domain credential model.
        """
        private_key = KeyGenerator.generate_private_key(domain=self.domain)

        certificate = self._build_certificate(
            common_name=self._pseudonym,
            public_key=private_key.public_key_serializer.as_crypto(),
            validity_days=365,
            extra_extensions=[(x509.BasicConstraints(ca=False, path_length=None), True)],
        )

        credential = CredentialSerializer(
            (
                private_key,
                certificate,
                [
                    self.domain.issuing_ca.credential.get_certificate(),
                    *self.domain.issuing_ca.credential.get_certificate_chain(),
                ],
            )
        )

        issued_domain_credential = self._save(
            credential=credential,
            common_name=self._pseudonym,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL,
        )

        self.device.onboarding_status = self.device.OnboardingStatus.ONBOARDED
        self.device.save()

        return issued_domain_credential

    def issue_domain_credential_certificate(self, public_key: oid.PublicKey) -> IssuedCredentialModel:
        """Issues a domain credential certificate.

        Args:
            public_key (oid.PublicKey): The public key associated with the issued certificate.

        Returns:
            IssuedCredentialModel: The issued domain credential certificate model.
        """
        # TODO(AlexHx8472): Check matching public_key and signature suite.  # noqa: FIX002

        certificate = self._build_certificate(
            common_name=self._pseudonym,
            public_key=public_key,
            validity_days=365,
            extra_extensions=[(x509.BasicConstraints(ca=False, path_length=None), True)],
        )

        issued_domain_credential = self._save_keyless_credential(
            certificate=certificate,
            certificate_chain=[
                self.domain.issuing_ca.credential.get_certificate(),
                *self.domain.issuing_ca.credential.get_certificate_chain(),
            ],
            common_name=self._pseudonym,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL,
        )

        self.device.onboarding_status = self.device.OnboardingStatus.ONBOARDED
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

    def _get_key_usage(self, public_key: oid.PublicKey) -> x509.KeyUsage:
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
        """Validates the Uniform resource identifier according to OPC UA specification"""

        if isinstance(application_uri, list) and len(application_uri) == 0:
            raise ValueError('Application URI cannot be empty')

        if isinstance(application_uri, list) and len(application_uri) > 1:
            raise ValueError('Application URI cannot be longer than 1 item')

    def issue_opcua_server_credential(  # noqa: PLR0913
        self,
        common_name: str,
        application_uri: str | list[str],
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
        validity_days: int = 365,
    ) -> IssuedCredentialModel:
        """Issues an OPC UA server credential (certificate + private key) following OPC UA security standards."""

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

        credential = CredentialSerializer(
            (
                private_key,
                certificate,
                [
                    self.domain.issuing_ca.credential.get_certificate(),
                    *self.domain.issuing_ca.credential.get_certificate_chain(),
                ],
            )
        )

        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_SERVER,
        )

    def issue_opcua_server_certificate(  # noqa: PLR0913
        self,
        common_name: str,
        application_uri: str | list[str],
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
        validity_days: int,
        public_key: oid.PublicKey,
    ) -> IssuedCredentialModel:
        """Issues an OPC UA server certificate (no private key) following OPC UA security standards."""
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
                self.domain.issuing_ca.credential.get_certificate(),
                *self.domain.issuing_ca.credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_SERVER,
        )


class OpcUaClientCredentialIssuer(BaseTlsCredentialIssuer):
    """Issues OPC UA client credentials."""

    _pseudonym = 'Trustpoint OPC UA Client Credential'

    def _build_san_extension(self, application_uri: str) -> x509.SubjectAlternativeName:
        """Builds the Subject Alternative Name (SAN) extension for OPC UA client certificates."""
        return x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)])

    def _get_key_usage(self, public_key: oid.PublicKey) -> x509.KeyUsage:
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
        """Validates the Uniform resource identifier according to OPC UA specification"""

        if isinstance(application_uri, list) and len(application_uri) == 0:
            raise ValueError('Application URI cannot be empty')

        if isinstance(application_uri, list) and len(application_uri) > 1:
            raise ValueError('Application URI cannot be longer than 1 item')

    def issue_opcua_client_credential(
        self, common_name: str, application_uri: str | list[str], validity_days: int = 365
    ) -> IssuedCredentialModel:
        """Issues an OPC UA client credential (certificate + private key) following OPC UA security standards."""

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

        credential = CredentialSerializer(
            (
                private_key,
                certificate,
                [
                    self.domain.issuing_ca.credential.get_certificate(),
                    *self.domain.issuing_ca.credential.get_certificate_chain(),
                ],
            )
        )

        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_CLIENT,
        )

    def issue_opcua_client_certificate(
        self, common_name: str, application_uri: str | list[str], validity_days: int, public_key: oid.PublicKey
    ) -> IssuedCredentialModel:
        """Issues an OPC UA client certificate (no private key) following OPC UA security standards."""

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
                self.domain.issuing_ca.credential.get_certificate(),
                *self.domain.issuing_ca.credential.get_certificate_chain(),
            ],
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_CLIENT,
        )
