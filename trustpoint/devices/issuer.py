from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from trustpoint_core.serializer import CredentialSerializer
from trustpoint_core import oid

from cryptography import x509
from pki.models import CredentialModel
from pki.util.keys import KeyGenerator

from devices.models import DeviceModel, DomainModel, IssuedCredentialModel

if TYPE_CHECKING:
    import ipaddress


class SaveCredentialToDbMixin:
    device: DeviceModel
    domain: DomainModel

    def _save(
            self,
            credential: CredentialSerializer,
            common_name: str,
            issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
            issued_credential_purpose: IssuedCredentialModel.IssuedCredentialPurpose
    ) -> IssuedCredentialModel:
        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential,
            credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
        )

        issued_credential_model = IssuedCredentialModel(
            issued_credential_type=issued_credential_type,
            issued_credential_purpose=issued_credential_purpose,
            common_name=common_name,
            credential=credential_model,
            device=self.device,
            domain=self.domain
        )

        issued_credential_model.save()

        return issued_credential_model

    def _save_keyless_credential(
            self,
            certificate: x509.Certificate,
            certificate_chain: list[x509.Certificate],
            common_name: str,
            issued_credential_type: IssuedCredentialModel.IssuedCredentialType,
            issued_credential_purpose: IssuedCredentialModel.IssuedCredentialPurpose
    ) -> IssuedCredentialModel:
        credential_model = CredentialModel.save_keyless_credential(
            certificate=certificate,
            certificate_chain=certificate_chain,
            credential_type=CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL
        )

        issued_credential_model = IssuedCredentialModel(
            issued_credential_type=issued_credential_type,
            issued_credential_purpose=issued_credential_purpose,
            common_name=common_name,
            credential=credential_model,
            device=self.device,
            domain=self.domain
        )

        issued_credential_model.save()

        return issued_credential_model


class BaseTlsCredentialIssuer(SaveCredentialToDbMixin):
    _pseudonym: str
    _device: DeviceModel
    _domain: DomainModel

    _credential: None | CredentialSerializer = None
    _credential_model: None | CredentialModel = None
    _issued_application_credential_model: None | IssuedCredentialModel = None

    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        return self._device

    @property
    def domain(self) -> DomainModel:
        return self._domain

    @property
    def serial_number(self) -> str:
        return self.device.serial_number

    @property
    def domain_component(self) -> str:
        return self.domain.unique_name

    @property
    def pseudonym(self) -> str:
        return self._pseudonym

    @classmethod
    def get_fixed_values(cls, device: DeviceModel, domain: DomainModel) -> dict[str, str]:
        return {
            'pseudonym': cls._pseudonym,
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number
        }

    def _build_certificate(self,
                           common_name: str,
                           public_key,
                           validity_days: int,
                           extra_extensions: Optional[list[tuple[x509.ExtensionType, bool]]] = None
                           ):
        issuing_credential = self.domain.issuing_ca.credential
        issuer_certificate = issuing_credential.get_certificate()
        hash_algorithm = oid.SignatureSuite.from_certificate(
            issuer_certificate).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(days=1)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(x509.NameOID.PSEUDONYM, self.pseudonym),
            x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number),
            x509.NameAttribute(x509.NameOID.USER_ID, str(self.device.pk))
        ]))
        certificate_builder = certificate_builder.issuer_name(
            self.domain.issuing_ca.credential.get_certificate().subject)
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        certificate_builder = certificate_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + (one_day * validity_days))
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.public_key(public_key)

        default_extensions = {
            x509.BasicConstraints: (x509.BasicConstraints(ca=False, path_length=None), False),
            x509.KeyUsage: (x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), True),
            x509.AuthorityKeyIdentifier: (x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuing_credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ), False),
            x509.SubjectKeyIdentifier: (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
        }

        if extra_extensions:
            for ext, critical in extra_extensions:
                default_extensions[type(ext)] = (ext, critical)

        for ext_type, (ext, critical) in default_extensions.items():
            certificate_builder = certificate_builder.add_extension(ext, critical)

        return certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )


class LocalTlsClientCredentialIssuer(BaseTlsCredentialIssuer):
    _pseudonym = 'Trustpoint Application Credential - TLS Client'

    def issue_tls_client_credential(self, common_name: str, validity_days: int) -> IssuedCredentialModel:
        private_key = KeyGenerator.generate_private_key(domain=self.domain)

        certificate = self._build_certificate(
            common_name,
            private_key.public_key_serializer.as_crypto(),
            validity_days,
            [(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False)]
        )
        credential = CredentialSerializer((
            private_key, certificate,
            [
                self.domain.issuing_ca.credential.get_certificate()] + self.domain.issuing_ca.credential.get_certificate_chain()
        ))
        return self._save(credential, common_name, IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                          IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT)

    def issue_tls_client_certificate(self, common_name: str, validity_days: int, public_key) -> IssuedCredentialModel:
        certificate = self._build_certificate(
            common_name, public_key, validity_days,
            [(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False)]
        )
        return self._save_keyless_credential(certificate, [
            self.domain.issuing_ca.credential.get_certificate()] + self.domain.issuing_ca.credential.get_certificate_chain(),
                                             common_name,
                                             IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                                             IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT)


class LocalTlsServerCredentialIssuer(BaseTlsCredentialIssuer):
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

    def issue_tls_server_credential(
            self,
            common_name: str,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str],
            san_critical: bool,
            validity_days: int,
    ) -> IssuedCredentialModel:
        private_key = KeyGenerator.generate_private_key(domain=self.domain)
        san_extension = self._build_san_extension(ipv4_addresses, ipv6_addresses, domain_names)

        certificate = self._build_certificate(
            common_name,
            private_key.public_key_serializer.as_crypto(),
            validity_days,
            [(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False), (san_extension, san_critical)]
        )
        credential = CredentialSerializer((
            private_key, certificate,
            [
                self.domain.issuing_ca.credential.get_certificate()] + self.domain.issuing_ca.credential.get_certificate_chain()
        ))
        return self._save(credential, common_name, IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                          IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER)

    def issue_tls_server_certificate(self,
                                     common_name: str,
                                     ipv4_addresses: list[ipaddress.IPv4Address],
                                     ipv6_addresses: list[ipaddress.IPv6Address],
                                     domain_names: list[str],
                                     san_critical: bool,
                                     validity_days: int,
                                     public_key: oid.PublicKey) -> IssuedCredentialModel:
        san_extension = self._build_san_extension(ipv4_addresses, ipv6_addresses, domain_names)

        certificate = self._build_certificate(
            common_name, public_key, validity_days,
            [(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False), (san_extension, san_critical)]
        )
        return self._save_keyless_credential(certificate, [
            self.domain.issuing_ca.credential.get_certificate()] + self.domain.issuing_ca.credential.get_certificate_chain(),
                                             common_name,
                                             IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                                             IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER)


class LocalDomainCredentialIssuer(BaseTlsCredentialIssuer):
    _pseudonym = 'Trustpoint Domain Credential'

    def issue_domain_credential(self) -> IssuedCredentialModel:
        private_key = KeyGenerator.generate_private_key(domain=self.domain)

        certificate = self._build_certificate(
            common_name=self._pseudonym,
            public_key=private_key.public_key_serializer.as_crypto(),
            validity_days=365,
            extra_extensions=[
                (x509.BasicConstraints(ca=False, path_length=None), True)
            ]
        )

        credential = CredentialSerializer((
            private_key, certificate,
            [self.domain.issuing_ca.credential.get_certificate()] +
            self.domain.issuing_ca.credential.get_certificate_chain()
        ))

        issued_domain_credential = self._save(
            credential=credential,
            common_name=self._pseudonym,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL
        )

        self.device.onboarding_status = self.device.OnboardingStatus.ONBOARDED
        self.device.save()

        return issued_domain_credential

    def issue_domain_credential_certificate(self, public_key: oid.PublicKey) -> IssuedCredentialModel:

        # TODO(AlexHx8472): Check matching public_key and signature suite.

        certificate = self._build_certificate(
            common_name=self._pseudonym,
            public_key=public_key,
            validity_days=365,
            extra_extensions=[
                (x509.BasicConstraints(ca=False, path_length=None), True)
            ]
        )

        issued_domain_credential = self._save_keyless_credential(
            certificate=certificate,
            certificate_chain=[
                                  self.domain.issuing_ca.credential.get_certificate()] +
                              self.domain.issuing_ca.credential.get_certificate_chain(),
            common_name=self._pseudonym,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL
        )

        self.device.onboarding_status = self.device.OnboardingStatus.ONBOARDED
        self.device.save()

        return issued_domain_credential


class OpcUaServerCredentialIssuer(BaseTlsCredentialIssuer):
    _pseudonym = "Trustpoint OPC UA Server Credential"

    def _build_san_extension(
            self,
            application_uri: str,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str]
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

    def _get_key_usage(self, public_key) -> x509.KeyUsage:
        """Determines Key Usage based on RSA vs ECC."""
        if isinstance(public_key, rsa.RSAPublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        else:
            raise ValueError("Unsupported key type for OPC UA Server Certificate")

    def issue_opcua_server_credential(
            self,
            common_name: str,
            application_uri: str,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str],
            validity_days: int = 365
    ) -> IssuedCredentialModel:
        """
        Issues an OPC UA server credential (certificate + private key) following OPC UA security standards.
        """
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
                (x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
                ]), False),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False)
            ]
        )

        credential = CredentialSerializer((
            private_key, certificate,
            [self.domain.issuing_ca.credential.get_certificate()] +
            self.domain.issuing_ca.credential.get_certificate_chain()
        ))

        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_SERVER
        )

    def issue_opcua_server_certificate(
            self,
            common_name: str,
            application_uri: str,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str],
            validity_days: int,
            public_key: oid.PublicKey
    ) -> IssuedCredentialModel:
        """
        Issues an OPC UA server certificate (no private key) following OPC UA security standards.
        """
        san_extension = self._build_san_extension(application_uri, ipv4_addresses, ipv6_addresses, domain_names)
        key_usage = self._get_key_usage(public_key)

        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [
                (key_usage, True),
                (x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
                ]), False),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False)
            ]
        )

        return self._save_keyless_credential(
            certificate,
            [self.domain.issuing_ca.credential.get_certificate()] +
            self.domain.issuing_ca.credential.get_certificate_chain(),
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_SERVER
        )

class OpcUaClientCredentialIssuer(BaseTlsCredentialIssuer):
    _pseudonym = "Trustpoint OPC UA Client Credential"

    def _build_san_extension(
            self,
            application_uri: str
    ) -> x509.SubjectAlternativeName:
        """Builds the Subject Alternative Name (SAN) extension for OPC UA client certificates."""
        return x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(application_uri)
        ])

    def _get_key_usage(self, public_key) -> x509.KeyUsage:
        """Determines Key Usage based on RSA vs ECC."""
        if isinstance(public_key, rsa.RSAPublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        else:
            raise ValueError("Unsupported key type for OPC UA Client Certificate")

    def issue_opcua_client_credential(
            self,
            common_name: str,
            application_uri: str,
            validity_days: int = 365
    ) -> IssuedCredentialModel:
        """
        Issues an OPC UA client credential (certificate + private key) following OPC UA security standards.
        """
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
                (x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]), False),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False)
            ]
        )

        credential = CredentialSerializer((
            private_key, certificate,
            [self.domain.issuing_ca.credential.get_certificate()] +
            self.domain.issuing_ca.credential.get_certificate_chain()
        ))

        return self._save(
            credential,
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_CLIENT
        )

    def issue_opcua_client_certificate(
            self,
            common_name: str,
            application_uri: str,
            validity_days: int,
            public_key: oid.PublicKey
    ) -> IssuedCredentialModel:
        """
        Issues an OPC UA client certificate (no private key) following OPC UA security standards.
        """
        san_extension = self._build_san_extension(application_uri)
        key_usage = self._get_key_usage(public_key)

        certificate = self._build_certificate(
            common_name,
            public_key,
            validity_days,
            [
                (key_usage, True),
                (x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]), False),
                (x509.BasicConstraints(ca=False, path_length=None), True),
                (san_extension, False)
            ]
        )

        return self._save_keyless_credential(
            certificate,
            [self.domain.issuing_ca.credential.get_certificate()] +
            self.domain.issuing_ca.credential.get_certificate_chain(),
            common_name,
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_CLIENT
        )