from __future__ import annotations

import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, cast

from trustpoint_core.serializer import CredentialSerializer
from trustpoint_core import oid

from cryptography import x509
from pki.models import CredentialModel, DomainModel
from pki.util.keys import KeyGenerator

from devices.models import DeviceModel, IssuedCredentialModel

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



class LocalDomainCredentialIssuer(SaveCredentialToDbMixin):

    _common_name: str = 'Trustpoint Domain Credential'
    _device: DeviceModel
    _domain: DomainModel

    _credential: None | CredentialSerializer = None
    _credential_model: None | CredentialModel = None
    _issued_domain_credential_model: None | LocalDomainCredentialIssuer = None

    def __init__(self, device: DeviceModel, domain: DomainModel) -> None:
        self._device = device
        self._domain = domain

    @property
    def device(self) -> DeviceModel:
        return self._device

    @device.setter
    def device(self, device: DeviceModel) -> None:
        self._device = device

    @property
    def domain(self) -> DomainModel:
        return self._domain

    @domain.setter
    def domain(self, domain: DomainModel) -> None:
        self._domain = domain

    @property
    def serial_number(self) -> str:
        return self.device.serial_number

    @property
    def domain_component(self) -> str:
        return self.domain.unique_name

    @property
    def common_name(self) -> str:
        return self._common_name

    @classmethod
    def get_fixed_values(cls, device: DeviceModel, domain: DomainModel) -> dict[str, str]:
        return {
            'common_name': cls._common_name,
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number
        }

    def issue_domain_credential(self) -> IssuedCredentialModel:
        certificate_builder = x509.CertificateBuilder()
        domain_credential_private_key = KeyGenerator.generate_private_key(domain=self.domain)
        public_key = domain_credential_private_key.public_key_serializer.as_crypto()


        # TODO(AlexHx8472): Check matching public_key and signature suite.

        hash_algorithm = oid.SignatureSuite.from_certificate(
            self.domain.issuing_ca.credential.get_certificate()).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(1, 0, 0)


        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name),
            x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number),
            x509.NameAttribute(x509.NameOID.USER_ID, str(self.device.pk))
        ]))
        certificate_builder = certificate_builder.issuer_name(
            self.domain.issuing_ca.credential.get_certificate().subject)
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        certificate_builder = certificate_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + (one_day * 365))
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.public_key(public_key)
        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        cert_chain =  (
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain())

        if domain_credential_private_key:
            credential = CredentialSerializer(
                (
                    domain_credential_private_key,
                    domain_certificate,
                    cert_chain
                )
            )

            issued_domain_credential = self._save(
                credential=credential,
                common_name=self.common_name,
                issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL
            )
        else:
            issued_domain_credential = self._save_keyless_credential(
                certificate=domain_certificate,
                certificate_chain=cert_chain,
                common_name=self.common_name,
                issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL
            )

        self.device.onboarding_status = self.device.OnboardingStatus.ONBOARDED
        self.device.save()

        return issued_domain_credential

    def issue_domain_credential_certificate(self, public_key: oid.PublicKey ) -> IssuedCredentialModel:
        certificate_builder = x509.CertificateBuilder()

        # TODO(AlexHx8472): Check matching public_key and signature suite.

        hash_algorithm = oid.SignatureSuite.from_certificate(
            self.domain.issuing_ca.credential.get_certificate()).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(1, 0, 0)

        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name),
            x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, self.domain_component),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.serial_number),
            x509.NameAttribute(x509.NameOID.USER_ID, str(self.device.pk))
        ]))
        certificate_builder = certificate_builder.issuer_name(
            self.domain.issuing_ca.credential.get_certificate().subject)
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        certificate_builder = certificate_builder.not_valid_after(
            datetime.datetime.now(datetime.UTC) + (one_day * 365))
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.public_key(public_key)
        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        cert_chain = (
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain())

        issued_domain_credential = self._save_keyless_credential(
            certificate=domain_certificate,
            certificate_chain=cert_chain,
            common_name=self.common_name,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL
        )

        self.device.onboarding_status = self.device.OnboardingStatus.ONBOARDED
        self.device.save()

        return issued_domain_credential


class LocalTlsClientCredentialIssuer(SaveCredentialToDbMixin):

    _pseudonym: str = 'Trustpoint Application Credential - TLS Client'
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

    @device.setter
    def device(self, device: DeviceModel) -> None:
        self._device = device

    @property
    def domain(self) -> DomainModel:
        return self._domain

    @domain.setter
    def domain(self, domain: DomainModel) -> None:
        self._domain = domain

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
    def get_fixed_values(cls, domain: DomainModel, device: DeviceModel) -> dict[str, str]:
        return {
            'pseudonym': cls._pseudonym,
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number
        }

    # TODO(AlexHx8472): Reduce code duplication
    def issue_tls_client_credential(self, common_name: str, validity_days: int) -> IssuedCredentialModel:

        application_credential_private_key = KeyGenerator.generate_private_key(domain=self.domain)
        application_credential_public_key = application_credential_private_key.public_key_serializer.as_crypto()
        hash_algorithm = oid.SignatureSuite.from_certificate(
            self.domain.issuing_ca.credential.get_certificate()).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(1, 0, 0)


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
        certificate_builder = certificate_builder.public_key(application_credential_public_key)

        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(application_credential_public_key),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )

        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        credential = CredentialSerializer(
            (
                application_credential_private_key,
                domain_certificate,
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain()
            )
        )

        return self._save(
            credential=credential,
            common_name=common_name,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT
        )

    def issue_tls_client_certificate(
            self,
            common_name: str,
            validity_days: int,
            public_key: oid.PublicKey
    ) -> IssuedCredentialModel:

        hash_algorithm = oid.SignatureSuite.from_certificate(
            self.domain.issuing_ca.credential.get_certificate()).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(1, 0, 0)

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

        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )

        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        return self._save_keyless_credential(
            certificate=domain_certificate,
            certificate_chain=[self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain(),
            common_name=common_name,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT
        )


class LocalTlsServerCredentialIssuer(SaveCredentialToDbMixin):

    _pseudonym: str = 'Trustpoint Application Credential - TLS Server'
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

    @device.setter
    def device(self, device: DeviceModel) -> None:
        self._device = device

    @property
    def domain(self) -> DomainModel:
        return self._domain

    @domain.setter
    def domain(self, domain: DomainModel) -> None:
        self._domain = domain

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

    def issue_tls_server_credential(
            self,
            common_name: str,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str],
            validity_days: int
    ) -> IssuedCredentialModel:
        application_credential_private_key = KeyGenerator.generate_private_key(domain=self.domain)
        hash_algorithm = oid.SignatureSuite.from_certificate(
            self.domain.issuing_ca.credential.get_certificate()).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(1, 0, 0)

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
        certificate_builder = certificate_builder.public_key(
            application_credential_private_key.public_key_serializer.as_crypto())

        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(application_credential_private_key.public_key_serializer.as_crypto()),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )

        general_names: list[x509.GeneralName] = (
            [x509.IPAddress(ipv4_address) for ipv4_address  in ipv4_addresses] +
            [x509.IPAddress(ipv6_address) for ipv6_address  in ipv6_addresses] +
            [x509.DNSName(domain_name) for domain_name in domain_names]
        )

        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName(
                general_names
            ),
            critical=False
        )
        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )
        credential = CredentialSerializer(
            (
                application_credential_private_key,
                domain_certificate,
                [self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain()
            )
        )

        return self._save(
            credential=credential,
            common_name=common_name,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER
        )

    def issue_tls_server_certificate(
            self,
            common_name: str,
            ipv4_addresses: list[ipaddress.IPv4Address],
            ipv6_addresses: list[ipaddress.IPv6Address],
            domain_names: list[str],
            san_critical: bool,
            validity_days: int,
            public_key: oid.PublicKey
    ) -> IssuedCredentialModel:

        hash_algorithm = oid.SignatureSuite.from_certificate(
            self.domain.issuing_ca.credential.get_certificate()).algorithm_identifier.hash_algorithm.hash_algorithm()
        one_day = datetime.timedelta(1, 0, 0)

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

        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.domain.issuing_ca.credential.get_private_key_serializer().public_key_serializer.as_crypto()
            ),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )

        general_names: list[x509.GeneralName] = (
            [x509.IPAddress(ipv4_address) for ipv4_address  in ipv4_addresses] +
            [x509.IPAddress(ipv6_address) for ipv6_address  in ipv6_addresses] +
            [x509.DNSName(domain_name) for domain_name in domain_names]
        )

        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName(
                general_names
            ),
            critical=san_critical
        )
        domain_certificate = certificate_builder.sign(
            private_key=self.domain.issuing_ca.credential.get_private_key_serializer().as_crypto(),
            algorithm=hash_algorithm
        )

        return self._save_keyless_credential(
            certificate=domain_certificate,
            certificate_chain=[self.domain.issuing_ca.credential.get_certificate()] +
                self.domain.issuing_ca.credential.get_certificate_chain(),
            common_name=common_name,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_SERVER
        )
