"""Logic for generating and importing staged TLS server credentials."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ExtendedKeyUsageOID, NameOID
from cryptography.x509 import ExtensionNotFound
from pki.util.x509 import CertificateVerifier
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

if TYPE_CHECKING:
    import ipaddress

    from pki.models import CredentialModel

ONE_DAY = datetime.timedelta(days=1)


def extract_staged_tls_sans(tls_credential: CredentialModel | None) -> tuple[list[str], list[str], list[str]]:
    """Extract SAN values from a staged TLS credential."""
    if tls_credential is None or tls_credential.certificate is None:
        return [], [], []

    certificate = tls_credential.certificate
    san_extension = certificate.subject_alternative_name_extension
    if san_extension is None:
        return [], [], []

    general_names = san_extension.subject_alt_name
    if general_names is None:
        return [], [], []

    ip_address_model = general_names.ip_addresses.model
    ipv4_addresses = [
        entry.value
        for entry in general_names.ip_addresses.filter(ip_type=ip_address_model.IpType.IPV4_ADDRESS)
    ]
    ipv6_addresses = [
        entry.value
        for entry in general_names.ip_addresses.filter(ip_type=ip_address_model.IpType.IPV6_ADDRESS)
    ]
    dns_names = [entry.value for entry in general_names.dns_names.all()]
    return ipv4_addresses, ipv6_addresses, dns_names


class TlsServerCredentialGenerator:
    """Wrap methods for generating a TLS server credential."""

    def __init__(
        self,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
    ) -> None:
        self._ipv4_addresses = ipv4_addresses
        self._ipv6_addresses = ipv6_addresses
        self._domain_names = domain_names

    @staticmethod
    def _generate_key_pair() -> PrivateKeySerializer:
        return PrivateKeySerializer(ec.generate_private_key(curve=ec.SECP256R1()))

    def generate_tls_server_credential(self) -> CredentialSerializer:
        """Generate a self-signed TLS credential for use by the Trustpoint server."""
        one_day = datetime.timedelta(1, 0, 0)
        private_key = ec.generate_private_key(curve=ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint Self-Signed TLS Server Credential'),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint Self-Signed TLS Server Credential'),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.now(tz=datetime.UTC) - one_day)
        builder = builder.not_valid_after(datetime.datetime.now(tz=datetime.UTC) + (one_day * 365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=False,
        )
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        builder = builder.add_extension(
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
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        san = (
            [x509.IPAddress(ipv4) for ipv4 in self._ipv4_addresses]
            + [x509.IPAddress(ipv6) for ipv6 in self._ipv6_addresses]
            + [x509.DNSName(domain) for domain in self._domain_names]
        )
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=True)

        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        return CredentialSerializer(
            private_key=private_key, certificate=certificate, additional_certificates=[certificate]
        )


class TlsServerCredentialFileParser:
    """Build staged TLS server credentials from uploaded files."""

    @staticmethod
    def _encode_password(password: str | None, field_name: str) -> bytes | None:
        if not password:
            return None
        try:
            return password.encode('utf-8')
        except UnicodeError as exception:
            err_msg = f'The {field_name} contains invalid UTF-8 data.'
            raise ValueError(err_msg) from exception

    @staticmethod
    def _parse_certificates(raw_bytes: bytes) -> list[x509.Certificate]:
        try:
            return list(CertificateCollectionSerializer.from_bytes(raw_bytes).as_crypto())
        except Exception:
            pass

        try:
            return [CertificateSerializer.from_bytes(raw_bytes).as_crypto()]
        except Exception as exception:
            err_msg = 'Failed to parse the certificate file.'
            raise ValueError(err_msg) from exception

    @staticmethod
    def _is_ca_certificate(certificate: x509.Certificate) -> bool:
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        except ExtensionNotFound:
            return False
        return basic_constraints.ca

    @classmethod
    def _is_tls_server_certificate(cls, certificate: x509.Certificate) -> bool:
        if cls._is_ca_certificate(certificate):
            return False
        try:
            eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except ExtensionNotFound:
            return False
        return ExtendedKeyUsageOID.SERVER_AUTH in eku

    @classmethod
    def _get_single_end_entity_certificate(cls, certificates: list[x509.Certificate]) -> x509.Certificate:
        ee_certificates = [certificate for certificate in certificates if not cls._is_ca_certificate(certificate)]
        if len(ee_certificates) != 1:
            err_msg = 'Expected exactly one end-entity TLS server certificate.'
            raise ValueError(err_msg)

        end_entity_certificate = ee_certificates[0]
        if not cls._is_tls_server_certificate(end_entity_certificate):
            err_msg = 'The end-entity certificate is not a valid TLS server certificate.'
            raise ValueError(err_msg)
        return end_entity_certificate

    @staticmethod
    def _match_private_key(private_key_serializer: PrivateKeySerializer, certificate: x509.Certificate) -> None:
        private_key_public_bytes = private_key_serializer.as_crypto().public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
        certificate_public_bytes = certificate.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
        if private_key_public_bytes != certificate_public_bytes:
            err_msg = 'The provided private key does not match the TLS server certificate.'
            raise ValueError(err_msg)

    @classmethod
    def _find_chain(
        cls,
        current_certificate: x509.Certificate,
        candidates: list[x509.Certificate],
    ) -> list[x509.Certificate] | None:
        if cls._is_ca_certificate(current_certificate) and current_certificate.issuer == current_certificate.subject:
            return [current_certificate]

        for index, candidate in enumerate(candidates):
            if candidate.subject != current_certificate.issuer:
                continue
            try:
                CertificateVerifier._verify_cert_signature(current_certificate, candidate)
            except Exception:
                continue

            remaining_candidates = [*candidates[:index], *candidates[index + 1:]]
            tail = cls._find_chain(candidate, remaining_candidates)
            if tail is not None:
                return [current_certificate, *tail]
        return None

    @classmethod
    def _build_certificate_chain(
        cls,
        end_entity_certificate: x509.Certificate,
        additional_certificates: list[x509.Certificate],
    ) -> list[x509.Certificate]:
        invalid_certificates = [
            certificate
            for certificate in additional_certificates
            if not cls._is_ca_certificate(certificate)
        ]
        if invalid_certificates:
            err_msg = 'Only CA certificates may be included in the certificate chain.'
            raise ValueError(err_msg)

        chain = cls._find_chain(end_entity_certificate, additional_certificates)
        if chain is None or len(chain) < 2:
            err_msg = 'The uploaded certificates do not contain the full chain up to the root CA.'
            raise ValueError(err_msg)
        return chain

    @staticmethod
    def _to_credential_serializer(
        private_key_serializer: PrivateKeySerializer,
        chain: list[x509.Certificate],
    ) -> CredentialSerializer:
        certificate_collection_serializer = CertificateCollectionSerializer(chain[1:])
        return CredentialSerializer.from_serializers(
            private_key_serializer=private_key_serializer,
            certificate_serializer=CertificateSerializer(chain[0]),
            certificate_collection_serializer=certificate_collection_serializer,
        )

    @classmethod
    def build_from_pkcs12_bytes(
        cls,
        pkcs12_raw: bytes,
        pkcs12_password: str | None = None,
    ) -> CredentialSerializer:
        password_bytes = cls._encode_password(pkcs12_password, 'PKCS#12 password')
        try:
            credential_serializer = CredentialSerializer.from_pkcs12_bytes(pkcs12_raw, password_bytes)
        except Exception as exception:
            err_msg = 'Failed to parse and load the uploaded PKCS#12 file. Either wrong password or corrupted file.'
            raise ValueError(err_msg) from exception

        certificate = credential_serializer.certificate
        if certificate is None:
            err_msg = 'The PKCS#12 file does not contain a TLS server certificate.'
            raise ValueError(err_msg)

        private_key_serializer = credential_serializer.get_private_key_serializer()
        if private_key_serializer is None:
            err_msg = 'The PKCS#12 file does not contain a private key.'
            raise ValueError(err_msg)

        chain = cls._build_certificate_chain(
            cls._get_single_end_entity_certificate(
                [certificate, *(credential_serializer.additional_certificates or [])]
            ),
            list(credential_serializer.additional_certificates or []),
        )
        cls._match_private_key(private_key_serializer, chain[0])
        return cls._to_credential_serializer(private_key_serializer, chain)

    @classmethod
    def build_from_separate_files(
        cls,
        tls_server_certificate_raw: bytes,
        further_certificates_raw: list[bytes],
        key_file_raw: bytes,
        key_password: str | None = None,
    ) -> CredentialSerializer:
        password_bytes = cls._encode_password(key_password, 'key password')
        try:
            private_key_serializer = PrivateKeySerializer.from_bytes(key_file_raw, password_bytes)
        except Exception as exception:
            err_msg = 'Failed to parse the private key file. Either wrong password or corrupted file.'
            raise ValueError(err_msg) from exception

        tls_server_certificates = cls._parse_certificates(tls_server_certificate_raw)
        end_entity_certificate = cls._get_single_end_entity_certificate(tls_server_certificates)

        additional_certificates = [
            certificate
            for certificate in tls_server_certificates
            if certificate != end_entity_certificate
        ]
        for further_certificates_file_raw in further_certificates_raw:
            additional_certificates.extend(cls._parse_certificates(further_certificates_file_raw))

        chain = cls._build_certificate_chain(end_entity_certificate, additional_certificates)
        cls._match_private_key(private_key_serializer, chain[0])
        return cls._to_credential_serializer(private_key_serializer, chain)
