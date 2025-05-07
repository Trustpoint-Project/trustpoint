from __future__ import annotations

import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import NameOID
from trustpoint_core.serializer import CredentialSerializer, PrivateKeySerializer

ONE_DAY = datetime.timedelta(days=1)


class Generator:
    def __init__(
        self,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
    ):
        self._ipv4_addresses = ipv4_addresses
        self._ipv6_addresses = ipv6_addresses
        self._domain_names = domain_names

    @staticmethod
    def _generate_key_pair() -> PrivateKeySerializer:
        return PrivateKeySerializer(ec.generate_private_key(curve=ec.SECP256R1()))

    def _generate_root_ca(self) -> CredentialSerializer:
        private_key_serializer = self._generate_key_pair()
        private_key = private_key_serializer.as_crypto()
        public_key = private_key_serializer.public_key_serializer.as_crypto()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint TLS Root CA'),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint TLS Root CA'),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.today() + (4 * 365 * ONE_DAY))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
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
        root_ca_certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        return CredentialSerializer(
            private_key=private_key,
            certificate=root_ca_certificate,
            additional_certificates=[]
        )

    def _generate_issuing_ca_credential(self, root_ca_credential: CredentialSerializer) -> CredentialSerializer:
        private_key_serializer = self._generate_key_pair()
        private_key = private_key_serializer.as_crypto()
        public_key = private_key_serializer.public_key_serializer.as_crypto()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint TLS Issuing CA'),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint TLS Root CA'),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.today() + (2 * 365 * ONE_DAY))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
        issuing_ca_certificate = builder.sign(
            private_key=root_ca_credential.private_key,
            algorithm=hashes.SHA256(),
        )

        return CredentialSerializer(
            private_key=private_key,
            certificate=issuing_ca_certificate,
            additional_certificates=root_ca_credential.additional_certificates
        )

    def _generate_tls_server_credential(self, issuing_ca_credential: CredentialSerializer) -> CredentialSerializer:
        one_day = datetime.timedelta(1, 0, 0)
        private_key = ec.generate_private_key(curve=ec.SECP256R1())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint Self-Signed TLS-Server Credential'),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint Self-Signed TLS-Server Credential'),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 365))
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
        san = []
        for ipv4_address in self._ipv4_addresses:
            san.append(x509.IPAddress(ipv4_address))
        for ipv6_address in self._ipv6_addresses:
            san.append(x509.IPAddress(ipv6_address))
        for domain_name in self._domain_names:
            san.append(x509.DNSName(domain_name))
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=True)

        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        return CredentialSerializer(
            private_key=private_key,
            certificate=certificate,
            additional_certificates=issuing_ca_credential.get_full_chain_as_crypto(),
        )

    def generate_tls_credential(self) -> CredentialSerializer:
        root_ca_credential = self._generate_root_ca()
        issuing_ca_credential = self._generate_issuing_ca_credential(root_ca_credential)
        return self._generate_tls_server_credential(issuing_ca_credential)
