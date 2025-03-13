"""Module for generating cryptographic credentials for TLS certificate issuance."""
from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import NameOID
from trustpoint_core.serializer import CredentialSerializer, PrivateKeySerializer

if TYPE_CHECKING:
    import ipaddress

ONE_DAY = datetime.timedelta(days=1)


class Generator:
    """Generates cryptographic credentials for TLS certificate issuance."""
    def __init__(
        self,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
    ) -> None:
        """Initializes the Generator with IP addresses and domain names.

        Args:
            ipv4_addresses (list[ipaddress.IPv4Address]): List of IPv4 addresses.
            ipv6_addresses (list[ipaddress.IPv6Address]): List of IPv6 addresses.
            domain_names (list[str]): List of domain names.
        """
        self._ipv4_addresses = ipv4_addresses
        self._ipv6_addresses = ipv6_addresses
        self._domain_names = domain_names

    @staticmethod
    def _generate_key_pair() -> PrivateKeySerializer:
        """Generates a new elliptic curve (EC) key pair.

        Returns:
            PrivateKeySerializer: The generated private key.
        """
        return PrivateKeySerializer(ec.generate_private_key(curve=ec.SECP256R1()))

    def _generate_root_ca(self) -> CredentialSerializer:
        """Generates a self-signed root Certificate Authority (CA) credential.

        Returns:
            CredentialSerializer: The root CA credential containing the private key and certificate.
        """
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
        builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC) - ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + (4 * 365 * ONE_DAY))
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

        return CredentialSerializer((private_key, root_ca_certificate, None))

    def _generate_issuing_ca_credential(self, root_ca_credential: CredentialSerializer) -> CredentialSerializer:
        """Generates an issuing Certificate Authority (CA) credential.

        Args:
            root_ca_credential (CredentialSerializer): The root CA credential used for signing the issuing CA.

        Returns:
            CredentialSerializer: The issuing CA credential containing the private key and certificate.
        """
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
        builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC) - ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + (2 * 365 * ONE_DAY))
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
            private_key=root_ca_credential.credential_private_key.as_crypto(),
            algorithm=hashes.SHA256(),
        )

        return CredentialSerializer(
            (private_key, issuing_ca_certificate, [root_ca_credential.credential_certificate.as_crypto()])
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
        builder = builder.not_valid_before(datetime.datetime.now(datetime.UTC) - one_day)
        builder = builder.not_valid_after(datetime.datetime.now(datetime.UTC) + (one_day * 365))
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
        san = [x509.IPAddress(ip) for ip in self._ipv4_addresses] + \
              [x509.IPAddress(ip) for ip in self._ipv6_addresses] + \
              [x509.DNSName(domain) for domain in self._domain_names]
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=True)

        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        return CredentialSerializer(
            (
                private_key,
                certificate,
                [
                    issuing_ca_credential.credential_certificate.as_crypto(),
                    issuing_ca_credential.additional_certificates.as_crypto()[0],
                ],
            )
        )

    def generate_tls_credential(self) -> CredentialSerializer:
        """Generates a complete TLS server credential chain.

        This method generates a root CA, an issuing CA, and a TLS server credential.

        Returns:
            CredentialSerializer: The TLS server credential containing the private key, certificate, and chain.
        """
        root_ca_credential = self._generate_root_ca()
        issuing_ca_credential = self._generate_issuing_ca_credential(root_ca_credential)
        return self._generate_tls_server_credential(issuing_ca_credential)
