"""Module that contains the logic for generating the TLS server credential."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, get_args

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import NameOID
from trustpoint_core.key_types import PrivateKey
from trustpoint_core.serializer import CredentialSerializer, PrivateKeySerializer

if TYPE_CHECKING:
    import ipaddress

ONE_DAY = datetime.timedelta(days=1)


class TlsServerCredentialGenerator:
    """Wraps methods for generating a TLS server credential."""

    def __init__(
        self,
        ipv4_addresses: list[ipaddress.IPv4Address],
        ipv6_addresses: list[ipaddress.IPv6Address],
        domain_names: list[str],
    ) -> None:
        """Initializes the TlsServerCredentialGenerator with the provided SAN information.

        Args:
            ipv4_addresses: IPv4 addresses to be included in the SAN.
            ipv6_addresses: IPv6 addresses to be included in the SAN.
            domain_names: Domain names to be included in the SAN.
        """
        self._ipv4_addresses = ipv4_addresses
        self._ipv6_addresses = ipv6_addresses
        self._domain_names = domain_names

    @staticmethod
    def _generate_key_pair() -> PrivateKeySerializer:
        return PrivateKeySerializer(ec.generate_private_key(curve=ec.SECP256R1()))

    def generate_tls_credential(self) -> CredentialSerializer:
        """Generates a self-signed TLS credential for use by the Trustpoint Apache server."""
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
            private_key=private_key,
            certificate=certificate,
            additional_certificates=[certificate]
        )
