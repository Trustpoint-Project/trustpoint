"""Django management command for creating a self-signed TLS server credential."""

from __future__ import annotations

import datetime
import ipaddress
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.management.base import BaseCommand

BASE_PATH = Path(__file__).parent.parent.parent.parent.parent / 'tests/data/x509/'
SERVER_CERT_PATH = BASE_PATH / 'https_server.crt'
SERVER_KEY_PATH = BASE_PATH / 'https_server.pem'


class Command(BaseCommand):
    """Django management command for creating a self-signed TLS server credential."""

    help = 'Creates a TLS Server Certificate as required.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Executes the command."""
        one_day = datetime.timedelta(1, 0, 0)
        ipv4_addresses = subprocess.check_output(['hostname', '-I']).decode().strip()  # noqa: S603, S607
        # ipv4_addresses = '10.10.0.5 10.10.4.89'  # noqa: ERA001
        ipv4_addresses_list = ipv4_addresses.split(' ')
        ipv4_addresses_list.append('127.0.0.1')
        basic_constraints_extension = x509.BasicConstraints(ca=False, path_length=None)
        key_usage_extension = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            decipher_only=False,
            encipher_only=False,
        )
        extended_key_usage_extension = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
        subject_alt_name_content = [x509.DNSName('localhost'), x509.DNSName('trustpoint.local')]
        subject_alt_name_content.extend(x509.IPAddress(ipaddress.IPv4Address(ipv4)) for ipv4 in ipv4_addresses_list)
        subject_alternative_names_extension = x509.SubjectAlternativeName(subject_alt_name_content)

        subject = x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Trustpoint TLS Server Certificate'),
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'DE'),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Trustpoint Project'),
            ]
        )
        issuer = subject

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(datetime.datetime.now(tz=datetime.UTC) - one_day)
        builder = builder.not_valid_after(datetime.datetime.now(tz=datetime.UTC) + (one_day * 365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(basic_constraints_extension, critical=True)
        builder = builder.add_extension(key_usage_extension, critical=False)
        builder = builder.add_extension(extended_key_usage_extension, critical=True)
        builder = builder.add_extension(subject_alternative_names_extension, critical=True)

        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

        SERVER_CERT_PATH.write_text(certificate.public_bytes(serialization.Encoding.PEM).decode())
        SERVER_KEY_PATH.write_text(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
        )
