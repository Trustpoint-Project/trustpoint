# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Generate a user TLS client credential in memory without saving or exporting it."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from pki.models import CaModel
from users.models import TrustpointUser

from .create_management_ca import ISSUING_CA_NAME

if TYPE_CHECKING:
    from django.core.management.base import CommandParser


def create_user_client_certificate(
    user_id: int, subject_identifier: str, *, validity_days: int = 365,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Return a new client certificate and private key for an existing human user.

    The subject contains CN=trustpoint-client-certificate, UID=<username>,
    serialNumber=<user ID>, and unstructuredName=<subject_identifier>. The
    caller-supplied string is preserved unchanged. The certificate has a separate
    random serial number.
    Validity is capped at the management issuing CA's expiry. The client key is
    generated only in memory; persistence and delivery are left to the caller.
    """
    if validity_days <= 0:
        raise CommandError('The validity period must be a positive number of days.')

    try:
        user = TrustpointUser.objects.get(
            pk=user_id, account_type=TrustpointUser.AccountType.HUMAN, is_active=True,
        )
    except TrustpointUser.DoesNotExist as exc:
        raise CommandError(f'No active human user exists with ID {user_id}.') from exc

    issuing_ca = CaModel.objects.select_related('credential__certificate').filter(unique_name=ISSUING_CA_NAME).first()
    if issuing_ca is None or issuing_ca.credential is None:
        raise CommandError('The Management Issuing CA is missing. Run create_management_ca first.')
    issuer_certificate = issuing_ca.get_certificate()
    if issuer_certificate is None:
        raise CommandError('The Management Issuing CA has no certificate.')

    try:
        basic_constraints = issuer_certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        key_usage = issuer_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CommandError('The Management Issuing CA is missing required CA extensions.') from exc
    if not basic_constraints.ca or not key_usage.key_cert_sign:
        raise CommandError('The Management Issuing CA certificate does not permit certificate signing.')

    now = timezone.now()
    if not issuer_certificate.not_valid_before_utc <= now < issuer_certificate.not_valid_after_utc:
        raise CommandError('The Management Issuing CA certificate is not currently valid.')
    remaining_days = (issuer_certificate.not_valid_after_utc - now).days + 1
    not_valid_after = min(
        now + timedelta(days=min(validity_days, remaining_days)), issuer_certificate.not_valid_after_utc,
    )

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'trustpoint-client-certificate'),
        x509.NameAttribute(NameOID.USER_ID, user.username),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, str(user.pk)),
        x509.NameAttribute(NameOID.UNSTRUCTURED_NAME, subject_identifier),
    ])

    try:
        issuer_key_identifier = issuer_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_key_identifier)
    except x509.ExtensionNotFound:
        authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_certificate.public_key())

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(max(now - timedelta(minutes=5), issuer_certificate.not_valid_before_utc))
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(authority_key_identifier, critical=False)
    )
    certificate = builder.sign(
        private_key=issuing_ca.credential.get_private_key(), algorithm=hashes.SHA256(),
    )
    certificate.verify_directly_issued_by(issuer_certificate)
    return certificate, private_key


class Command(BaseCommand):
    """Generate a TLS client credential without persistence or credential output.

    Other code can call ``create_user_client_certificate()`` directly, or pass a
    command instance to ``call_command()`` and read its certificate/private_key.
    """

    help = 'Generates an in-memory TLS client certificate and key signed by the Management Issuing CA.'
    certificate: x509.Certificate | None = None
    private_key: ec.EllipticCurvePrivateKey | None = None

    def add_arguments(self, parser: CommandParser) -> None:
        """Accept the user ID, subject identifier, and requested certificate lifetime."""
        parser.add_argument('user_id', type=int, help='ID of the user receiving the certificate.')
        parser.add_argument('subject_identifier', help='Arbitrary string included in the subject as unstructuredName.')
        parser.add_argument('--validity-days', type=int, default=365, help='Requested lifetime in days (default: 365).')

    def handle(self, *_args: Any, **options: Any) -> None:
        """Generate the credential and leave it in memory for the calling code."""
        self.certificate, self.private_key = create_user_client_certificate(
            options['user_id'], options['subject_identifier'], validity_days=options['validity_days'],
        )
