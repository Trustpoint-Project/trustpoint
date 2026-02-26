"""Utilities for Certificate Revocation List (CRL) generation and management."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, get_args

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from django.utils import timezone
from trustpoint_core.crypto_types import AllowedCertSignHashAlgos

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509 import CertificateRevocationList

    from pki.models.ca import CaModel


def generate_empty_crl(
    ca_cert: x509.Certificate,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    hash_algorithm: hashes.HashAlgorithm | None = None,
    crl_validity_hours: int = 2400,
    crl_number: int = 1,
) -> str:
    """Generate an empty CRL for a CA.

    Args:
        ca_cert: The CA certificate.
        private_key: The private key of the CA.
        hash_algorithm: The hash algorithm to use. Defaults to SHA256.
        crl_validity_hours: Validity period in hours.
        crl_number: The CRL number to use.

    Returns:
        str: The CRL in PEM format.
    """
    if hash_algorithm is None:
        hash_algorithm = hashes.SHA256()

    crl_issued_at = datetime.datetime.now(datetime.UTC)
    ca_subject = ca_cert.subject

    crl_builder = x509.CertificateRevocationListBuilder(
        issuer_name=ca_subject,
        last_update=crl_issued_at,
        next_update=crl_issued_at + datetime.timedelta(hours=crl_validity_hours),
    )
    crl_builder = crl_builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    crl = crl_builder.sign(private_key=private_key, algorithm=hash_algorithm)  # type: ignore[arg-type]
    return crl.public_bytes(encoding=serialization.Encoding.PEM).decode()


def generate_crl_with_revoked_certs(
    issuing_ca: CaModel,
    crl_validity_hours: int = 24,
) -> CertificateRevocationList:
    """Generate a CRL with revoked certificates for an issuing CA.

    Args:
        issuing_ca: The issuing CA model instance.
        crl_validity_hours: Hours until the next CRL update (nextUpdate field).

    Returns:
        CertificateRevocationList: The generated CRL.

    Raises:
        AttributeError: If called on a keyless CA.
        ValueError: If credential is None for issuing CA.
        TypeError: If hash algorithm is not allowed.
    """
    if issuing_ca.is_keyless_ca:
        msg = 'Keyless CAs cannot issue CRLs (no private key available).'
        raise AttributeError(msg)
    if issuing_ca.credential is None:
        msg = 'Credential is None for issuing CA'
        raise ValueError(msg)

    crl_issued_at = timezone.now()
    ca_subject = issuing_ca.credential.certificate_or_error.get_certificate_serializer().as_crypto().subject

    latest_crl = issuing_ca.get_latest_crl()
    next_crl_number = (latest_crl.crl_number + 1) if latest_crl and latest_crl.crl_number else 1

    crl_builder = x509.CertificateRevocationListBuilder(
        issuer_name=ca_subject,
        last_update=crl_issued_at,
        next_update=crl_issued_at + datetime.timedelta(hours=crl_validity_hours),
    )
    crl_builder = crl_builder.add_extension(x509.CRLNumber(next_crl_number), critical=False)

    crl_certificates = issuing_ca.revoked_certificates.all()

    for cert in crl_certificates:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(cert.certificate.serial_number, 16))
            .revocation_date(cert.revoked_at)
            .add_extension(x509.CRLReason(x509.ReasonFlags(cert.revocation_reason)), critical=False)
            .build()
        )
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    hash_algorithm = issuing_ca.credential.hash_algorithm

    if hash_algorithm is not None and not isinstance(hash_algorithm, get_args(AllowedCertSignHashAlgos)):
        err_msg = f'CRL: Hash algo must be one of {AllowedCertSignHashAlgos}, but found {type(hash_algorithm)}'
        raise TypeError(err_msg)

    priv_k = issuing_ca.credential.get_private_key_serializer().as_crypto()

    return crl_builder.sign(private_key=priv_k, algorithm=hash_algorithm)
