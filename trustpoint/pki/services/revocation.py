# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared certificate revocation, issuer resolution and credential scopes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from django.db import transaction
from django.utils import timezone

from pki.models.ca import CaModel
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.issued_credential import IssuedCredentialModel

if TYPE_CHECKING:
    from collections.abc import Iterable


def resolve_revocation_ca(certificate: CertificateModel, ca: CaModel | None) -> CaModel | None:
    """Use the verified issuer certificate to find its CA, falling back to the caller's CA.

    CertificateModel establishes the issuer relationship by verifying signatures
    when certificates are saved. Unlike subject names, this relationship also
    distinguishes rollover CAs sharing the same subject, before and after the
    domain switches to the replacement CA.
    """
    issuer_pk = certificate.issuer_id_id
    if issuer_pk is None:
        return ca
    if ca is not None:
        ca_certificate = ca.ca_certificate_model
        if ca_certificate is not None and ca_certificate.pk == issuer_pk:
            return ca
    return CaModel.objects.filter(credential__certificate_id=issuer_pk).first() or ca


@transaction.atomic
def revoke_certificate(
    certificate: CertificateModel,
    *,
    reason: str | x509.ReasonFlags,
    ca: CaModel | None,
) -> bool:
    """Revoke one certificate, returning whether a new revocation was recorded.

    Repeated calls preserve the original reason and revocation time. Locking the
    certificate serializes concurrent callers; get_or_create also respects the
    unique certificate constraint. Saving normally retains CRL scheduling signals.
    Expired certificates are permitted here; callers choose their expiry policy.
    """
    reason_code = RevokedCertificateModel.ReasonCode(reason.value if isinstance(reason, x509.ReasonFlags) else reason)
    locked_certificate = CertificateModel.objects.select_for_update().get(pk=certificate.pk)
    revocation, created = RevokedCertificateModel.objects.get_or_create(
        certificate=locked_certificate,
        defaults={
            'revocation_reason': reason_code,
            'ca': resolve_revocation_ca(locked_certificate, ca),
        },
    )
    # Refresh even a previously cached absence on the instance supplied by the caller.
    certificate.revoked_certificate = revocation
    return created


@transaction.atomic
def revoke_certificates(
    certificates: Iterable[CertificateModel],
    *,
    reason: str | x509.ReasonFlags,
    ca: CaModel | None,
    only_unexpired: bool,
) -> int:
    """Revoke the supplied scope atomically and return the number newly revoked."""
    now = timezone.now()
    revoked = 0
    # Concurrent batches acquire certificate locks in the same order.
    for certificate in sorted(certificates, key=lambda certificate: certificate.pk):
        if only_unexpired and certificate.not_valid_after <= now:
            continue
        revoked += revoke_certificate(certificate, reason=reason, ca=ca)
    return revoked


def revoke_primary_certificate(issued_credential_id: int, reason: str) -> tuple[bool, str]:
    """Revoke an issued credential's primary certificate using operator-facing results."""
    try:
        issued_credential = IssuedCredentialModel.objects.select_related(
            'credential__certificate',
            'domain__issuing_ca',
        ).get(pk=issued_credential_id)
    except IssuedCredentialModel.DoesNotExist:
        return False, 'The credential to revoke does not exist.'

    certificate = issued_credential.credential.certificate
    if certificate is None:
        return False, 'The associated certificate to revoke was not found.'
    ca = issued_credential.domain.issuing_ca if issued_credential.domain else None
    if not revoke_certificate(certificate, reason=reason, ca=ca):
        return False, 'The certificate is already revoked.'
    return True, 'Certificate successfully revoked.'
