# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create certificate policy notifications in one pass over the certificate table."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils import timezone
from trustpoint_core.oid import PublicKeyAlgorithmOid

from management.models import NotificationModel, NotificationStatus, SecurityConfig
from pki.models import CertificateModel
from pki.security_policy import (
    CryptographicPolicy,
    PolicyViolationCode,
    evaluate_public_key,
    evaluate_signature,
    stored_public_key_facts,
    stored_signature_facts,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pki.security_policy import PolicyViolation

SIGNATURE_EVENT = 'WEAK_SIGNATURE_ALGORITHM'
KEY_EVENT = 'INSUFFICIENT_KEY_LENGTH'
CURVE_EVENT = 'WEAK_ECC_CURVE'
_POLICY_SIGNATURE_CODES = frozenset(
    {PolicyViolationCode.SIGNATURE_BLOCKED, PolicyViolationCode.SIGNATURE_HASH_BLOCKED}
)


def _signature_violation(policy: CryptographicPolicy, certificate: CertificateModel) -> tuple[PolicyViolation, ...]:
    return tuple(
        failure
        for failure in evaluate_signature(policy, stored_signature_facts(certificate))
        if failure.code in _POLICY_SIGNATURE_CODES
    )


def _key_violation(policy: CryptographicPolicy, certificate: CertificateModel) -> tuple[PolicyViolation, ...]:
    if certificate.spki_algorithm_oid != PublicKeyAlgorithmOid.RSA.dotted_string:
        return ()
    return evaluate_public_key(policy, stored_public_key_facts(certificate))


def _curve_violation(policy: CryptographicPolicy, certificate: CertificateModel) -> tuple[PolicyViolation, ...]:
    if certificate.spki_algorithm_oid != PublicKeyAlgorithmOid.ECC.dotted_string:
        return ()
    return tuple(
        failure
        for failure in evaluate_public_key(policy, stored_public_key_facts(certificate))
        if failure.code == PolicyViolationCode.ECC_CURVE_BLOCKED
    )


def _create_certificate_notification(
    certificate: CertificateModel,
    *,
    event: str,
    message_type: NotificationModel.NotificationMessageType,
    message_data: dict[str, object],
    new_status: NotificationStatus,
) -> None:
    notification = NotificationModel.objects.create(
        certificate=certificate,
        created_at=timezone.now(),
        event=event,
        notification_source=NotificationModel.NotificationSource.CERTIFICATE,
        notification_type=NotificationModel.NotificationTypes.WARNING,
        message_type=message_type,
        message_data=message_data,
    )
    notification.statuses.add(new_status)


def _notification_payload(
    certificate: CertificateModel, event: str
) -> tuple[NotificationModel.NotificationMessageType, dict[str, object]]:
    """Build the message type and non-secret summary for one event."""
    if event == SIGNATURE_EVENT:
        try:
            algorithm_name: object = certificate.signature_algorithm
        except ValueError:
            algorithm_name = certificate.signature_algorithm_oid
        return (
            NotificationModel.NotificationMessageType.WEAK_SIGNATURE_ALGORITHM,
            {'common_name': certificate.common_name, 'signature_algorithm': algorithm_name},
        )
    if event == KEY_EVENT:
        return (
            NotificationModel.NotificationMessageType.INSUFFICIENT_KEY_LENGTH,
            {'common_name': certificate.common_name, 'spki_key_size': certificate.spki_key_size},
        )
    return (
        NotificationModel.NotificationMessageType.WEAK_ECC_CURVE,
        {'common_name': certificate.common_name, 'spki_ec_curve': certificate.spki_ec_curve},
    )


def check_certificate_policy_notifications(
    *,
    signature: bool = True,
    key: bool = True,
    curve: bool = True,
) -> None:
    """Evaluate the selected policy checks while streaming the certificate table once."""
    config = SecurityConfig.objects.first()
    if config is None:
        return

    policy = CryptographicPolicy.from_config(config)
    checks: list[
        tuple[str, Callable[[CryptographicPolicy, CertificateModel], tuple[PolicyViolation, ...]]]
    ] = []
    if signature and policy.blocked_signature_oids:
        checks.append((SIGNATURE_EVENT, _signature_violation))
    if key and policy.rsa_minimum_key_size != 0:
        checks.append((KEY_EVENT, _key_violation))
    if curve and policy.blocked_curve_oids:
        checks.append((CURVE_EVENT, _curve_violation))
    if not checks:
        return

    events = {event for event, _check in checks}
    notified = set(
        NotificationModel.objects.filter(
            event__in=events,
            certificate__isnull=False,
        ).values_list('event', 'certificate_id')
    )
    new_status, _ = NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.NEW)

    certificates = CertificateModel.objects.only(
        'pk',
        'common_name',
        'signature_algorithm_oid',
        'cert_pem',
        'spki_algorithm_oid',
        'spki_key_size',
        'spki_ec_curve_oid',
        'spki_ec_curve',
    )
    for certificate in certificates.iterator():
        for event, check in checks:
            if (event, certificate.pk) in notified:
                continue
            if not check(policy, certificate):
                continue

            message_type, message_data = _notification_payload(certificate, event)
            _create_certificate_notification(
                certificate,
                event=event,
                message_type=message_type,
                message_data=message_data,
                new_status=new_status,
            )
            notified.add((event, certificate.pk))
