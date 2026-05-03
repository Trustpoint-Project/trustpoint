"""Workflow 2 integration hooks for certificate lifecycle events."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from pki.models import CredentialModel, IssuedCredentialModel, RemoteIssuedCredentialModel, RevokedCertificateModel
from workflows2.events.payloads import build_certificate_snapshot, build_device_snapshot, serialize_source
from workflows2.events.triggers import Triggers
from workflows2.services.dispatch import EventSource, WorkflowDispatchService

if TYPE_CHECKING:
    from pki.models.certificate import CertificateModel
    from pki.models.domain import DomainModel

type CertificateRecord = IssuedCredentialModel | RemoteIssuedCredentialModel


def _issued_credential_type_slug(record: CertificateRecord) -> str:
    """Return a stable slug for the issued credential type."""
    display = record.get_issued_credential_type_display()
    return display.strip().lower().replace(' ', '_')


def _resolve_ca_id(*, domain: DomainModel | None, ca_id: int | None = None) -> int | None:
    """Resolve a CA ID from explicit input or a domain relation."""
    if ca_id is not None:
        return ca_id
    if domain is None:
        return None
    issuing_ca = domain.issuing_ca
    return issuing_ca.id if issuing_ca is not None else None


def _build_event_source_for_record(
    record: CertificateRecord | None,
    *,
    ca_id: int | None = None,
) -> EventSource:
    """Build the Workflow 2 event source for a certificate record."""
    if record is None:
        return EventSource(trustpoint=True, ca_id=ca_id)

    domain = getattr(record, 'domain', None)
    device = getattr(record, 'device', None)
    explicit_ca_id = getattr(record, 'ca_id', None)
    if not isinstance(explicit_ca_id, int):
        explicit_ca_id = None
    return EventSource(
        trustpoint=True,
        ca_id=_resolve_ca_id(domain=domain, ca_id=ca_id if ca_id is not None else explicit_ca_id),
        domain_id=domain.id if domain is not None else None,
        device_id=str(device.id) if device is not None else None,
    )


def _build_certificate_event_payload(
    *,
    certificate: CertificateModel,
    record: CertificateRecord | None,
    source: EventSource,
    revocation_reason: str | None = None,
) -> dict[str, Any]:
    """Build the JSON payload for a certificate lifecycle event."""
    cert_profile = getattr(record, 'issued_using_cert_profile', None) if record is not None else None
    issued_credential_type = _issued_credential_type_slug(record) if record is not None else None

    event: dict[str, Any] = {
        'certificate': build_certificate_snapshot(
            certificate,
            cert_profile=cert_profile,
            issued_credential_type=issued_credential_type,
            revocation_reason=revocation_reason,
        ),
        'source': serialize_source(source),
    }

    device = getattr(record, 'device', None) if record is not None else None
    if device is not None:
        event['device'] = build_device_snapshot(device)

    return event


def emit_certificate_issued_for_record(record: CertificateRecord) -> None:
    """Emit ``certificate.issued`` for an issued credential record."""
    certificate = record.credential.certificate
    if certificate is None:
        return

    source = _build_event_source_for_record(record)
    event = _build_certificate_event_payload(
        certificate=certificate,
        record=record,
        source=source,
    )
    WorkflowDispatchService().emit_event(
        on=Triggers.CERTIFICATE_ISSUED,
        event=event,
        source=source,
        initial_vars={},
    )


def _resolve_record_for_certificate(certificate: CertificateModel) -> CertificateRecord | None:
    """Return the owning issued credential record for the given certificate if one exists."""
    credential = (
        CredentialModel.objects.select_related(
            'issued_credential',
            'issued_credential__device',
            'issued_credential__domain',
            'remote_issued_credential',
            'remote_issued_credential__device',
            'remote_issued_credential__domain',
            'remote_issued_credential__ca',
        )
        .filter(certificate=certificate)
        .first()
    )
    if credential is None:
        return None
    if hasattr(credential, 'issued_credential'):
        return credential.issued_credential
    if hasattr(credential, 'remote_issued_credential'):
        return credential.remote_issued_credential
    return None


@receiver(post_save, sender=IssuedCredentialModel)
def on_issued_credential_created(
    sender: type[IssuedCredentialModel],  # noqa: ARG001
    instance: IssuedCredentialModel,
    *,
    created: bool,
    **_kwargs: Any,
) -> None:
    """Emit ``certificate.issued`` when an issued credential is created."""
    if not created:
        return
    emit_certificate_issued_for_record(instance)


@receiver(post_save, sender=RemoteIssuedCredentialModel)
def on_remote_issued_credential_created(
    sender: type[RemoteIssuedCredentialModel],  # noqa: ARG001
    instance: RemoteIssuedCredentialModel,
    *,
    created: bool,
    **_kwargs: Any,
) -> None:
    """Emit ``certificate.issued`` when a remote issued credential is created."""
    if not created:
        return
    emit_certificate_issued_for_record(instance)


@receiver(post_save, sender=RevokedCertificateModel)
def on_certificate_revoked(
    sender: type[RevokedCertificateModel],  # noqa: ARG001
    instance: RevokedCertificateModel,
    *,
    created: bool,
    **_kwargs: Any,
) -> None:
    """Emit ``certificate.revoked`` when a revoked certificate record is created."""
    if not created:
        return

    record = _resolve_record_for_certificate(instance.certificate)
    source = _build_event_source_for_record(record, ca_id=instance.ca_id)
    event = _build_certificate_event_payload(
        certificate=instance.certificate,
        record=record,
        source=source,
        revocation_reason=instance.revocation_reason,
    )
    WorkflowDispatchService().emit_event(
        on=Triggers.CERTIFICATE_REVOKED,
        event=event,
        source=source,
        initial_vars={},
    )
