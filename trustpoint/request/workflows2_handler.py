"""Route request-context events into the Workflow 2 dispatch layer."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import CertificateSigningRequest

from request.request_context import BaseCertificateRequestContext, BaseRequestContext, HttpBaseRequestContext
from trustpoint.logger import LoggerMixin
from workflows2.events.payloads import build_device_snapshot, serialize_source
from workflows2.events.triggers import Triggers
from workflows2.models import Workflow2Run
from workflows2.services.dispatch import DispatchOutcome, EventSource, WorkflowDispatchService

Workflow2HandleMode = Literal['continue', 'stop']
Workflow2DispatchBuilder = Callable[[Any], 'Workflow2DispatchRequest | None']


@dataclass(frozen=True)
class Workflow2HandleResult:
    """Describe how request processing should continue after Workflow 2 dispatch."""

    mode: Workflow2HandleMode
    outcome: DispatchOutcome | None = None

    @classmethod
    def continue_processing(cls, outcome: DispatchOutcome | None = None) -> Workflow2HandleResult:
        """Return a result indicating request processing should continue."""
        return cls(mode='continue', outcome=outcome)

    @classmethod
    def stop_processing(cls, outcome: DispatchOutcome | None = None) -> Workflow2HandleResult:
        """Return a result indicating Workflow 2 handled the response fully."""
        return cls(mode='stop', outcome=outcome)

    @property
    def should_stop(self) -> bool:
        """Return whether the request pipeline should stop immediately."""
        return self.mode == 'stop'


@dataclass(frozen=True)
class Workflow2DispatchRequest:
    """Normalized request payload ready for Workflow 2 dispatch."""

    on: str
    event: dict[str, Any]
    source: EventSource
    idempotency_key: str | None = None
    initial_vars: dict[str, Any] | None = None


def _normalize_event_key(protocol: str | None, operation: str | None) -> tuple[str, str]:
    return (str(protocol or '').strip().lower(), str(operation or '').strip().lower())


def _request_body_bytes(context: BaseRequestContext) -> bytes | None:
    if not isinstance(context, HttpBaseRequestContext) or context.raw_message is None:
        return None

    raw_body = getattr(context.raw_message, 'body', b'') or b''
    if isinstance(raw_body, bytes):
        return raw_body
    if isinstance(raw_body, bytearray):
        return bytes(raw_body)
    if isinstance(raw_body, str):
        return raw_body.encode('utf-8')
    return None


def _build_certificate_request_dispatch(
    context: BaseCertificateRequestContext,
    *,
    on: str,
    event_key: str,
    operation: str,
) -> Workflow2DispatchRequest | None:
    if (
        not context.device
        or not context.domain
        or not isinstance(context.cert_requested, CertificateSigningRequest)
    ):
        return None

    issuing_ca = context.domain.get_issuing_ca_or_value_error()
    source = EventSource(
        trustpoint=False,
        ca_id=issuing_ca.id,
        domain_id=context.domain.id,
        device_id=str(context.device.id),
    )

    fingerprint = hashlib.sha256(context.cert_requested.tbs_certrequest_bytes).hexdigest()
    event = {
        'device': {
            **build_device_snapshot(context.device),
            'domain_id': context.domain.id,
        },
        event_key: {
            'operation': operation,
            'fingerprint': fingerprint,
            'cert_profile': context.cert_profile_str or '',
            'csr_pem': context.cert_requested.public_bytes(Encoding.PEM).decode('utf-8'),
        },
        'source': serialize_source(source),
    }

    return Workflow2DispatchRequest(
        on=on,
        event=event,
        source=source,
        idempotency_key=fingerprint,
        initial_vars={},
    )


def _build_est_simpleenroll_dispatch(
    context: BaseCertificateRequestContext,
) -> Workflow2DispatchRequest | None:
    return _build_certificate_request_dispatch(
        context,
        on=Triggers.EST_SIMPLEENROLL,
        event_key='est',
        operation='simpleenroll',
    )


def _build_est_simplereenroll_dispatch(
    context: BaseCertificateRequestContext,
) -> Workflow2DispatchRequest | None:
    return _build_certificate_request_dispatch(
        context,
        on=Triggers.EST_SIMPLEREENROLL,
        event_key='est',
        operation='simplereenroll',
    )


def _build_rest_enroll_dispatch(
    context: BaseCertificateRequestContext,
) -> Workflow2DispatchRequest | None:
    return _build_certificate_request_dispatch(
        context,
        on=Triggers.REST_ENROLL,
        event_key='rest',
        operation='enroll',
    )


def _build_rest_reenroll_dispatch(
    context: BaseCertificateRequestContext,
) -> Workflow2DispatchRequest | None:
    return _build_certificate_request_dispatch(
        context,
        on=Triggers.REST_REENROLL,
        event_key='rest',
        operation='reenroll',
    )


def _build_cmp_request_dispatch(
    context: BaseCertificateRequestContext,
    *,
    on: str,
    operation: str,
) -> Workflow2DispatchRequest | None:
    if not context.device or not context.domain:
        return None

    request_body = _request_body_bytes(context)
    if not request_body:
        return None

    issuing_ca = context.domain.get_issuing_ca_or_value_error()
    source = EventSource(
        trustpoint=False,
        ca_id=issuing_ca.id,
        domain_id=context.domain.id,
        device_id=str(context.device.id),
    )

    fingerprint = hashlib.sha256(request_body).hexdigest()
    event = {
        'device': {
            **build_device_snapshot(context.device),
            'domain_id': context.domain.id,
        },
        'cmp': {
            'operation': operation,
            'fingerprint': fingerprint,
            'cert_profile': context.cert_profile_str or '',
        },
        'source': serialize_source(source),
    }

    return Workflow2DispatchRequest(
        on=on,
        event=event,
        source=source,
        idempotency_key=fingerprint,
        initial_vars={},
    )


def _build_cmp_initialization_dispatch(
    context: BaseCertificateRequestContext,
) -> Workflow2DispatchRequest | None:
    return _build_cmp_request_dispatch(
        context,
        on=Triggers.CMP_INITIALIZATION,
        operation='initialization',
    )


def _build_cmp_certification_dispatch(
    context: BaseCertificateRequestContext,
) -> Workflow2DispatchRequest | None:
    return _build_cmp_request_dispatch(
        context,
        on=Triggers.CMP_CERTIFICATION,
        operation='certification',
    )


def _resolve_device_domain(context: BaseRequestContext) -> Any | None:
    if context.domain is not None:
        return context.domain
    return getattr(context.device, 'domain', None) if context.device is not None else None


def _resolve_device_ca_id(domain: Any | None) -> int | None:
    if domain is None:
        return None

    with suppress(AttributeError, TypeError, ValueError):
        issuing_ca = domain.get_issuing_ca_or_value_error()
        return int(issuing_ca.id)

    return None


def _build_device_source(context: BaseRequestContext) -> EventSource:
    domain = _resolve_device_domain(context)
    domain_id = getattr(context.device, 'domain_id', None) if context.device is not None else None
    if domain_id is None and domain is not None:
        domain_id = getattr(domain, 'id', None)

    return EventSource(
        trustpoint=True,
        ca_id=_resolve_device_ca_id(domain),
        domain_id=domain_id,
        device_id=str(context.device.id) if context.device is not None else None,
    )


def _build_device_event_payload(context: BaseRequestContext, *, source: EventSource) -> dict[str, Any]:
    if context.device is None:
        msg = '_build_device_event_payload requires a device.'
        raise ValueError(msg)

    if isinstance(context.event_payload, dict):
        event = dict(context.event_payload)
        event['source'] = serialize_source(source)
        return event

    return {
        'device': {**build_device_snapshot(context.device), 'domain_id': source.domain_id},
        'source': serialize_source(source),
    }


def _build_device_created_dispatch(context: BaseRequestContext) -> Workflow2DispatchRequest | None:
    if not context.device:
        return None

    source = _build_device_source(context)
    event = _build_device_event_payload(context, source=source)

    return Workflow2DispatchRequest(
        on=Triggers.DEVICE_CREATED,
        event=event,
        source=source,
        initial_vars={},
    )


def _build_device_updated_dispatch(context: BaseRequestContext) -> Workflow2DispatchRequest | None:
    if not context.device:
        return None

    if not isinstance(context.event_payload, dict):
        return None

    source = _build_device_source(context)
    event = _build_device_event_payload(context, source=source)

    return Workflow2DispatchRequest(
        on=Triggers.DEVICE_UPDATED,
        event=event,
        source=source,
        initial_vars={},
    )


def _build_device_deleted_dispatch(context: BaseRequestContext) -> Workflow2DispatchRequest | None:
    if not context.device:
        return None

    source = _build_device_source(context)
    event = _build_device_event_payload(context, source=source)

    return Workflow2DispatchRequest(
        on=Triggers.DEVICE_DELETED,
        event=event,
        source=source,
        initial_vars={},
    )


class Workflow2Handler(LoggerMixin):
    """Dispatch a request context to the matching Workflow 2 sub-handler."""

    def handle(self, context: BaseRequestContext) -> Workflow2HandleResult:
        """Route the given request context by its registered handler key."""
        context.workflow2_outcome = None

        if not context.event:
            self.logger.debug('Skipping workflows2 handling because no event is set on the request context.')
            return Workflow2HandleResult.continue_processing()

        handler_key = context.event.handler
        if handler_key == 'certificate_request':
            return Workflow2CertificateRequestHandler().handle(context)
        if handler_key == 'device_action':
            return Workflow2DeviceActionHandler().handle(context)

        self.logger.debug('No workflows2 handler registered for event handler "%s".', handler_key)
        return Workflow2HandleResult.continue_processing()


class Workflow2CertificateRequestHandler(LoggerMixin):
    """Handle certificate-request events for Workflow 2."""

    _DISPATCH_BUILDERS: ClassVar[dict[tuple[str, str], Workflow2DispatchBuilder]] = {
        ('cmp', 'initialization'): _build_cmp_initialization_dispatch,
        ('cmp', 'certification'): _build_cmp_certification_dispatch,
        ('est', 'simpleenroll'): _build_est_simpleenroll_dispatch,
        ('est', 'simplereenroll'): _build_est_simplereenroll_dispatch,
        ('rest', 'enroll'): _build_rest_enroll_dispatch,
        ('rest', 'reenroll'): _build_rest_reenroll_dispatch,
    }

    def handle(self, context: BaseRequestContext) -> Workflow2HandleResult:
        """Dispatch one certificate-request event into Workflow 2."""
        if not isinstance(context, BaseCertificateRequestContext):
            msg = 'Workflow2CertificateRequestHandler requires a BaseCertificateRequestContext.'
            raise TypeError(msg)

        dispatch_request = self._build_dispatch_request(context)
        if dispatch_request is None:
            return Workflow2HandleResult.continue_processing()

        outcome = WorkflowDispatchService().emit_event_outcome(
            on=dispatch_request.on,
            event=dispatch_request.event,
            source=dispatch_request.source,
            initial_vars=dispatch_request.initial_vars,
            idempotency_key=dispatch_request.idempotency_key,
        )
        context.workflow2_outcome = outcome
        if outcome is None:
            return Workflow2HandleResult.continue_processing()
        return self._result_for_outcome(outcome)

    def _build_dispatch_request(
        self,
        context: BaseCertificateRequestContext,
    ) -> Workflow2DispatchRequest | None:
        builder = self._DISPATCH_BUILDERS.get(_normalize_event_key(context.protocol, context.operation))
        if builder is None:
            return None
        return builder(context)

    @staticmethod
    def _result_for_outcome(
        outcome: DispatchOutcome,
    ) -> Workflow2HandleResult:
        if outcome.status in {'blocked', 'running'}:
            return Workflow2HandleResult.stop_processing(outcome)

        if outcome.run.status == Workflow2Run.STATUS_REJECTED:
            return Workflow2HandleResult.stop_processing(outcome)

        if outcome.run.status in {
            Workflow2Run.STATUS_FAILED,
            Workflow2Run.STATUS_CANCELLED,
            Workflow2Run.STATUS_STOPPED,
        }:
            return Workflow2HandleResult.stop_processing(outcome)

        return Workflow2HandleResult.continue_processing(outcome)


class Workflow2DeviceActionHandler(LoggerMixin):
    """Handle device lifecycle events for Workflow 2."""

    _DISPATCH_BUILDERS: ClassVar[dict[tuple[str, str], Workflow2DispatchBuilder]] = {
        ('device', 'created'): _build_device_created_dispatch,
        ('device', 'updated'): _build_device_updated_dispatch,
        ('device', 'deleted'): _build_device_deleted_dispatch,
    }

    def handle(self, context: BaseRequestContext) -> Workflow2HandleResult:
        """Dispatch one device-action event into Workflow 2."""
        builder = self._DISPATCH_BUILDERS.get(_normalize_event_key(context.protocol, context.operation))
        if builder is None:
            return Workflow2HandleResult.continue_processing()

        dispatch_request = builder(context)
        if dispatch_request is None:
            return Workflow2HandleResult.continue_processing()

        outcome = WorkflowDispatchService().emit_event_outcome(
            on=dispatch_request.on,
            event=dispatch_request.event,
            source=dispatch_request.source,
            initial_vars=dispatch_request.initial_vars,
            idempotency_key=dispatch_request.idempotency_key,
        )
        context.workflow2_outcome = outcome

        if outcome is None:
            return Workflow2HandleResult.continue_processing()

        return Workflow2HandleResult.continue_processing(outcome)
