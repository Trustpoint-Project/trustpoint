from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import CertificateSigningRequest

from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin
from workflows2.events.triggers import Triggers
from workflows2.models import Workflow2Run
from workflows2.services.dispatch import DispatchOutcome, EventSource, WorkflowDispatchService

Workflow2HandleMode = Literal['no_match', 'continue', 'stop']


@dataclass(frozen=True)
class Workflow2HandleResult:
    mode: Workflow2HandleMode
    outcome: DispatchOutcome | None = None

    @classmethod
    def no_match(cls, outcome: DispatchOutcome | None = None) -> 'Workflow2HandleResult':
        return cls(mode='no_match', outcome=outcome)

    @classmethod
    def continue_processing(cls, outcome: DispatchOutcome | None = None) -> 'Workflow2HandleResult':
        return cls(mode='continue', outcome=outcome)

    @classmethod
    def stop_processing(cls, outcome: DispatchOutcome | None = None) -> 'Workflow2HandleResult':
        return cls(mode='stop', outcome=outcome)

    @property
    def should_stop(self) -> bool:
        return self.mode == 'stop'

    @property
    def should_fallback_to_legacy(self) -> bool:
        return self.mode == 'no_match'


@dataclass(frozen=True)
class Workflow2DispatchRequest:
    on: str
    event: dict[str, Any]
    source: EventSource
    idempotency_key: str | None = None
    initial_vars: dict[str, Any] | None = None


def _normalize_event_key(protocol: str | None, operation: str | None) -> tuple[str, str]:
    return (str(protocol or '').strip().lower(), str(operation or '').strip().lower())


def _serialize_source(source: EventSource) -> dict[str, Any]:
    return {
        'trustpoint': source.trustpoint,
        'ca_id': source.ca_id,
        'domain_id': source.domain_id,
        'device_id': source.device_id,
    }


def _build_est_simpleenroll_dispatch(
    context: BaseCertificateRequestContext,
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
            'id': str(context.device.id),
            'common_name': context.device.common_name or '',
            'serial_number': context.device.serial_number or '',
            'domain_id': context.domain.id,
        },
        'est': {
            'operation': 'simpleenroll',
            'fingerprint': fingerprint,
            'cert_profile': context.cert_profile_str or '',
            'csr_pem': context.cert_requested.public_bytes(Encoding.PEM).decode('utf-8'),
        },
        'source': _serialize_source(source),
    }

    return Workflow2DispatchRequest(
        on=Triggers.EST_SIMPLEENROLL,
        event=event,
        source=source,
        idempotency_key=fingerprint,
        initial_vars={},
    )


def _build_device_created_dispatch(context: BaseRequestContext) -> Workflow2DispatchRequest | None:
    if not context.device:
        return None

    source = EventSource(
        trustpoint=True,
        domain_id=context.device.domain_id,
        device_id=str(context.device.id),
    )
    event = {
        'device': {
            'id': str(context.device.id),
            'common_name': context.device.common_name,
            'serial_number': context.device.serial_number,
            'domain_id': context.device.domain_id,
        },
        'source': _serialize_source(source),
    }

    return Workflow2DispatchRequest(
        on=Triggers.DEVICE_CREATED,
        event=event,
        source=source,
        initial_vars={},
    )


class Workflow2Handler(LoggerMixin):
    def handle(self, context: BaseRequestContext) -> Workflow2HandleResult:
        if not context.event:
            self.logger.debug('Skipping workflows2 handling because no event is set on the request context.')
            return Workflow2HandleResult.no_match()

        handler_key = context.event.handler
        if handler_key == 'certificate_request':
            return Workflow2CertificateRequestHandler().handle(context)
        if handler_key == 'device_action':
            return Workflow2DeviceActionHandler().handle(context)

        self.logger.debug('No workflows2 handler registered for event handler "%s".', handler_key)
        return Workflow2HandleResult.no_match()


class Workflow2CertificateRequestHandler(LoggerMixin):
    _DISPATCH_BUILDERS = {
        ('est', 'simpleenroll'): _build_est_simpleenroll_dispatch,
    }

    def handle(self, context: BaseRequestContext) -> Workflow2HandleResult:
        if not isinstance(context, BaseCertificateRequestContext):
            msg = 'Workflow2CertificateRequestHandler requires a BaseCertificateRequestContext.'
            raise TypeError(msg)

        builder = self._DISPATCH_BUILDERS.get(_normalize_event_key(context.protocol, context.operation))
        if builder is None:
            return Workflow2HandleResult.no_match()

        dispatch_request = builder(context)
        if dispatch_request is None:
            return Workflow2HandleResult.no_match()

        outcome = WorkflowDispatchService().emit_event_outcome(
            on=dispatch_request.on,
            event=dispatch_request.event,
            source=dispatch_request.source,
            initial_vars=dispatch_request.initial_vars,
            idempotency_key=dispatch_request.idempotency_key,
        )

        if outcome.status == 'no_match':
            return Workflow2HandleResult.no_match(outcome)

        if outcome.status in {'blocked', 'running'}:
            context.http_response_status = 202
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request pending workflow approval.'
            return Workflow2HandleResult.stop_processing(outcome)

        if outcome.run.status == Workflow2Run.STATUS_REJECTED:
            context.http_response_status = 403
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request rejected by workflow.'
            return Workflow2HandleResult.stop_processing(outcome)

        if outcome.run.status in {
            Workflow2Run.STATUS_FAILED,
            Workflow2Run.STATUS_CANCELLED,
        }:
            context.http_response_status = 500
            context.http_response_content_type = 'text/plain'
            context.http_response_content = 'Enrollment request failed in workflow processing.'
            return Workflow2HandleResult.stop_processing(outcome)

        context.workflow2_gate_applied = True
        return Workflow2HandleResult.continue_processing(outcome)


class Workflow2DeviceActionHandler(LoggerMixin):
    _DISPATCH_BUILDERS = {
        ('device', 'created'): _build_device_created_dispatch,
    }

    def handle(self, context: BaseRequestContext) -> Workflow2HandleResult:
        builder = self._DISPATCH_BUILDERS.get(_normalize_event_key(context.protocol, context.operation))
        if builder is None:
            return Workflow2HandleResult.no_match()

        dispatch_request = builder(context)
        if dispatch_request is None:
            return Workflow2HandleResult.no_match()

        outcome = WorkflowDispatchService().emit_event_outcome(
            on=dispatch_request.on,
            event=dispatch_request.event,
            source=dispatch_request.source,
            initial_vars=dispatch_request.initial_vars,
            idempotency_key=dispatch_request.idempotency_key,
        )

        if outcome.status == 'no_match':
            return Workflow2HandleResult.no_match(outcome)

        return Workflow2HandleResult.continue_processing(outcome)
