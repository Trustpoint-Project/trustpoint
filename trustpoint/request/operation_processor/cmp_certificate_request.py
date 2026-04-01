"""CMP certificate-request processing with CMP-owned transaction persistence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from django.db import IntegrityError, transaction

from cmp.models import CmpTransactionModel
from request.authorization import CmpAuthorization
from request.cmp_transaction_state import CmpTransactionState
from request.message_parser import CmpMessageParser
from request.request_context import (
    BaseRequestContext,
    CmpCertificateRequestContext,
    HttpBaseRequestContext,
)
from request.workflow2_issuance import Workflow2IssuanceDecision, get_workflow2_issuance_decision
from trustpoint.logger import LoggerMixin
from workflows2.models import Workflow2Run

from .base import AbstractOperationProcessor
from .issue_cert import CertificateIssueProcessor


@dataclass(frozen=True)
class _StoredCmpHttpRequest:
    """Minimal request-like object for replaying a stored CMP DER body."""

    body: bytes
    META: dict[str, str] = field(default_factory=dict)


class CmpCertificateRequestProcessor(AbstractOperationProcessor, LoggerMixin):
    """Process CMP certificate-request messages through CMP transaction state."""

    DEFAULT_CHECK_AFTER_SECONDS = 60

    def process_operation(self, context: BaseRequestContext) -> None:  # noqa: C901
        """Process one CMP certificate request."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpCertificateRequestProcessor requires a CmpCertificateRequestContext.'
            raise TypeError(exc_msg)
        if context.protocol != 'cmp':
            CertificateIssueProcessor().process_operation(context)
            return
        if context.cmp_body_type not in {'ir', 'cr'}:
            CertificateIssueProcessor().process_operation(context)
            return

        transaction_id = self._require_transaction_id(context)
        request_der = self._require_request_der(context)

        transaction_record = self._get_existing_transaction(transaction_id)
        if transaction_record is not None:
            self._validate_existing_request(transaction_record, context, request_der)
            self._apply_existing_transaction(context, transaction_record)
            return

        transaction_record = self._create_processing_transaction(context, transaction_id, request_der)
        context.cmp_transaction = transaction_record

        workflow_decision = get_workflow2_issuance_decision(context)
        if workflow_decision == Workflow2IssuanceDecision.WAIT:
            workflow_outcome = context.workflow2_outcome
            if workflow_outcome is None:
                exc_msg = 'CMP waiting decision requires a Workflow 2 outcome.'
                raise ValueError(exc_msg)
            run_status = str(workflow_outcome.run.status)
            context.cmp_transaction = self._mark_transaction_waiting(
                transaction_record.pk,
                backend=CmpTransactionModel.Backend.WORKFLOW2,
                backend_reference=str(workflow_outcome.run.id),
                detail=self.detail_for_pending_run(run_status),
            )
            return
        if workflow_decision in {
            Workflow2IssuanceDecision.REJECT,
            Workflow2IssuanceDecision.FAIL,
        }:
            workflow_outcome = context.workflow2_outcome
            if workflow_outcome is None:
                exc_msg = 'CMP terminal workflow decision requires a Workflow 2 outcome.'
                raise ValueError(exc_msg)
            context.cmp_transaction = self._mark_transaction_terminal(
                transaction_record.pk,
                request_decision=workflow_decision,
                run_status=str(workflow_outcome.run.status),
            )
            return

        try:
            CertificateIssueProcessor().process_operation(context)
        except Exception:
            context.cmp_transaction = self._mark_transaction_failed(
                transaction_record.pk,
                detail='CMP enrollment failed while issuing the certificate.',
            )
            raise

        if context.issued_certificate is None:
            context.cmp_transaction = self._mark_transaction_failed(
                transaction_record.pk,
                detail='CMP enrollment completed without issuing a certificate.',
            )
            return

        context.cmp_transaction = self.mark_transaction_issued(transaction_record.pk, context)

    @classmethod
    def populate_success_context(
        cls,
        context: CmpCertificateRequestContext | Any,
        transaction_record: CmpTransactionModel,
    ) -> None:
        """Populate a context with the issued certificate material from a CMP transaction."""
        if transaction_record.final_certificate is None:
            exc_msg = 'CMP issued transaction is missing its final certificate.'
            raise ValueError(exc_msg)
        if transaction_record.issuer_credential is None:
            exc_msg = 'CMP issued transaction is missing its issuer credential.'
            raise ValueError(exc_msg)

        context.operation = transaction_record.operation
        context.implicit_confirm = transaction_record.implicit_confirm
        context.cert_profile_str = transaction_record.cert_profile or None
        context.issuer_credential = transaction_record.issuer_credential
        context.issued_certificate = transaction_record.final_certificate.get_certificate_serializer().as_crypto()
        context.issued_certificate_chain = [
            transaction_record.issuer_credential.get_certificate(),
            *transaction_record.issuer_credential.get_certificate_chain(),
        ]
        context.cmp_transaction = transaction_record

    @classmethod
    def build_replay_context(
        cls,
        transaction_record: CmpTransactionModel,
        poll_context: Any,
    ) -> CmpCertificateRequestContext:
        """Rebuild the original CMP certificate-request context for final issuance."""
        replay_context = CmpCertificateRequestContext(
            raw_message=cast(
                'Any',
                _StoredCmpHttpRequest(
                    body=bytes(transaction_record.request_der),
                    META=dict(getattr(poll_context.raw_message, 'META', {}) or {}),
                ),
            ),
            domain_str=transaction_record.domain_name or poll_context.domain_str,
            protocol='cmp',
            operation=transaction_record.operation,
            cert_profile_str=transaction_record.cert_profile or None,
        )
        replay_context = cast('CmpCertificateRequestContext', CmpMessageParser().parse(replay_context))

        replay_context.device = transaction_record.device or poll_context.device
        replay_context.domain = transaction_record.domain or poll_context.domain
        replay_context.client_certificate = poll_context.client_certificate
        replay_context.client_intermediate_certificate = poll_context.client_intermediate_certificate
        replay_context.owner_credential = poll_context.owner_credential
        replay_context.actor = poll_context.actor
        replay_context.cmp_shared_secret = poll_context.cmp_shared_secret
        replay_context.implicit_confirm = transaction_record.implicit_confirm

        CmpAuthorization([transaction_record.operation]).authorize(replay_context)
        return replay_context

    @staticmethod
    def _request_body_bytes(context: CmpCertificateRequestContext) -> bytes:
        """Return the raw CMP request body bytes from the HTTP wrapper object."""
        if not isinstance(context, HttpBaseRequestContext) or context.raw_message is None:
            exc_msg = 'CMP certificate-request context is missing its raw HTTP message.'
            raise ValueError(exc_msg)

        raw_body = getattr(context.raw_message, 'body', b'') or b''
        if isinstance(raw_body, bytes):
            return raw_body
        if isinstance(raw_body, bytearray):
            return bytes(raw_body)
        if isinstance(raw_body, str):
            return raw_body.encode('utf-8')

        exc_msg = 'CMP certificate-request body must be bytes-like.'
        raise TypeError(exc_msg)

    @classmethod
    def _require_request_der(cls, context: CmpCertificateRequestContext) -> bytes:
        """Return the original DER request body and fail if it is missing or empty."""
        request_der = cls._request_body_bytes(context)
        if not request_der:
            exc_msg = 'CMP certificate-request body is empty.'
            raise ValueError(exc_msg)
        return request_der

    @staticmethod
    def _require_transaction_id(context: CmpCertificateRequestContext) -> str:
        """Return the normalized CMP transaction ID required for persistence/polling."""
        transaction_id = str(context.cmp_transaction_id or '').strip().lower()
        if not transaction_id:
            exc_msg = 'CMP certificate request is missing transactionID.'
            raise ValueError(exc_msg)
        return transaction_id

    @staticmethod
    def detail_for_pending_run(run_status: str) -> str:
        """Return a user-facing CMP waiting detail for one workflows2 pending run state."""
        if run_status == Workflow2Run.STATUS_AWAITING:
            return 'Enrollment request pending workflow approval.'
        return 'Enrollment request pending workflow processing.'

    @staticmethod
    def _request_matches_transaction(
        transaction_record: CmpTransactionModel,
        context: CmpCertificateRequestContext,
        request_der: bytes,
    ) -> bool:
        return (
            bytes(transaction_record.request_der) == request_der
            and transaction_record.operation == str(context.operation or '')
            and transaction_record.request_body_type == str(context.cmp_body_type or '')
        )

    def _get_existing_transaction(self, transaction_id: str) -> CmpTransactionModel | None:
        """Look up an existing persisted CMP transaction by transaction ID."""
        return CmpTransactionState.get_by_transaction_id(transaction_id)

    def _validate_existing_request(
        self,
        transaction_record: CmpTransactionModel,
        context: CmpCertificateRequestContext,
        request_der: bytes,
    ) -> None:
        """Ensure a repeated CMP request matches the stored transaction exactly."""
        if not self._request_matches_transaction(transaction_record, context, request_der):
            exc_msg = 'CMP transactionID is already in use for a different certificate request.'
            raise ValueError(exc_msg)

    def _apply_existing_transaction(
        self,
        context: CmpCertificateRequestContext,
        transaction_record: CmpTransactionModel,
    ) -> None:
        """Hydrate the current context from an already persisted CMP transaction."""
        context.cmp_transaction = transaction_record
        context.operation = transaction_record.operation
        context.cert_profile_str = transaction_record.cert_profile or context.cert_profile_str
        context.implicit_confirm = transaction_record.implicit_confirm
        context.device = context.device or transaction_record.device
        context.domain = context.domain or transaction_record.domain

        if transaction_record.status == CmpTransactionModel.Status.ISSUED:
            self.populate_success_context(context, transaction_record)

    def _create_processing_transaction(
        self,
        context: CmpCertificateRequestContext,
        transaction_id: str,
        request_der: bytes,
    ) -> CmpTransactionModel:
        """Create the initial CMP transaction row or reuse the one won by a race."""
        defaults = {
            'operation': str(context.operation or ''),
            'request_body_type': str(context.cmp_body_type or ''),
            'domain_name': str(context.domain_str or ''),
            'cert_profile': str(context.cert_profile_str or ''),
            'cert_req_id': 0,
            'request_der': request_der,
            'implicit_confirm': bool(context.implicit_confirm),
            'device': context.device,
            'domain': context.domain,
            'status': CmpTransactionModel.Status.PROCESSING,
            'detail': 'CMP certificate request is being processed.',
            'check_after_seconds': self.DEFAULT_CHECK_AFTER_SECONDS,
        }
        try:
            with transaction.atomic():
                return CmpTransactionModel.objects.create(transaction_id=transaction_id, **defaults)
        except IntegrityError:
            existing = self._get_existing_transaction(transaction_id)
            if existing is None:
                raise
            self._validate_existing_request(existing, context, request_der)
            return existing

    def _mark_transaction_waiting(
        self,
        transaction_pk: int,
        *,
        backend: str,
        backend_reference: str,
        detail: str,
    ) -> CmpTransactionModel:
        """Persist that this CMP request is waiting on an asynchronous backend."""
        return CmpTransactionState.mark_waiting(
            transaction_pk,
            backend=backend,
            backend_reference=backend_reference,
            detail=detail,
            check_after_seconds=self.DEFAULT_CHECK_AFTER_SECONDS,
        )

    def _mark_transaction_terminal(
        self,
        transaction_pk: int,
        *,
        request_decision: Workflow2IssuanceDecision,
        run_status: str,
    ) -> CmpTransactionModel:
        """Persist a rejected/failed CMP transaction from the workflows2 decision."""
        return CmpTransactionState.mark_terminal_from_request_decision(
            transaction_pk,
            request_decision=request_decision,
            run_status=run_status,
        )

    def _mark_transaction_failed(self, transaction_pk: int, *, detail: str) -> CmpTransactionModel:
        """Persist a local CMP processing failure before a certificate was issued."""
        return CmpTransactionState.mark_failed(transaction_pk, detail=detail)

    def mark_transaction_issued(
        self,
        transaction_pk: int,
        context: CmpCertificateRequestContext,
    ) -> CmpTransactionModel:
        """Persist the final issued certificate material for one CMP transaction."""
        return CmpTransactionState.mark_issued(transaction_pk, context)
