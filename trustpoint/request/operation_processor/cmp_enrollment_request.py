"""CMP enrollment-request processing with CMP-owned transaction persistence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from cryptography.hazmat.primitives import hashes
from django.db import IntegrityError, transaction
from django.utils import timezone

from cmp.models import CmpTransactionModel
from pki.models import CertificateModel
from request.authorization import CmpAuthorization
from request.message_parser import CmpMessageParser
from request.request_context import BaseRequestContext, CmpCertificateRequestContext, HttpBaseRequestContext
from request.workflows2_gate import NEGATIVE_RUN_STATUSES, PENDING_RUN_STATUSES
from request.workflows2_handler import Workflow2Handler
from trustpoint.logger import LoggerMixin
from workflows2.models import Workflow2Run

from .base import AbstractOperationProcessor
from .issue_cert import CertificateIssueProcessor


@dataclass(frozen=True)
class _StoredCmpHttpRequest:
    """Minimal request-like object for replaying a stored CMP DER body."""

    body: bytes


class CmpEnrollmentRequestProcessor(AbstractOperationProcessor, LoggerMixin):
    """Process CMP IR/CR enrollment requests through CMP transaction state."""

    DEFAULT_CHECK_AFTER_SECONDS = 35

    def process_operation(self, context: BaseRequestContext) -> None:  # noqa: C901
        """Process one CMP enrollment request."""
        if not isinstance(context, CmpCertificateRequestContext):
            exc_msg = 'CmpEnrollmentRequestProcessor requires a CmpCertificateRequestContext.'
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

        if context.event is not None:
            Workflow2Handler().handle(context)

        workflow_outcome = context.workflow2_outcome
        if workflow_outcome is not None:
            run_status = str(workflow_outcome.run.status)
            if run_status in PENDING_RUN_STATUSES:
                context.cmp_transaction = self._mark_transaction_waiting(
                    transaction_record.pk,
                    backend=CmpTransactionModel.Backend.WORKFLOW2,
                    backend_reference=str(workflow_outcome.run.id),
                    detail=self.detail_for_pending_run(run_status),
                )
                return
            if run_status in NEGATIVE_RUN_STATUSES:
                context.cmp_transaction = self._mark_transaction_terminal(
                    transaction_record.pk,
                    run_status=run_status,
                )
                return

        try:
            CertificateIssueProcessor().process_operation(context)
        except Exception:
            self._mark_transaction_failed(
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
        """Rebuild the original CMP enrollment context for final issuance."""
        replay_context = CmpCertificateRequestContext(
            raw_message=cast('Any', _StoredCmpHttpRequest(body=bytes(transaction_record.request_der))),
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
        if not isinstance(context, HttpBaseRequestContext) or context.raw_message is None:
            exc_msg = 'CMP enrollment context is missing its raw HTTP message.'
            raise ValueError(exc_msg)

        raw_body = getattr(context.raw_message, 'body', b'') or b''
        if isinstance(raw_body, bytes):
            return raw_body
        if isinstance(raw_body, bytearray):
            return bytes(raw_body)
        if isinstance(raw_body, str):
            return raw_body.encode('utf-8')

        exc_msg = 'CMP enrollment request body must be bytes-like.'
        raise TypeError(exc_msg)

    @classmethod
    def _require_request_der(cls, context: CmpCertificateRequestContext) -> bytes:
        request_der = cls._request_body_bytes(context)
        if not request_der:
            exc_msg = 'CMP enrollment request body is empty.'
            raise ValueError(exc_msg)
        return request_der

    @staticmethod
    def _require_transaction_id(context: CmpCertificateRequestContext) -> str:
        transaction_id = str(context.cmp_transaction_id or '').strip().lower()
        if not transaction_id:
            exc_msg = 'CMP enrollment request is missing transactionID.'
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
        return (
            CmpTransactionModel.objects.select_related('final_certificate', 'issuer_credential', 'device', 'domain')
            .filter(transaction_id=transaction_id)
            .first()
        )

    def _validate_existing_request(
        self,
        transaction_record: CmpTransactionModel,
        context: CmpCertificateRequestContext,
        request_der: bytes,
    ) -> None:
        if not self._request_matches_transaction(transaction_record, context, request_der):
            exc_msg = 'CMP transactionID is already in use for a different enrollment request.'
            raise ValueError(exc_msg)

    def _apply_existing_transaction(
        self,
        context: CmpCertificateRequestContext,
        transaction_record: CmpTransactionModel,
    ) -> None:
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
            'detail': 'CMP enrollment request is being processed.',
            'check_after_seconds': self.DEFAULT_CHECK_AFTER_SECONDS,
            'backend': CmpTransactionModel.Backend.NONE,
            'backend_reference': '',
            'final_certificate': None,
            'issuer_credential': None,
            'finalized_at': None,
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
        with transaction.atomic():
            transaction_record = CmpTransactionModel.objects.select_for_update().get(pk=transaction_pk)
            transaction_record.status = CmpTransactionModel.Status.WAITING
            transaction_record.detail = detail
            transaction_record.check_after_seconds = self.DEFAULT_CHECK_AFTER_SECONDS
            transaction_record.backend = backend
            transaction_record.backend_reference = backend_reference
            transaction_record.final_certificate = None
            transaction_record.issuer_credential = None
            transaction_record.finalized_at = None
            transaction_record.save(
                update_fields=[
                    'status',
                    'detail',
                    'check_after_seconds',
                    'backend',
                    'backend_reference',
                    'final_certificate',
                    'issuer_credential',
                    'finalized_at',
                    'updated_at',
                ]
            )
            return transaction_record

    def _mark_transaction_terminal(self, transaction_pk: int, *, run_status: str) -> CmpTransactionModel:
        if run_status == Workflow2Run.STATUS_REJECTED:
            status = CmpTransactionModel.Status.REJECTED
            detail = 'Enrollment request rejected by workflow.'
        elif run_status == Workflow2Run.STATUS_CANCELLED:
            status = CmpTransactionModel.Status.CANCELLED
            detail = 'Enrollment request cancelled in workflow processing.'
        else:
            status = CmpTransactionModel.Status.FAILED
            detail = 'Enrollment request failed in workflow processing.'

        with transaction.atomic():
            transaction_record = CmpTransactionModel.objects.select_for_update().get(pk=transaction_pk)
            transaction_record.status = status
            transaction_record.detail = detail
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
            return transaction_record

    def _mark_transaction_failed(self, transaction_pk: int, *, detail: str) -> CmpTransactionModel:
        with transaction.atomic():
            transaction_record = CmpTransactionModel.objects.select_for_update().get(pk=transaction_pk)
            transaction_record.status = CmpTransactionModel.Status.FAILED
            transaction_record.detail = detail
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
            return transaction_record

    def mark_transaction_issued(
        self,
        transaction_pk: int,
        context: CmpCertificateRequestContext,
    ) -> CmpTransactionModel:
        """Persist the issued certificate result on the CMP transaction."""
        if context.issued_certificate is None:
            exc_msg = 'Cannot mark CMP transaction as issued without an issued certificate.'
            raise ValueError(exc_msg)

        certificate_fingerprint = context.issued_certificate.fingerprint(hashes.SHA256()).hex().upper()
        final_certificate = CertificateModel.get_cert_by_sha256_fingerprint(certificate_fingerprint)
        if final_certificate is None:
            exc_msg = f'Issued CMP certificate {certificate_fingerprint} was not persisted in the database.'
            raise ValueError(exc_msg)

        with transaction.atomic():
            transaction_record = CmpTransactionModel.objects.select_for_update().get(pk=transaction_pk)
            transaction_record.status = CmpTransactionModel.Status.ISSUED
            transaction_record.detail = ''
            transaction_record.final_certificate = final_certificate
            transaction_record.issuer_credential = context.issuer_credential
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(
                update_fields=[
                    'status',
                    'detail',
                    'final_certificate',
                    'issuer_credential',
                    'finalized_at',
                    'updated_at',
                ]
            )
            return transaction_record
