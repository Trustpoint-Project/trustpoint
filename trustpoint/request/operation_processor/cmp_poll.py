"""CMP pollReq processing backed by persisted CMP transaction state."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from cmp.models import CmpTransactionModel
from request.request_context import BaseRequestContext, CmpPollRequestContext
from request.workflows2_gate import NEGATIVE_RUN_STATUSES, PENDING_RUN_STATUSES
from trustpoint.logger import LoggerMixin
from workflows2.models import Workflow2Run

from .base import AbstractOperationProcessor
from .cmp_enrollment_request import CmpEnrollmentRequestProcessor
from .issue_cert import CertificateIssueProcessor


class CmpPollProcessor(AbstractOperationProcessor, LoggerMixin):
    """Resolve CMP pollReq messages through CMP transaction state transitions."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process one CMP pollReq."""
        if not isinstance(context, CmpPollRequestContext):
            exc_msg = 'CmpPollProcessor requires a CmpPollRequestContext.'
            raise TypeError(exc_msg)
        if context.cmp_transaction is None:
            exc_msg = 'CMP pollReq is missing its CMP transaction context.'
            raise ValueError(exc_msg)

        transaction_record = self._load_locked_transaction(context)
        if transaction_record.status == CmpTransactionModel.Status.WAITING:
            transaction_record = self._synchronize_waiting_transaction(transaction_record)

        context.cmp_transaction = transaction_record
        context.operation = transaction_record.operation
        context.cert_profile_str = transaction_record.cert_profile or None
        context.implicit_confirm = transaction_record.implicit_confirm

        if transaction_record.status == CmpTransactionModel.Status.ISSUED:
            CmpEnrollmentRequestProcessor.populate_success_context(context, transaction_record)
            return

        if self._is_ready_for_final_issuance(transaction_record):
            self._finalize_transaction(context)

    def _load_locked_transaction(
        self,
        context: CmpPollRequestContext,
    ) -> CmpTransactionModel:
        context_transaction = context.cmp_transaction
        if context_transaction is None:
            exc_msg = 'CMP pollReq is missing its CMP transaction context.'
            raise ValueError(exc_msg)

        with transaction.atomic():
            return (
                CmpTransactionModel.objects.select_for_update()
                .select_related('device', 'domain', 'final_certificate', 'issuer_credential')
                .get(pk=context_transaction.pk)
            )

    def _finalize_transaction(self, context: CmpPollRequestContext) -> None:
        transaction_record = context.cmp_transaction
        if transaction_record is None:
            exc_msg = 'CMP poll finalization requires a CMP transaction.'
            raise ValueError(exc_msg)

        replay_context = CmpEnrollmentRequestProcessor.build_replay_context(transaction_record, context)
        try:
            CertificateIssueProcessor().process_operation(replay_context)
        except Exception:  # noqa: BLE001
            context.cmp_transaction = self._mark_failed(
                transaction_record.pk,
                detail='CMP poll finalization failed while issuing the certificate.',
            )
            return

        if replay_context.issued_certificate is None:
            context.cmp_transaction = self._mark_failed(
                transaction_record.pk,
                detail='CMP poll finalization completed without issuing a certificate.',
            )
            return

        issued_transaction = CmpEnrollmentRequestProcessor().mark_transaction_issued(
            transaction_record.pk,
            replay_context,
        )
        context.cmp_transaction = issued_transaction
        CmpEnrollmentRequestProcessor.populate_success_context(context, issued_transaction)

    def _synchronize_waiting_transaction(self, transaction_record: CmpTransactionModel) -> CmpTransactionModel:
        """Refresh one waiting CMP transaction from its backend state."""
        if transaction_record.backend != CmpTransactionModel.Backend.WORKFLOW2:
            return transaction_record

        if not transaction_record.backend_reference:
            transaction_record.status = CmpTransactionModel.Status.FAILED
            transaction_record.detail = 'CMP transaction is missing its workflows2 run reference.'
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
            return transaction_record

        run = Workflow2Run.objects.filter(pk=transaction_record.backend_reference).first()
        if run is None:
            transaction_record.status = CmpTransactionModel.Status.FAILED
            transaction_record.detail = 'Referenced workflows2 run no longer exists for this CMP transaction.'
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
            return transaction_record

        run_status = str(run.status)
        if run_status in PENDING_RUN_STATUSES:
            transaction_record.status = CmpTransactionModel.Status.WAITING
            transaction_record.detail = CmpEnrollmentRequestProcessor.detail_for_pending_run(run_status)
            transaction_record.save(update_fields=['status', 'detail', 'updated_at'])
            return transaction_record

        if run_status == Workflow2Run.STATUS_SUCCEEDED:
            transaction_record.status = CmpTransactionModel.Status.PROCESSING
            transaction_record.detail = 'CMP poll finalization in progress.'
            transaction_record.save(update_fields=['status', 'detail', 'updated_at'])
            return transaction_record

        if run_status in NEGATIVE_RUN_STATUSES:
            if run_status == Workflow2Run.STATUS_REJECTED:
                transaction_record.status = CmpTransactionModel.Status.REJECTED
                transaction_record.detail = 'Enrollment request rejected by workflow.'
            elif run_status == Workflow2Run.STATUS_CANCELLED:
                transaction_record.status = CmpTransactionModel.Status.CANCELLED
                transaction_record.detail = 'Enrollment request cancelled in workflow processing.'
            else:
                transaction_record.status = CmpTransactionModel.Status.FAILED
                transaction_record.detail = 'Enrollment request failed in workflow processing.'

            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])

        return transaction_record

    @staticmethod
    def _is_ready_for_final_issuance(transaction_record: CmpTransactionModel) -> bool:
        """Return whether a CMP transaction is ready for final certificate issuance."""
        return transaction_record.status == CmpTransactionModel.Status.PROCESSING

    def _mark_failed(self, transaction_pk: int, *, detail: str) -> CmpTransactionModel:
        with transaction.atomic():
            transaction_record = CmpTransactionModel.objects.select_for_update().get(pk=transaction_pk)
            transaction_record.status = CmpTransactionModel.Status.FAILED
            transaction_record.detail = detail
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
            return transaction_record
