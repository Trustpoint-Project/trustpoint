"""CMP pollReq processing backed by persisted CMP transaction state."""

from __future__ import annotations

from enum import Enum

from django.db import transaction

from cmp.models import CmpTransactionModel
from request.cmp_transaction_state import CmpTransactionState
from request.request_context import BaseRequestContext, CmpPollRequestContext
from trustpoint.logger import LoggerMixin
from workflows2.models import Workflow2Run
from workflows2.services.request_decision import Workflow2RequestDecision, resolve_request_decision

from .base import AbstractOperationProcessor
from .cmp_certificate_request import CmpCertificateRequestProcessor
from .issue_cert import CertificateIssueProcessor


class CmpPollDisposition(Enum):
    """Describe the next poll-processing step for one CMP transaction."""

    WAIT = 'wait'
    READY_FOR_FINAL_ISSUANCE = 'ready_for_final_issuance'
    ISSUED = 'issued'
    TERMINAL = 'terminal'


class CmpPollProcessor(AbstractOperationProcessor, LoggerMixin):
    """Resolve CMP pollReq messages through CMP transaction state transitions."""

    @transaction.atomic
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
            transaction_record = self._refresh_waiting_transaction(transaction_record)

        context.cmp_transaction = transaction_record
        context.operation = transaction_record.operation
        context.cert_profile_str = transaction_record.cert_profile or None
        context.implicit_confirm = transaction_record.implicit_confirm

        disposition = self._determine_poll_disposition(transaction_record)
        if disposition == CmpPollDisposition.ISSUED:
            CmpCertificateRequestProcessor.populate_success_context(context, transaction_record)
            return

        if disposition == CmpPollDisposition.READY_FOR_FINAL_ISSUANCE:
            self._finalize_transaction(context)

    def _load_locked_transaction(
        self,
        context: CmpPollRequestContext,
    ) -> CmpTransactionModel:
        """Reload the authorized CMP transaction with a row lock for poll handling."""
        context_transaction = context.cmp_transaction
        if context_transaction is None:
            exc_msg = 'CMP pollReq is missing its CMP transaction context.'
            raise ValueError(exc_msg)

        return CmpTransactionState.load_locked(context_transaction.pk)

    def _finalize_transaction(self, context: CmpPollRequestContext) -> None:
        """Replay the original CMP request and finish issuance after approval."""
        transaction_record = context.cmp_transaction
        if transaction_record is None:
            exc_msg = 'CMP poll finalization requires a CMP transaction.'
            raise ValueError(exc_msg)

        replay_context = CmpCertificateRequestProcessor.build_replay_context(transaction_record, context)
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

        issued_transaction = CmpCertificateRequestProcessor().mark_transaction_issued(
            transaction_record.pk,
            replay_context,
        )
        context.cmp_transaction = issued_transaction
        CmpCertificateRequestProcessor.populate_success_context(context, issued_transaction)

    def _refresh_waiting_transaction(self, transaction_record: CmpTransactionModel) -> CmpTransactionModel:
        """Refresh one waiting CMP transaction from its backend state."""
        next_transaction = transaction_record
        if transaction_record.backend != CmpTransactionModel.Backend.WORKFLOW2:
            return next_transaction
        if not transaction_record.backend_reference:
            next_transaction = CmpTransactionState.mark_failed(
                transaction_record.pk,
                detail='CMP transaction is missing its workflows2 run reference.',
            )
        else:
            run = Workflow2Run.objects.filter(pk=transaction_record.backend_reference).first()
            if run is None:
                next_transaction = CmpTransactionState.mark_failed(
                    transaction_record.pk,
                    detail='Referenced workflows2 run no longer exists for this CMP transaction.',
                )
            else:
                run_status = str(run.status)
                request_decision = resolve_request_decision(run)
                if request_decision == Workflow2RequestDecision.WAIT:
                    next_transaction = CmpTransactionState.mark_waiting(
                        transaction_record.pk,
                        backend=transaction_record.backend,
                        backend_reference=transaction_record.backend_reference,
                        detail=CmpCertificateRequestProcessor.detail_for_pending_run(run_status),
                        check_after_seconds=transaction_record.check_after_seconds,
                    )
                elif request_decision == Workflow2RequestDecision.CONTINUE:
                    next_transaction = CmpTransactionState.mark_processing(
                        transaction_record.pk,
                        detail='CMP poll finalization in progress.',
                    )
                elif request_decision in {
                    Workflow2RequestDecision.REJECT,
                    Workflow2RequestDecision.FAIL,
                }:
                    next_transaction = CmpTransactionState.mark_terminal_from_request_decision(
                        transaction_record.pk,
                        request_decision=request_decision,
                        run_status=run_status,
                    )

        return next_transaction

    @staticmethod
    def _determine_poll_disposition(transaction_record: CmpTransactionModel) -> CmpPollDisposition:
        """Return the current poll-processing disposition for one CMP transaction."""
        if transaction_record.status == CmpTransactionModel.Status.ISSUED:
            return CmpPollDisposition.ISSUED
        if transaction_record.status == CmpTransactionModel.Status.PROCESSING:
            return CmpPollDisposition.READY_FOR_FINAL_ISSUANCE
        if transaction_record.status == CmpTransactionModel.Status.WAITING:
            return CmpPollDisposition.WAIT
        return CmpPollDisposition.TERMINAL

    def _mark_failed(self, transaction_pk: int, *, detail: str) -> CmpTransactionModel:
        """Store a terminal CMP poll failure on the persisted transaction."""
        return CmpTransactionState.mark_failed(transaction_pk, detail=detail)
