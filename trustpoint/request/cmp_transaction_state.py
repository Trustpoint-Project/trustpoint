"""Small helpers for CMP transaction persistence and state transitions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from django.db import transaction
from django.utils import timezone

from cmp.models import CmpTransactionModel
from pki.models import CertificateModel
from workflows2.models import Workflow2Run
from workflows2.services.request_decision import Workflow2RequestDecision, resolve_request_decision

if TYPE_CHECKING:
    from request.request_context import BaseCertificateRequestContext


class CmpTransactionState:
    """Read and update persisted CMP transaction state."""

    @staticmethod
    def get_by_transaction_id(transaction_id: str) -> CmpTransactionModel | None:
        """Return one CMP transaction by transaction ID, if present."""
        return (
            CmpTransactionModel.objects.select_related('device', 'domain', 'final_certificate', 'issuer_credential')
            .filter(transaction_id=transaction_id)
            .first()
        )

    @staticmethod
    def load_locked(transaction_pk: int) -> CmpTransactionModel:
        """Load one CMP transaction row with a write lock."""
        return CmpTransactionModel.objects.select_for_update().get(pk=transaction_pk)

    @staticmethod
    def mark_processing(transaction_pk: int, *, detail: str) -> CmpTransactionModel:
        """Mark one CMP transaction as processing."""
        with transaction.atomic():
            transaction_record = CmpTransactionState.load_locked(transaction_pk)
            transaction_record.status = CmpTransactionModel.Status.PROCESSING
            transaction_record.detail = detail
            transaction_record.save(update_fields=['status', 'detail', 'updated_at'])
            return transaction_record

    @staticmethod
    def mark_waiting(
        transaction_pk: int,
        *,
        backend: str,
        backend_reference: str,
        detail: str,
        check_after_seconds: int,
    ) -> CmpTransactionModel:
        """Mark one CMP transaction as waiting on a backend."""
        with transaction.atomic():
            transaction_record = CmpTransactionState.load_locked(transaction_pk)
            transaction_record.status = CmpTransactionModel.Status.WAITING
            transaction_record.detail = detail
            transaction_record.check_after_seconds = check_after_seconds
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

    @staticmethod
    def mark_terminal_from_run_status(transaction_pk: int, *, run_status: str) -> CmpTransactionModel:
        """Mark one CMP transaction terminal based on one request workflow decision."""
        return CmpTransactionState.mark_terminal_from_request_decision(
            transaction_pk,
            request_decision=(
                Workflow2RequestDecision.REJECT
                if run_status == Workflow2Run.STATUS_REJECTED
                else Workflow2RequestDecision.FAIL
            ),
            run_status=run_status,
        )

    @staticmethod
    def mark_terminal_from_request_decision(
        transaction_pk: int,
        *,
        request_decision: Workflow2RequestDecision,
        run_status: str | None = None,
    ) -> CmpTransactionModel:
        """Mark one CMP transaction terminal from the request-facing workflow decision."""
        if request_decision == Workflow2RequestDecision.REJECT:
            status = CmpTransactionModel.Status.REJECTED
            detail = 'Enrollment request rejected by workflow.'
        elif run_status == Workflow2Run.STATUS_CANCELLED:
            status = CmpTransactionModel.Status.CANCELLED
            detail = 'Enrollment request cancelled in workflow processing.'
        elif request_decision == Workflow2RequestDecision.FAIL:
            status = CmpTransactionModel.Status.FAILED
            detail = 'Enrollment request failed in workflow processing.'
        else:
            exc_msg = 'CMP terminal transaction update requires a reject or fail workflow decision.'
            raise ValueError(exc_msg)

        with transaction.atomic():
            transaction_record = CmpTransactionState.load_locked(transaction_pk)
            transaction_record.status = status
            transaction_record.detail = detail
            transaction_record.backend = CmpTransactionModel.Backend.NONE
            transaction_record.finalized_at = timezone.now()
            if status == CmpTransactionModel.Status.CANCELLED:
                transaction_record.device = None
                transaction_record.domain = None
            transaction_record.save(
                update_fields=[
                    'status',
                    'detail',
                    'backend',
                    'device',
                    'domain',
                    'finalized_at',
                    'updated_at',
                ]
            )
            return transaction_record

    @staticmethod
    def mark_failed(transaction_pk: int, *, detail: str) -> CmpTransactionModel:
        """Mark one CMP transaction as failed."""
        with transaction.atomic():
            transaction_record = CmpTransactionState.load_locked(transaction_pk)
            transaction_record.status = CmpTransactionModel.Status.FAILED
            transaction_record.detail = detail
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
            return transaction_record

    @staticmethod
    def mark_issued(
        transaction_pk: int,
        context: BaseCertificateRequestContext,
    ) -> CmpTransactionModel:
        """Persist a successfully issued certificate on one CMP transaction."""
        if context.issued_certificate is None:
            exc_msg = 'Cannot mark CMP transaction as issued without an issued certificate.'
            raise ValueError(exc_msg)

        certificate_fingerprint = context.issued_certificate.fingerprint(hashes.SHA256()).hex().upper()
        final_certificate = CertificateModel.get_cert_by_sha256_fingerprint(certificate_fingerprint)
        if final_certificate is None:
            exc_msg = f'Issued CMP certificate {certificate_fingerprint} was not persisted in the database.'
            raise ValueError(exc_msg)

        with transaction.atomic():
            transaction_record = CmpTransactionState.load_locked(transaction_pk)
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

    @staticmethod
    def sync_from_workflow2_run(*, run: Workflow2Run) -> None:
        """Synchronize CMP transactions that are waiting on one workflows2 run."""
        run_id = getattr(run, 'id', None)
        run_status = str(run.status)
        transaction_ids = list(
            CmpTransactionModel.objects.filter(
                backend=CmpTransactionModel.Backend.WORKFLOW2,
                backend_reference=str(run_id),
                status__in=[
                    CmpTransactionModel.Status.WAITING,
                    CmpTransactionModel.Status.PROCESSING,
                ],
            ).values_list('pk', flat=True)
        )
        if not transaction_ids:
            return

        request_decision = resolve_request_decision(run)

        if request_decision == Workflow2RequestDecision.CONTINUE:
            for transaction_pk in transaction_ids:
                CmpTransactionState.mark_processing(
                    transaction_pk,
                    detail='CMP poll finalization in progress.',
                )
            return

        if request_decision == Workflow2RequestDecision.WAIT:
            for transaction_pk in transaction_ids:
                transaction_record = CmpTransactionModel.objects.only(
                    'backend',
                    'backend_reference',
                    'check_after_seconds',
                ).get(pk=transaction_pk)
                CmpTransactionState.mark_waiting(
                    transaction_pk,
                    backend=transaction_record.backend,
                    backend_reference=transaction_record.backend_reference,
                    detail=CmpTransactionState._detail_for_pending_run_status(run_status),
                    check_after_seconds=transaction_record.check_after_seconds,
                )
            return

        if request_decision in {
            Workflow2RequestDecision.REJECT,
            Workflow2RequestDecision.FAIL,
        }:
            for transaction_pk in transaction_ids:
                CmpTransactionState.mark_terminal_from_request_decision(
                    transaction_pk,
                    request_decision=request_decision,
                    run_status=run_status,
                )

    @staticmethod
    def _detail_for_pending_run_status(run_status: str) -> str:
        """Return a stable user-facing waiting detail from one workflows2 run status."""
        if run_status == Workflow2Run.STATUS_AWAITING:
            return 'Enrollment request pending workflow approval.'
        return 'Enrollment request pending workflow processing.'
