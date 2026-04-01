"""Small helpers for CMP transaction persistence and state transitions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from django.db import transaction
from django.utils import timezone

from cmp.models import CmpTransactionModel
from pki.models import CertificateModel
from workflows2.models import Workflow2Run

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
        return (
            CmpTransactionModel.objects.select_for_update()
            .select_related('device', 'domain', 'final_certificate', 'issuer_credential')
            .get(pk=transaction_pk)
        )

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
        """Mark one CMP transaction terminal based on a workflows2 run status."""
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
            transaction_record = CmpTransactionState.load_locked(transaction_pk)
            transaction_record.status = status
            transaction_record.detail = detail
            transaction_record.finalized_at = timezone.now()
            transaction_record.save(update_fields=['status', 'detail', 'finalized_at', 'updated_at'])
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
