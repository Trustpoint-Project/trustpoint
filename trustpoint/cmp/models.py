"""CMP-owned transaction persistence for delayed delivery and polling."""
from __future__ import annotations

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class CmpTransactionModel(models.Model):
    """Persist CMP enrollment transaction state across delayed-delivery polling."""

    class Status(models.TextChoices):
        """Lifecycle state for one CMP transaction."""

        PROCESSING = 'processing', _('Processing')
        WAITING = 'waiting', _('Waiting')
        ISSUED = 'issued', _('Issued')
        REJECTED = 'rejected', _('Rejected')
        FAILED = 'failed', _('Failed')
        CANCELLED = 'cancelled', _('Cancelled')

    class Backend(models.TextChoices):
        """Backend currently responsible for completing the transaction."""

        NONE = '', _('None')
        WORKFLOW2 = 'workflow2', _('Workflow 2')

    transaction_id = models.CharField(
        verbose_name=_('Transaction ID'),
        max_length=64,
        unique=True,
        db_index=True,
        help_text=_('Hex-encoded CMP transactionID from the PKIHeader.'),
    )
    operation = models.CharField(
        verbose_name=_('CMP Operation'),
        max_length=32,
        help_text=_('CMP management operation, for example initialization or certification.'),
    )
    request_body_type = models.CharField(
        verbose_name=_('Request Body Type'),
        max_length=16,
        help_text=_('Original CMP request body type, for example ir or cr.'),
    )
    domain_name = models.CharField(
        verbose_name=_('Domain Name'),
        max_length=255,
        blank=True,
        default='',
        help_text=_('Original CMP domain path segment, even when no Domain FK could be resolved.'),
    )
    cert_profile = models.CharField(
        verbose_name=_('Certificate Profile'),
        max_length=255,
        blank=True,
        default='',
    )
    cert_req_id = models.PositiveIntegerField(
        verbose_name=_('certReqId'),
        default=0,
        help_text=_('CertResponse identifier referenced by pollReq / pollRep.'),
    )
    request_der = models.BinaryField(
        verbose_name=_('Original Request (DER)'),
        help_text=_('Original CMP enrollment PKIMessage in DER form.'),
    )
    implicit_confirm = models.BooleanField(
        verbose_name=_('Implicit Confirm Requested'),
        default=False,
    )

    device = models.ForeignKey(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name='cmp_transactions',
    )
    domain = models.ForeignKey(
        'pki.DomainModel',
        verbose_name=_('Domain'),
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name='cmp_transactions',
    )

    status = models.CharField(
        verbose_name=_('Status'),
        max_length=16,
        choices=Status.choices,
        default=Status.PROCESSING,
        db_index=True,
    )
    detail = models.TextField(
        verbose_name=_('Detail'),
        blank=True,
        default='',
    )
    check_after_seconds = models.PositiveIntegerField(
        verbose_name=_('Check After (Seconds)'),
        default=5,
    )

    backend = models.CharField(
        verbose_name=_('Backend'),
        max_length=32,
        choices=Backend.choices,
        blank=True,
        default=Backend.NONE,
    )
    backend_reference = models.CharField(
        verbose_name=_('Backend Reference'),
        max_length=128,
        blank=True,
        default='',
    )

    final_certificate = models.ForeignKey(
        'pki.CertificateModel',
        verbose_name=_('Final Certificate'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='cmp_transaction_records',
    )
    issuer_credential = models.ForeignKey(
        'pki.CredentialModel',
        verbose_name=_('Issuer Credential'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='cmp_transaction_issuer_records',
    )

    created_at = models.DateTimeField(verbose_name=_('Created At'), default=timezone.now)
    updated_at = models.DateTimeField(verbose_name=_('Updated At'), auto_now=True)
    finalized_at = models.DateTimeField(verbose_name=_('Finalized At'), null=True, blank=True)

    class Meta:
        """Indexes for transaction and state lookups."""

        indexes = (
            models.Index(fields=['status']),
            models.Index(fields=['backend', 'backend_reference']),
            models.Index(fields=['device', 'status']),
            models.Index(fields=['domain', 'status']),
        )

    def __str__(self) -> str:
        """Return a readable transaction identifier."""
        return f'CMP transaction {self.transaction_id} ({self.status})'
