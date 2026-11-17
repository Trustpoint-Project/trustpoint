# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Configuration and signed checkpoints for the audit hash chain."""

from __future__ import annotations

import hashlib
from typing import ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta

from management.models.traceability import (
    TraceabilityCredentialGenerationModel,
    TraceabilityCredentialModel,
)


class AuditSigningConfig(models.Model):
    """Global policy for signing audit log checkpoints."""

    enabled = models.BooleanField(
        verbose_name=_('Enable audit checkpoint signing'),
        default=False,
        help_text=_('Sign a checkpoint of the audit hash chain after the configured interval.'),
    )
    traceability_credential = models.ForeignKey(
        TraceabilityCredentialModel,
        verbose_name=_('Signing credential'),
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='+',
        help_text=_('The Traceability Credential used for new audit checkpoints.'),
    )
    checkpoint_event_interval = models.PositiveIntegerField(
        verbose_name=_('Events per checkpoint'),
        default=100,
        validators=[MinValueValidator(1)],
        help_text=_('Number of new audit events that triggers a signed checkpoint.'),
    )
    checkpoint_time_interval_minutes = models.PositiveIntegerField(
        verbose_name=_('Maximum checkpoint interval (minutes)'),
        null=True,
        blank=True,
        validators=[MinValueValidator(1)],
        help_text=_('Sign at least this often when new audit events exist. Leave empty to disable time-based signing.'),
    )
    last_signing_attempt_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_signing_error = models.TextField(blank=True, default='', editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta(TypedModelMeta):
        """Model metadata."""

        verbose_name = _('Audit Log Signing Configuration')
        verbose_name_plural = _('Audit Log Signing Configuration')

    def __str__(self) -> str:
        """Return a stable display name."""
        return 'Audit Log Signing Configuration'

    @classmethod
    def get(cls) -> AuditSigningConfig:
        """Return the singleton configuration row."""
        config, _created = cls.objects.get_or_create(pk=1)
        return config

    def clean(self) -> None:
        """Reject unsafe or unusable signing settings."""
        if self.checkpoint_event_interval is None or self.checkpoint_event_interval < 1:
            raise ValidationError({'checkpoint_event_interval': _('Enter at least one audit event.')})
        if self.checkpoint_time_interval_minutes is not None and self.checkpoint_time_interval_minutes < 1:
            raise ValidationError({'checkpoint_time_interval_minutes': _('Enter at least one minute.')})
        if not self.enabled:
            return
        credential = self.traceability_credential
        if credential is None:
            raise ValidationError({'traceability_credential': _('Select a Traceability Credential.')})
        if credential.status != TraceabilityCredentialModel.Status.ACTIVE or not credential.is_usable:
            raise ValidationError(
                {'traceability_credential': _('The selected Traceability Credential is not currently usable.')}
            )


class AuditLogCheckpoint(models.Model):
    """A signed commitment to a contiguous range of audit chain entries."""

    checkpoint_number = models.PositiveIntegerField(unique=True, editable=False)
    first_sequence = models.PositiveBigIntegerField(editable=False)
    last_sequence = models.PositiveBigIntegerField(unique=True, editable=False)
    entry_count = models.PositiveBigIntegerField(editable=False)
    head_hash = models.CharField(max_length=64, editable=False)
    previous_checkpoint_hash = models.CharField(max_length=64, blank=True, default='', editable=False)
    payload = models.TextField(editable=False)
    signature = models.BinaryField(editable=False)
    signature_algorithm = models.CharField(max_length=32, editable=False)
    traceability_credential = models.ForeignKey(
        TraceabilityCredentialModel,
        on_delete=models.PROTECT,
        related_name='audit_checkpoints',
        editable=False,
    )
    traceability_generation = models.ForeignKey(
        TraceabilityCredentialGenerationModel,
        on_delete=models.PROTECT,
        related_name='audit_checkpoints',
        editable=False,
    )
    certificate_fingerprint_sha256 = models.CharField(max_length=64, editable=False)
    signed_at = models.DateTimeField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta(TypedModelMeta):
        """Model metadata."""

        ordering: ClassVar[list[str]] = ['checkpoint_number']
        verbose_name = _('Audit Log Checkpoint')
        verbose_name_plural = _('Audit Log Checkpoints')

    def __str__(self) -> str:
        """Return the covered range."""
        return f'Checkpoint {self.checkpoint_number} (sequences {self.first_sequence}-{self.last_sequence})'

    @property
    def checkpoint_hash(self) -> str:
        """Return the hash that links the next checkpoint to this payload."""
        return hashlib.sha256(self.payload.encode('utf-8')).hexdigest()

    def delete(self, *_args: object, **_kwargs: object) -> tuple[int, dict[str, int]]:
        """Prevent deletion so historical signature verification remains possible."""
        raise ValidationError(_('Audit log checkpoints cannot be deleted.'))
