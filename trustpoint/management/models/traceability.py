# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Models for long-lived Traceability Credentials."""

from __future__ import annotations

import datetime
from typing import ClassVar

from django.apps import apps
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta
from trustpoint_core.oid import NamedCurve


class TraceabilityCredentialModel(models.Model):
    """Logical Traceability Credential identity across key rotations."""

    class Curve(models.TextChoices):
        """Curves supported by Traceability Credentials."""

        SECP256R1 = NamedCurve.SECP256R1.dotted_string, NamedCurve.SECP256R1.verbose_name
        SECP384R1 = NamedCurve.SECP384R1.dotted_string, NamedCurve.SECP384R1.verbose_name

    class Purpose(models.TextChoices):
        """Stable consumer purposes for Traceability Credentials."""

        ISSUANCE_LOG = 'ISSUANCE_LOG', _('Issuance Log')
        AUDIT_LOG = 'AUDIT_LOG', _('Audit Log')
        CT_LOG = 'CT_LOG', _('Certificate Transparency Log')

    class Status(models.TextChoices):
        """Logical credential lifecycle states."""

        ACTIVE = 'ACTIVE', _('Active')
        RETIRED = 'RETIRED', _('Retired')

    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, default='')
    curve = models.CharField(max_length=64, choices=Curve.choices)
    purposes = models.JSONField(default=list)
    status = models.CharField(max_length=8, choices=Status.choices, default=Status.ACTIVE)
    current_generation = models.ForeignKey(
        'management.TraceabilityCredentialGenerationModel',
        on_delete=models.PROTECT,
        related_name='+',
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta(TypedModelMeta):
        """Model metadata."""

        ordering: ClassVar[list[str]] = ['-created_at']

    def __str__(self) -> str:
        """Return the logical credential name."""
        return self.name

    def clean(self) -> None:
        """Defensively enforce immutable metadata and lifecycle invariants."""
        self._clean_metadata()
        self._clean_lifecycle()

    def _clean_metadata(self) -> None:
        """Validate required and immutable metadata."""
        if not self.name:
            raise ValidationError({'name': _('Name is required.')})
        normalized_purposes = list(dict.fromkeys(self.purposes or []))
        known_purposes = {choice.value for choice in self.Purpose}
        if not normalized_purposes:
            raise ValidationError({'purposes': _('At least one purpose is required.')})
        if len(normalized_purposes) != len(self.purposes):
            raise ValidationError({'purposes': _('Purposes must not contain duplicates.')})
        if any(purpose not in known_purposes for purpose in normalized_purposes):
            raise ValidationError({'purposes': _('Unknown Traceability Credential purpose.')})

        if self.pk:
            previous = type(self).objects.get(pk=self.pk)
            if self.name != previous.name or self.curve != previous.curve or self.purposes != previous.purposes:
                raise ValidationError(_('Name, curve, and purposes are immutable after creation.'))

    def _clean_lifecycle(self) -> None:
        """Validate status and retirement timestamp consistency."""
        if self.status not in self.Status.values:
            raise ValidationError({'status': _('Invalid Traceability Credential status.')})
        if self.status == self.Status.ACTIVE and self.retired_at is not None:
            raise ValidationError({'retired_at': _('Active credentials cannot have a retirement timestamp.')})
        if self.status == self.Status.RETIRED and self.retired_at is None:
            raise ValidationError({'retired_at': _('Retired credentials require a retirement timestamp.')})

        previous = type(self).objects.get(pk=self.pk) if self.pk else None
        if previous and previous.status == self.Status.RETIRED and self.status != self.Status.RETIRED:
            raise ValidationError(_('A retired Traceability Credential cannot be reactivated.'))

    @property
    def is_usable(self) -> bool:
        """Return whether the current generation can sign now."""
        if self.status != self.Status.ACTIVE or self.current_generation is None:
            return False
        generation = self.current_generation
        if generation.status != TraceabilityCredentialGenerationModel.Status.ACTIVE:
            return False
        certificate = generation.credential.certificate
        if certificate is None:
            return False
        now = datetime.datetime.now(datetime.UTC)
        return certificate.not_valid_before <= now <= certificate.not_valid_after

    def delete(self, *_args: object, **_kwargs: object) -> tuple[int, dict[str, int]]:
        """Prevent deletion; retirement is the lifecycle end state."""
        raise ValidationError(_('Traceability Credentials cannot be deleted.'))


class TraceabilityCredentialGenerationModel(models.Model):
    """A concrete key and certificate generation of a logical credential."""

    class Status(models.TextChoices):
        """Generation lifecycle states."""

        ACTIVE = 'ACTIVE', _('Active')
        RETIRED = 'RETIRED', _('Retired')

    traceability_credential = models.ForeignKey(
        TraceabilityCredentialModel,
        on_delete=models.PROTECT,
        related_name='generations',
    )
    credential = models.OneToOneField(
        'pki.CredentialModel',
        on_delete=models.PROTECT,
        related_name='traceability_generation',
    )
    generation_number = models.PositiveIntegerField()
    status = models.CharField(max_length=8, choices=Status.choices)
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField()
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta(TypedModelMeta):
        """Model metadata."""

        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['traceability_credential', 'generation_number'],
                name='traceability_signing_generation_number_unique',
            ),
            models.UniqueConstraint(
                fields=['traceability_credential'],
                condition=models.Q(status='ACTIVE'),
                name='traceability_signing_one_active_generation',
            ),
        ]
        ordering: ClassVar[list[str]] = ['generation_number']

    def __str__(self) -> str:
        """Return the generation identity."""
        return f'{self.traceability_credential.name} generation {self.generation_number}'

    def clean(self) -> None:
        """Defensively enforce credential type and timestamp invariants."""
        credential_model = apps.get_model('pki', 'CredentialModel')
        if self.credential.credential_type != credential_model.CredentialTypeChoice.EVIDENCE_SIGNING_CREDENTIAL:
            raise ValidationError({'credential': _('Credential must be an Traceability Credential.')})
        if self.status == self.Status.ACTIVE:
            if self.activated_at is None or self.retired_at is not None:
                raise ValidationError(_('Active generations require activation and no retirement timestamp.'))
        elif self.status == self.Status.RETIRED:
            if self.activated_at is None or self.retired_at is None:
                raise ValidationError(_('Retired generations require activation and retirement timestamps.'))
        else:
            raise ValidationError({'status': _('Invalid generation status.')})
        if self.retired_at is not None and self.retired_at < self.activated_at:
            raise ValidationError({'retired_at': _('A generation cannot retire before activation.')})

    def delete(self, *_args: object, **_kwargs: object) -> tuple[int, dict[str, int]]:
        """Prevent deletion; generations are retained for historical verification."""
        raise ValidationError(_('Traceability Credential generations cannot be deleted.'))
