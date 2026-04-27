"""Models for Issuing CA rollover management."""

from __future__ import annotations

from typing import ClassVar

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from trustpoint.logger import LoggerMixin


class CaRolloverStrategyType(models.TextChoices):
    """Defines how the new Issuing CA is provisioned during a rollover."""

    IMPORT_CA = 'import_ca', _('Import new Issuing CA from file')
    GENERATE_KEYPAIR = 'generate_keypair', _('Generate keypair and request certificate')
    REMOTE_CA = 'remote_ca', _('Configure a remote Issuing CA')


class CaRolloverState(models.TextChoices):
    """Enumeration of CA rollover lifecycle states."""

    PLANNED = 'planned', _('Planned')
    AWAITING_NEW_CA = 'awaiting_new_ca', _('Awaiting New CA')
    IN_PROGRESS = 'in_progress', _('In Progress')
    COMPLETED = 'completed', _('Completed')
    CANCELLED = 'cancelled', _('Cancelled')


class CaRolloverModel(LoggerMixin, models.Model):
    """Tracks an Issuing CA rollover."""

    old_issuing_ca = models.ForeignKey(
        'pki.CaModel',
        on_delete=models.PROTECT,
        related_name='rollovers_as_old',
        verbose_name=_('Old Issuing CA'),
        help_text=_('The Issuing CA being replaced.'),
    )

    new_issuing_ca = models.ForeignKey(
        'pki.CaModel',
        on_delete=models.PROTECT,
        related_name='rollovers_as_new',
        null=True,
        blank=True,
        verbose_name=_('New Issuing CA'),
        help_text=_('The replacement Issuing CA. Null until the new CA is ready.'),
    )

    state = models.CharField(
        max_length=20,
        choices=CaRolloverState.choices,
        default=CaRolloverState.PLANNED,
        verbose_name=_('State'),
    )

    strategy_type = models.CharField(
        max_length=20,
        choices=CaRolloverStrategyType.choices,
        verbose_name=_('Strategy'),
        help_text=_('How the new Issuing CA is provisioned.'),
    )

    planned_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Planned At'))
    started_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Started At'))
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Completed At'))

    # TODO (FHK): This is a future functionality we should support  # noqa: FIX002
    overlap_end = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_('Overlap End'),
        help_text=_('When the old CA should stop being served in CA cert chains.'),
    )

    initiated_by = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Initiated By'),
    )

    notes = models.TextField(blank=True, default='', verbose_name=_('Notes'))

    class Meta:
        """Meta options for CaRolloverModel."""

        ordering: ClassVar[list[str]] = ['-planned_at']
        verbose_name = _('CA Rollover')
        verbose_name_plural = _('CA Rollovers')
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['old_issuing_ca'],
                condition=models.Q(state__in=['planned', 'awaiting_new_ca', 'in_progress']),
                name='unique_active_rollover_per_old_ca',
            ),
        ]

    def __str__(self) -> str:
        """Return human-readable representation."""
        new_ca_display = str(self.new_issuing_ca) if self.new_issuing_ca else _('(pending)')
        return f'{self.old_issuing_ca} → {new_ca_display} ({self.get_state_display()})'

    @property
    def is_active(self) -> bool:
        """Return True if the rollover is planned, awaiting, or in progress."""
        return self.state in (
            CaRolloverState.PLANNED,
            CaRolloverState.AWAITING_NEW_CA,
            CaRolloverState.IN_PROGRESS,
        )

    @property
    def overlap_has_ended(self) -> bool:
        """Return True if the overlap period has passed."""
        if self.overlap_end is None:
            return False
        return timezone.now() >= self.overlap_end

    def start(self) -> None:
        """Transition from PLANNED to IN_PROGRESS.

        :raises ValueError: If the rollover is not in PLANNED state or new CA is not set.
        """
        if self.state != CaRolloverState.PLANNED:
            msg = f'Cannot start rollover in state {self.get_state_display()}.'
            raise ValueError(msg)
        if self.new_issuing_ca is None:
            msg = 'Cannot start rollover without a new Issuing CA.'
            raise ValueError(msg)
        self.state = CaRolloverState.IN_PROGRESS
        self.started_at = timezone.now()
        self.save(update_fields=['state', 'started_at'])

    def complete(self) -> None:
        """Transition from IN_PROGRESS to COMPLETED.

        :raises ValueError: If the rollover is not in IN_PROGRESS state.
        """
        if self.state != CaRolloverState.IN_PROGRESS:
            msg = f'Cannot complete rollover in state {self.get_state_display()}.'
            raise ValueError(msg)
        self.state = CaRolloverState.COMPLETED
        self.completed_at = timezone.now()
        self.save(update_fields=['state', 'completed_at'])

    def cancel(self) -> None:
        """Cancel the rollover from any active state.

        :raises ValueError: If the rollover is already completed or cancelled.
        """
        if self.state in (CaRolloverState.COMPLETED, CaRolloverState.CANCELLED):
            msg = f'Cannot cancel rollover in state {self.get_state_display()}.'
            raise ValueError(msg)
        self.state = CaRolloverState.CANCELLED
        self.save(update_fields=['state'])
