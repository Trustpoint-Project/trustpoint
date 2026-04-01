"""Service layer for Issuing CA rollover operations."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.db.models import Q

from pki.models.ca_rollover import CaRolloverModel, CaRolloverState, CaRolloverStrategyType
from pki.rollover.registry import rollover_registry

if TYPE_CHECKING:
    from django import forms
    from django.contrib.auth.models import AbstractBaseUser
    from django.db.models import QuerySet

    from pki.models import CaModel
    from pki.rollover.base import RolloverStrategy

logger = logging.getLogger(__name__)


class CaRolloverError(Exception):
    """Raised when a CA rollover operation fails."""


class CaRolloverService:
    """Orchestrates Issuing CA rollover workflows.

    Delegates provisioning-specific logic to the appropriate RolloverStrategy.
    """

    @staticmethod
    def get_strategy(strategy_type: CaRolloverStrategyType) -> RolloverStrategy:
        """Resolve a strategy by its type identifier.

        :param strategy_type: The strategy type to look up.
        :returns: The registered RolloverStrategy instance.
        :raises CaRolloverError: If the strategy type is not registered.
        """
        try:
            return rollover_registry.get(strategy_type)
        except KeyError as exc:
            raise CaRolloverError(str(exc)) from exc

    @staticmethod
    def get_available_strategies() -> list[tuple[str, str]]:
        """Return the list of available rollover strategies for form dropdowns.

        :returns: List of (value, label) tuples.
        """
        return rollover_registry.get_available()

    @staticmethod
    def plan_rollover(
        old_ca: CaModel,
        strategy_type: CaRolloverStrategyType,
        form: forms.Form,
        initiated_by: AbstractBaseUser | None = None,
    ) -> CaRolloverModel:
        """Plan and create a new CA rollover.

        :param old_ca: The current Issuing CA being replaced.
        :param strategy_type: Which provisioning strategy to use.
        :param form: The validated strategy-specific form.
        :param initiated_by: The user who initiated the rollover.
        :returns: The created CaRolloverModel.
        :raises CaRolloverError: If validation or creation fails.
        """
        active_exists = CaRolloverModel.objects.filter(
            old_issuing_ca=old_ca,
            state__in=[CaRolloverState.PLANNED, CaRolloverState.AWAITING_NEW_CA, CaRolloverState.IN_PROGRESS],
        ).exists()
        if active_exists:
            msg = f'Issuing CA "{old_ca}" already has an active rollover.'
            raise CaRolloverError(msg)

        completed_exists = CaRolloverModel.objects.filter(
            old_issuing_ca=old_ca,
            state=CaRolloverState.COMPLETED,
        ).exists()
        if completed_exists:
            msg = f'Issuing CA "{old_ca}" has already been rolled over. A second rollover is not permitted.'
            raise CaRolloverError(msg)

        strategy = CaRolloverService.get_strategy(strategy_type)
        new_ca = strategy.create_new_ca(form, old_ca)

        overlap_end = form.cleaned_data.get('overlap_end') if hasattr(form, 'cleaned_data') else None
        notes = form.cleaned_data.get('notes', '') if hasattr(form, 'cleaned_data') else ''

        initial_state = CaRolloverState.PLANNED if new_ca else CaRolloverState.AWAITING_NEW_CA

        rollover = CaRolloverModel.objects.create(
            old_issuing_ca=old_ca,
            new_issuing_ca=new_ca,
            state=initial_state,
            strategy_type=strategy_type,
            overlap_end=overlap_end,
            initiated_by=initiated_by,
            notes=notes,
        )

        logger.info(
            'Planned CA rollover %s (%s): %s → %s [state=%s]',
            rollover.pk,
            strategy_type,
            old_ca,
            new_ca or '(pending)',
            initial_state,
        )
        return rollover

    @staticmethod
    def execute_rollover(rollover: CaRolloverModel) -> None:
        """Start the rollover: transition from PLANNED to IN_PROGRESS.

        :param rollover: The rollover to execute.
        :raises CaRolloverError: If the rollover cannot be started.
        """
        strategy = CaRolloverService.get_strategy(
            CaRolloverStrategyType(rollover.strategy_type),
        )

        try:
            rollover.start()
        except ValueError as exc:
            raise CaRolloverError(str(exc)) from exc

        strategy.on_start(rollover)
        logger.info('Rollover %s started.', rollover.pk)

    @staticmethod
    def finalize_rollover(rollover: CaRolloverModel) -> None:
        """Complete the rollover.

        :param rollover: The rollover to finalize.
        :raises CaRolloverError: If the rollover cannot be completed.
        """
        strategy = CaRolloverService.get_strategy(
            CaRolloverStrategyType(rollover.strategy_type),
        )

        try:
            rollover.complete()
        except ValueError as exc:
            raise CaRolloverError(str(exc)) from exc

        strategy.on_complete(rollover)
        logger.info('Rollover %s completed.', rollover.pk)

    @staticmethod
    def cancel_rollover(rollover: CaRolloverModel) -> None:
        """Cancel the rollover.

        :param rollover: The rollover to cancel.
        :raises CaRolloverError: If the rollover cannot be cancelled.
        """
        strategy = CaRolloverService.get_strategy(
            CaRolloverStrategyType(rollover.strategy_type),
        )

        try:
            rollover.cancel()
        except ValueError as exc:
            raise CaRolloverError(str(exc)) from exc

        strategy.on_cancel(rollover)
        logger.info('Rollover %s cancelled.', rollover.pk)

    @staticmethod
    def get_active_rollover(issuing_ca: CaModel) -> CaRolloverModel | None:
        """Return the active rollover for the given Issuing CA, if any.

        :param issuing_ca: The Issuing CA to check.
        :returns: The active CaRolloverModel or None.
        """
        return CaRolloverModel.objects.filter(
            old_issuing_ca=issuing_ca,
            state__in=[
                CaRolloverState.PLANNED,
                CaRolloverState.AWAITING_NEW_CA,
                CaRolloverState.IN_PROGRESS,
            ],
        ).first()

    @staticmethod
    def get_rollover_history(issuing_ca: CaModel) -> QuerySet[CaRolloverModel]:
        """Return completed/cancelled rollovers involving the given CA.

        :param issuing_ca: The Issuing CA to look up.
        :returns: QuerySet of CaRolloverModel instances.
        """
        return CaRolloverModel.objects.filter(
            Q(old_issuing_ca=issuing_ca) | Q(new_issuing_ca=issuing_ca),
            state__in=[CaRolloverState.COMPLETED, CaRolloverState.CANCELLED],
        ).order_by('-planned_at')

    @staticmethod
    def has_completed_rollover(issuing_ca: CaModel) -> bool:
        """Return True if the given Issuing CA already has a completed rollover.

        :param issuing_ca: The Issuing CA to check.
        :returns: True if a completed rollover exists for this CA as the old CA.
        """
        return CaRolloverModel.objects.filter(
            old_issuing_ca=issuing_ca,
            state=CaRolloverState.COMPLETED,
        ).exists()
