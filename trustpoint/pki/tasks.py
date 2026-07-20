"""Asynchronous tasks for PKI operations."""

from __future__ import annotations

import logging

from django.db import transaction

from pki.models import CaModel
from pki.models.ca_rollover import CaRolloverModel, CaRolloverState

logger = logging.getLogger(__name__)


def generate_crl_for_ca(ca_id: int) -> None:
    """Generate a CRL for a specific CA.

    This function is executed by Django-Q2 as a background task.
    It should not use Django 6.0's @task decorator as Django-Q2 handles
    task execution and scheduling.

    Raises:
        ValueError: If the CA does not exist.
    """
    try:
        ca = CaModel.objects.get(pk=ca_id)
    except CaModel.DoesNotExist as exc:
        msg = f'CA with ID {ca_id} does not exist'
        logger.exception('CA with ID %s does not exist', ca_id)
        raise ValueError(msg) from exc

    logger.info('Starting CRL generation for CA: %s', ca.unique_name)

    try:
        with transaction.atomic():
            success = ca.issue_crl(crl_validity_hours=int(ca.crl_validity_hours))
            if success:
                logger.info('CRL generated successfully for CA: %s', ca.unique_name)
            else:
                logger.warning('CRL generation failed for CA: %s', ca.unique_name)
    except Exception:
        logger.exception('Unexpected error during CRL generation for CA %s', ca.unique_name)
        raise


def check_rollover_transition(rollover_id: int) -> None:
    """Check if a CA rollover should transition from PREPARATION to TRANSITION phase.

    This function is executed by Django-Q2 as a background task.
    It checks if the rollover is in PREPARATION state and if the scheduled
    transition time has been reached. If so, it transitions to TRANSITION state.

    Raises:
        ValueError: If the rollover does not exist.
    """
    try:
        rollover = CaRolloverModel.objects.get(pk=rollover_id)
    except CaRolloverModel.DoesNotExist as exc:
        msg = f'CA Rollover with ID {rollover_id} does not exist'
        logger.exception('CA Rollover with ID %s does not exist', rollover_id)
        raise ValueError(msg) from exc

    logger.info('Checking transition status for rollover: %s', rollover.id)

    try:
        with transaction.atomic():
            # Refresh from database to get latest state
            rollover.refresh_from_db()

            if rollover.state != CaRolloverState.PREPARATION:
                logger.info(
                    'Rollover %s is no longer in PREPARATION state (current: %s), skipping transition check',
                    rollover.id,
                    rollover.get_state_display()
                )
                return

            if rollover.should_transition:
                logger.info(
                    'Transitioning rollover %s from PREPARATION to TRANSITION (scheduled time: %s)',
                    rollover.id,
                    rollover.transition_scheduled_at
                )
                rollover.transition_to_transition()
                logger.info('Successfully transitioned rollover %s to TRANSITION state', rollover.id)
            else:
                logger.debug(
                    'Rollover %s is not yet ready to transition (scheduled time: %s)',
                    rollover.id,
                    rollover.transition_scheduled_at
                )
    except Exception:
        logger.exception('Unexpected error during rollover transition check for rollover %s', rollover.id)
        raise


