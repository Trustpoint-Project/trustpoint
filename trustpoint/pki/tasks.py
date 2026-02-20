"""Asynchronous tasks for PKI operations."""

from __future__ import annotations

import logging

from django.db import transaction

from pki.models import CaModel

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


