"""Asynchronous tasks for device operations."""

from __future__ import annotations

import asyncio
import logging

from django.db import transaction

from devices.models import DeviceModel
from request.gds_push import GdsPushError, GdsPushService

logger = logging.getLogger(__name__)


def perform_gds_push_update(device_id: int) -> None:
    """Perform a periodic GDS Push server certificate and trustlist update for a device.

    This function is executed by Django-Q2 as a background task.
    It updates both the server certificate and the trustlist on the OPC UA GDS Push device,
    then schedules the next execution according to the configured renewal interval.

    Args:
        device_id: Primary key of the DeviceModel to update.

    Raises:
        ValueError: If the device does not exist.
    """
    try:
        device = DeviceModel.objects.get(pk=device_id)
    except DeviceModel.DoesNotExist as exc:
        msg = f'Device with ID {device_id} does not exist'
        logger.exception('Device with ID %s does not exist', device_id)
        raise ValueError(msg) from exc

    logger.info('Starting periodic GDS Push update for device: %s', device.common_name)

    if not device.opc_gds_push_enable_periodic_update:
        logger.info(
            'Periodic GDS Push update disabled for device %s, skipping execution', device.common_name
        )
        return

    service = GdsPushService(device=device)

    # Update trustlist
    try:
        with transaction.atomic():
            success, message = asyncio.run(service.update_trustlist())
            if success:
                logger.info(
                    'Trustlist updated successfully for device %s: %s', device.common_name, message
                )
            else:
                logger.warning(
                    'Trustlist update failed for device %s: %s', device.common_name, message
                )
    except GdsPushError:
        logger.exception('GDS Push error during trustlist update for device %s', device.common_name)
    except Exception:
        logger.exception(
            'Unexpected error during trustlist update for device %s', device.common_name
        )
        raise

    # Update server certificate
    try:
        with transaction.atomic():
            success, message, _certificate_bytes = asyncio.run(service.update_server_certificate())
            if success:
                logger.info(
                    'Server certificate updated successfully for device %s: %s', device.common_name, message
                )
            else:
                logger.warning(
                    'Server certificate update failed for device %s: %s', device.common_name, message
                )
    except GdsPushError:
        logger.exception('GDS Push error during server certificate update for device %s', device.common_name)
    except Exception:
        logger.exception(
            'Unexpected error during server certificate update for device %s', device.common_name
        )
        raise

    # Schedule the next run
    device.refresh_from_db(fields=['opc_gds_push_enable_periodic_update', 'opc_gds_push_renewal_interval'])
    device.schedule_next_gds_push_update()
