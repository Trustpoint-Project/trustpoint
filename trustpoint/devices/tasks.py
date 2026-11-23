# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Asynchronous tasks for device operations."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from devices.domain_credential_renewal import renew_gds_push_domain_credential
from devices.models import DeviceModel, OpcUaGdsPushConfig
from onboarding.enums import OnboardingStatus
from request.gds_push import GdsPushError, GdsPushService

logger = logging.getLogger(__name__)


def perform_gds_push_update(device_id: int) -> None:
    """Perform a periodic GDS Push server certificate and trustlist update for a device.

    This function is executed by Django-Q2 as a background task.
    It reserves the next execution before updating the server certificate and trustlist,
    so concurrent queued tasks cannot start another renewal cycle.

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

    with transaction.atomic():
        config = OpcUaGdsPushConfig.objects.select_for_update().filter(device=device).first()
        if (
            device.device_type != DeviceModel.DeviceType.OPC_UA_GDS_PUSH
            or config is None
            or not config.opc_gds_push_enable_periodic_update
        ):
            logger.info('Periodic GDS Push update disabled for device %s, skipping execution', device.common_name)
            return
        next_run = config.opc_gds_push_last_update_scheduled_at
        if next_run is not None and next_run > timezone.now():
            return
        # Reserve the next cycle before external I/O so stale or duplicate jobs cannot run it again.
        config.schedule_next_gds_push_update()

    try:
        service = GdsPushService(device=device)

        # Update trustlist
        try:
            success, message = asyncio.run(service.update_trustlist())
            if success:
                logger.info('Trustlist updated successfully for device %s: %s', device.common_name, message)
            else:
                logger.warning('Trustlist update failed for device %s: %s', device.common_name, message)
        except GdsPushError:
            logger.exception('GDS Push error during trustlist update for device %s', device.common_name)

        # Update server certificate
        try:
            success, message, _certificate_bytes = asyncio.run(service.update_server_certificate())
            if success:
                logger.info('Server certificate updated successfully for device %s: %s', device.common_name, message)
            else:
                logger.warning('Server certificate update failed for device %s: %s', device.common_name, message)
        except GdsPushError:
            logger.exception('GDS Push error during server certificate update for device %s', device.common_name)
    except Exception:
        logger.exception('Unexpected error during GDS Push update for device %s', device.common_name)
        # Preserve queue retries without overwriting renewal settings saved during device I/O.
        OpcUaGdsPushConfig.objects.filter(
            pk=config.pk,
            opc_gds_push_last_update_scheduled_at=config.opc_gds_push_last_update_scheduled_at,
        ).update(opc_gds_push_last_update_scheduled_at=next_run)
        raise


def update_gds_push_trustlist(device_id: int) -> None:
    """Push the current trustlist to one OPC UA GDS Push device from a background job."""
    device = DeviceModel.objects.filter(pk=device_id).first()
    if device is None:
        logger.info('Device %s was deleted; skipping trustlist update', device_id)
        return
    try:
        success, message = asyncio.run(GdsPushService(device=device).update_trustlist())
    except Exception:
        logger.exception('Trustlist update failed for device %s', device.common_name)
        return
    if success:
        logger.info('Trustlist updated for device %s: %s', device.common_name, message)
    else:
        logger.warning('Trustlist update rejected for device %s: %s', device.common_name, message)


def update_gds_push_server_certificate(device_id: int) -> None:
    """Push a server certificate to one OPC UA GDS Push device from a background job."""
    device = DeviceModel.objects.filter(pk=device_id).first()
    if device is None:
        logger.info('Device %s was deleted; skipping server certificate update', device_id)
        return
    try:
        success, message, certificate_bytes = asyncio.run(GdsPushService(device=device).update_server_certificate())
    except Exception:
        logger.exception('Server certificate update failed for device %s', device.common_name)
        return
    if not success or not certificate_bytes:
        logger.warning('Server certificate update rejected for device %s: %s', device.common_name, message)
        return
    logger.info('Server certificate updated for device %s: %s', device.common_name, message)
    if device.onboarding_config is not None:
        device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
        device.onboarding_config.save(update_fields=['onboarding_status'])


def perform_gds_push_domain_credential_renewal(device_id: int) -> None:
    """Renew the local GDS identity and schedule its next independent renewal cycle."""
    with transaction.atomic():
        device = DeviceModel.objects.select_for_update().filter(pk=device_id).first()
        if device is None:
            logger.info('Device %s was deleted; skipping domain credential renewal', device_id)
            return
        if (
            device.device_type != DeviceModel.DeviceType.OPC_UA_GDS_PUSH
            or not hasattr(device, 'opc_ua_gds_push_config')
            or not device.opc_ua_gds_push_config.opc_gds_push_enable_domain_credential_renewal
        ):
            return
        config = device.opc_ua_gds_push_config
        next_run = config.opc_gds_push_domain_credential_next_renewal_at
        if next_run is not None and next_run > timezone.now():
            # A queued task may belong to settings that have since been replaced.
            return
        # Reserve this cycle before releasing the row lock so two workers cannot renew twice.
        config.opc_gds_push_domain_credential_next_renewal_at = timezone.now() + timedelta(
            hours=config.opc_gds_push_domain_credential_renewal_interval
        )
        config.save(update_fields=['opc_gds_push_domain_credential_next_renewal_at'])

    try:
        with transaction.atomic():
            replacement = renew_gds_push_domain_credential(device)
        logger.info('Renewed GDS Push domain credential for device %s: %s', device_id, replacement.pk)
    except Exception:
        logger.exception('Domain credential renewal failed for device %s; retaining previous identity', device_id)
    config.schedule_next_gds_push_domain_credential_renewal()
