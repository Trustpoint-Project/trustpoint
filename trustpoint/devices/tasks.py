# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Asynchronous tasks for device operations."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from devices.domain_credential_renewal import renew_gds_push_domain_credential
from devices.models import DeviceModel, OpcUaGdsPushConfig
from management.models.audit_log import AuditLog
from onboarding.enums import OnboardingStatus
from request.gds_push import GdsPushError, GdsPushService

logger = logging.getLogger(__name__)

GDS_PUSH_LOCK_TIMEOUT_SECONDS = 900


def _acquire_device_lock(device_id: int) -> bool:
    """Reserve the per-device GDS Push operation lock."""
    return cache.add(f'gds_push_device_{device_id}', '1', timeout=GDS_PUSH_LOCK_TIMEOUT_SECONDS)


def _release_device_lock(device_id: int) -> None:
    """Release the per-device GDS Push operation lock."""
    cache.delete(f'gds_push_device_{device_id}')


def _record_gds_push_audit(
    device: DeviceModel,
    initiated_by_id: int | None,
    result: str,
    message: str,
) -> None:
    """Record a GDS Push operation with optional user attribution."""
    try:
        actor = get_user_model().objects.filter(pk=initiated_by_id).first() if initiated_by_id else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.GDS_PUSH_UPDATE,
            target=device,
            target_display=f'Device: {device.common_name}',
            actor=actor,
            details={'protocol': 'OPC UA GDS Push', 'result': result, 'message': message[:1000]},
        )
    except Exception:
        logger.exception('Failed to record GDS Push audit entry for device %s', device.pk)


def _run_combined_update(service: GdsPushService, attempts: int = 2) -> tuple[bool, str, bytes | None]:
    """Run the combined workflow, retrying once when another transaction is pending."""
    success = False
    message = ''
    certificate: bytes | None = None
    for attempt in range(attempts):
        success, message, certificate = asyncio.run(service.update_trustlist_and_certificate())
        if success or 'BadTransactionPending' not in message:
            break
        logger.warning('Transaction pending; retrying GDS Push update (%d/%d)', attempt + 1, attempts)
        time.sleep(2)
    return success, message, certificate


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

    if not _acquire_device_lock(device_id):
        logger.warning('GDS Push operation already running for device %s; skipping this cycle', device.common_name)
        return

    try:
        try:
            service = GdsPushService(device=device)
            try:
                if service.server_certificate_needs_renewal():
                    success, message, _certificate_bytes = _run_combined_update(service)
                else:
                    success, message = asyncio.run(service.update_trustlist())
                    message = f'certificate not due for renewal; {message}'
                if success:
                    logger.info('GDS Push update succeeded for device %s: %s', device.common_name, message)
                    _record_gds_push_audit(device, None, 'success', message)
                else:
                    logger.warning('GDS Push update failed for device %s: %s', device.common_name, message)
                    _record_gds_push_audit(device, None, 'failed', message)
            except GdsPushError:
                logger.exception('GDS Push error during combined update for device %s', device.common_name)
        except Exception:
            logger.exception('Unexpected error during GDS Push update for device %s', device.common_name)
            # Preserve queue retries without overwriting renewal settings saved during device I/O.
            OpcUaGdsPushConfig.objects.filter(
                pk=config.pk,
                opc_gds_push_last_update_scheduled_at=config.opc_gds_push_last_update_scheduled_at,
            ).update(opc_gds_push_last_update_scheduled_at=next_run)
            raise
    finally:
        _release_device_lock(device_id)


def update_gds_push_trustlist(device_id: int, initiated_by_id: int | None = None) -> None:
    """Push the current trustlist to one OPC UA GDS Push device from a background job."""
    device = DeviceModel.objects.filter(pk=device_id).first()
    if device is None:
        logger.info('Device %s was deleted; skipping trustlist update', device_id)
        return
    if not _acquire_device_lock(device_id):
        logger.warning(
            'GDS Push operation already running for device %s; skipping trustlist update', device.common_name
        )
        return
    try:
        try:
            success, message = asyncio.run(GdsPushService(device=device).update_trustlist())
        except Exception as e:
            logger.exception('Trustlist update failed for device %s', device.common_name)
            _record_gds_push_audit(device, initiated_by_id, 'error', str(e))
            return
        if success:
            logger.info('Trustlist updated for device %s: %s', device.common_name, message)
            _record_gds_push_audit(device, initiated_by_id, 'success', message)
        else:
            logger.warning('Trustlist update rejected for device %s: %s', device.common_name, message)
            _record_gds_push_audit(device, initiated_by_id, 'failed', message)
    finally:
        _release_device_lock(device_id)


def update_gds_push_server_certificate(device_id: int, initiated_by_id: int | None = None) -> None:
    """Push a server certificate to one OPC UA GDS Push device from a background job."""
    device = DeviceModel.objects.filter(pk=device_id).first()
    if device is None:
        logger.info('Device %s was deleted; skipping server certificate update', device_id)
        return
    if not _acquire_device_lock(device_id):
        logger.warning(
            'GDS Push operation already running for device %s; skipping server certificate update', device.common_name
        )
        return

    try:
        service = GdsPushService(device=device)
        try:
            success, message, certificate_bytes = _run_combined_update(service)
        except Exception as e:
            logger.exception('Combined GDS Push update failed for device %s', device.common_name)
            _record_gds_push_audit(device, initiated_by_id, 'error', str(e))
            return
        if not success or not certificate_bytes:
            logger.warning('GDS Push update rejected for device %s: %s', device.common_name, message)
            _record_gds_push_audit(device, initiated_by_id, 'failed', message)
            return
        logger.info('GDS Push update succeeded for device %s: %s', device.common_name, message)
        _record_gds_push_audit(device, initiated_by_id, 'success', message)
        if device.onboarding_config is not None:
            device.onboarding_config.onboarding_status = OnboardingStatus.ONBOARDED
            device.onboarding_config.save(update_fields=['onboarding_status'])
    finally:
        _release_device_lock(device_id)


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

    if not _acquire_device_lock(device_id):
        logger.warning('GDS Push operation already running for device %s; skipping credential renewal', device_id)
        return

    try:
        try:
            with transaction.atomic():
                replacement = renew_gds_push_domain_credential(device)
            logger.info('Renewed GDS Push domain credential for device %s: %s', device_id, replacement.pk)
        except Exception:
            logger.exception('Domain credential renewal failed for device %s; retaining previous identity', device_id)
        config.schedule_next_gds_push_domain_credential_renewal()
    finally:
        _release_device_lock(device_id)
