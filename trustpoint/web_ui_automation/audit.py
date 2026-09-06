# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Audit-log integration for Web UI automation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from management.models.audit_log import AuditLog

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser
    from django.db.models import Model


class WebUiAuditOperation:
    """String values added to AuditLog.OperationType by the integration patch."""

    PROFILE_CREATED = 'WEBUI_PROFILE_CREATED'
    PROFILE_UPDATED = 'WEBUI_PROFILE_UPDATED'
    PROFILE_DELETED = 'WEBUI_PROFILE_DELETED'
    DEVICE_CONFIGURED = 'WEBUI_DEVICE_CONFIGURED'
    DEVICE_DELETED = 'WEBUI_DEVICE_DELETED'
    CREDENTIALS_UPDATED = 'WEBUI_CREDENTIALS_UPDATED'
    ENDPOINT_UPDATED = 'WEBUI_ENDPOINT_UPDATED'
    ONBOARDING_STARTED = 'WEBUI_ONBOARDING_STARTED'
    ONBOARDING_CONFIRMED = 'WEBUI_ONBOARDING_CONFIRMED'
    ONBOARDING_FAILED = 'WEBUI_ONBOARDING_FAILED'
    RENEWAL_ENABLED = 'WEBUI_RENEWAL_ENABLED'
    RENEWAL_DISABLED = 'WEBUI_RENEWAL_DISABLED'
    RENEWAL_STARTED = 'WEBUI_RENEWAL_STARTED'
    RENEWAL_CONFIRMED = 'WEBUI_RENEWAL_CONFIRMED'
    RENEWAL_FAILED = 'WEBUI_RENEWAL_FAILED'


def write_audit_entry(
    operation: str,
    target: Model,
    *,
    actor: AbstractBaseUser | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Write a generic Trustpoint audit entry for an automation object."""
    return AuditLog.create_entry(
        operation_type=operation,
        target=target,
        target_display=str(target),
        actor=actor,
        details=details or {},
    )
