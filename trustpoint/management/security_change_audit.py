# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Helpers for actor-aware auditing of security-sensitive object changes."""

from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final

from django.db import models

from management.models.audit_log import AuditLog

_REDACTED: Final[str] = '<redacted>'


@dataclass(frozen=True, slots=True)
class SecurityAuditSpec:
    """Describe the persisted fields that form a security-sensitive object state."""

    fields: tuple[str, ...]
    category: str
    redacted_fields: frozenset[str] = frozenset()


_PROVIDER_CATEGORY = 'crypto_provider_config'
_SECURITY_CATEGORY = 'security_object'

_SECURITY_AUDIT_SPECS: Final[dict[str, SecurityAuditSpec]] = {
    'appsecrets.AppSecretBackendModel': SecurityAuditSpec(
        fields=('backend_kind',),
        category=_PROVIDER_CATEGORY,
    ),
    'appsecrets.AppSecretPkcs11ConfigModel': SecurityAuditSpec(
        fields=(
            'backend',
            'module_path',
            'token_label',
            'token_serial',
            'slot_id',
            'auth_source',
            'auth_source_ref',
            'kek_label',
        ),
        category=_PROVIDER_CATEGORY,
        redacted_fields=frozenset({'auth_source_ref'}),
    ),
    'crypto.CryptoProviderProfileModel': SecurityAuditSpec(
        fields=('name', 'backend_kind', 'active'),
        category=_PROVIDER_CATEGORY,
    ),
    'crypto.CryptoProviderPkcs11ConfigModel': SecurityAuditSpec(
        fields=(
            'profile',
            'module_path',
            'provider_config_env_var',
            'provider_config_path',
            'token_label',
            'token_serial',
            'slot_id',
            'auth_source',
            'auth_source_ref',
            'max_sessions',
            'borrow_timeout_seconds',
            'rw_sessions',
        ),
        category=_PROVIDER_CATEGORY,
        redacted_fields=frozenset({'auth_source_ref'}),
    ),
    'crypto.CryptoProviderSoftwareConfigModel': SecurityAuditSpec(
        fields=(
            'profile',
            'encryption_source',
            'encryption_source_ref',
            'allow_exportable_private_keys',
        ),
        category=_PROVIDER_CATEGORY,
        redacted_fields=frozenset({'encryption_source_ref'}),
    ),
    'crypto.CryptoProviderRestConfigModel': SecurityAuditSpec(
        fields=('profile', 'base_url', 'auth_type', 'auth_ref', 'timeout_seconds', 'verify_tls'),
        category=_PROVIDER_CATEGORY,
        redacted_fields=frozenset({'auth_ref'}),
    ),
    'management.SecurityConfig': SecurityAuditSpec(
        fields=(
            'security_mode',
            'auto_gen_pki',
            'auto_gen_pki_key_algorithm',
            'rsa_minimum_key_size',
            'not_permitted_ecc_curve_oids',
            'not_permitted_mldsa_variant_oids',
            'not_permitted_signature_algorithm_oids',
            'max_cert_validity_days',
            'max_crl_validity_days',
            'credential_ttl_seconds',
            'allow_ca_issuance',
            'allow_auto_gen_pki',
            'allow_self_signed_ca',
            'allow_imported_private_keys',
            'permitted_no_onboarding_pki_protocols',
            'permitted_onboarding_protocols',
        ),
        category=_SECURITY_CATEGORY,
    ),
    'pki.CaModel': SecurityAuditSpec(
        fields=(
            'unique_name',
            'parent_ca',
            'is_active',
            'ca_type',
            'certificate',
            'credential',
            'chain_truststore',
            'remote_host',
            'remote_port',
            'remote_path',
            'est_username',
            'cmp_sender_kid',
            'onboarding_config',
            'no_onboarding_config',
            'crl_cycle_enabled',
            'crl_cycle_interval_hours',
            'crl_validity_hours',
            'auto_crl_on_revocation_enabled',
        ),
        category=_SECURITY_CATEGORY,
    ),
    'pki.TruststoreModel': SecurityAuditSpec(
        fields=('unique_name', 'intended_usage'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.TruststoreOrderModel': SecurityAuditSpec(
        fields=('order', 'certificate', 'trust_store'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.DomainModel': SecurityAuditSpec(
        fields=('unique_name', 'issuing_ca', 'organization', 'domain_credential_profile', 'is_active'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.DomainAllowedCertificateProfileModel': SecurityAuditSpec(
        fields=('domain', 'certificate_profile', 'alias'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.CertificateProfileModel': SecurityAuditSpec(
        fields=('unique_name', 'display_name', 'credential_type', 'profile_json', 'is_default'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.DevIdRegistration': SecurityAuditSpec(
        fields=('unique_name', 'truststore', 'domain', 'serial_number_pattern'),
        category=_SECURITY_CATEGORY,
    ),
}


def _json_safe(value: Any) -> object:
    """Convert persisted model values into deterministic JSON-safe audit values."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (datetime.date, datetime.datetime, datetime.time)):
        return value.isoformat()
    if isinstance(value, (uuid.UUID, Decimal)):
        return str(value)
    if isinstance(value, bytes):
        return {'type': 'bytes', 'length': len(value)}
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return str(value)


def _model_label(instance: models.Model) -> str:
    """Return the canonical Django model label for the instance."""
    return instance._meta.label  # noqa: SLF001 - Django model metadata is a supported public API.


def _get_spec(instance: models.Model) -> SecurityAuditSpec:
    """Return the registered audit specification for a security-sensitive model."""
    label = _model_label(instance)
    try:
        return _SECURITY_AUDIT_SPECS[label]
    except KeyError as exc:
        msg = f'No security audit specification is registered for {label!r}.'
        raise ValueError(msg) from exc


def _field_value(instance: models.Model, field_name: str) -> object:
    """Read a concrete field value without dereferencing related objects."""
    field = instance._meta.get_field(field_name)  # noqa: SLF001 - Django model metadata is a supported public API.
    if isinstance(field, models.ForeignKey):
        return _json_safe(getattr(instance, field.attname))
    return _json_safe(field.value_from_object(instance))


def snapshot_security_state(instance: models.Model) -> dict[str, object]:
    """Return the auditable persisted state of a registered security-sensitive object."""
    spec = _get_spec(instance)
    return {field_name: _field_value(instance, field_name) for field_name in spec.fields}


def _audit_value(field_name: str, value: object | None, spec: SecurityAuditSpec) -> object | None:
    """Return an audit-safe changed value, redacting sensitive configuration fields."""
    if field_name in spec.redacted_fields and value not in (None, ''):
        return _REDACTED
    return value


def _build_changes(
    before: dict[str, object] | None,
    after: dict[str, object] | None,
    spec: SecurityAuditSpec,
) -> dict[str, dict[str, object | None]]:
    """Return only changed fields while redacting sensitive values after comparison."""
    field_names = set(before or {}) | set(after or {})
    changes: dict[str, dict[str, object | None]] = {}
    for field_name in sorted(field_names):
        before_value = before.get(field_name) if before is not None else None
        after_value = after.get(field_name) if after is not None else None
        if before_value == after_value:
            continue
        changes[field_name] = {
            'before': _audit_value(field_name, before_value, spec),
            'after': _audit_value(field_name, after_value, spec),
        }
    return changes


def _target_display(instance: models.Model) -> str:
    """Return a stable human-readable audit target label."""
    try:
        instance_display = str(instance)
    except (AttributeError, RuntimeError, TypeError, ValueError):
        instance_display = str(instance.pk)
    return f'{_model_label(instance)}: {instance_display}'


def audit_security_change(
    *,
    target: models.Model,
    actor: models.Model | None,
    before: dict[str, object] | None,
    action: str = 'updated',
) -> AuditLog | None:
    """Write an actor-aware before/after entry to the existing :class:`AuditLog` model.

    Args:
        target: Security-sensitive model instance after the operation.
        actor: User that triggered the operation, or ``None`` for system/bootstrap operations.
        before: Snapshot captured with :func:`snapshot_security_state` before the mutation.
            Pass ``None`` when auditing object creation.
        action: One of ``created``, ``updated`` or ``deleted``.

    Returns:
        The newly created AuditLog entry, or ``None`` when no persisted state changed.
    """
    if action not in {'created', 'updated', 'deleted'}:
        msg = f'Unsupported security audit action {action!r}.'
        raise ValueError(msg)

    spec = _get_spec(target)
    after = None if action == 'deleted' else snapshot_security_state(target)
    before_state = snapshot_security_state(target) if action == 'deleted' and before is None else before
    changed_fields = _build_changes(before_state, after, spec)
    if not changed_fields:
        return None

    operation_by_action = {
        'created': AuditLog.OperationType.MODEL_CREATED,
        'updated': AuditLog.OperationType.MODEL_UPDATED,
        'deleted': AuditLog.OperationType.MODEL_DELETED,
    }
    operation_type = (
        AuditLog.OperationType.SECURITY_CONFIG_CHANGED
        if _model_label(target) == 'management.SecurityConfig'
        else operation_by_action[action]
    )

    return AuditLog.create_entry(
        operation_type=operation_type,
        target=target,
        target_display=_target_display(target),
        actor=actor,
        details={
            'action': action,
            'security_change_category': spec.category,
            'changed_fields': changed_fields,
        },
    )
