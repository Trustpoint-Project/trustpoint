# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Helpers for actor-aware auditing of security-sensitive object changes."""

from __future__ import annotations

import datetime
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from copy import copy
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Final, cast

from django.contrib.auth.models import AnonymousUser
from django.db import models, transaction

from management.models.audit_log import AuditLog

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pki.models import CaModel, DomainModel, TruststoreModel

_REDACTED: Final[str] = '<redacted>'
_PROVIDER_AUDIT_ACTIVE: ContextVar[bool] = ContextVar('provider_audit_active', default=False)


@dataclass(frozen=True, slots=True)
class SecurityAuditSpec:
    """Describe the persisted fields that form a security-sensitive object state."""

    fields: tuple[str, ...]
    category: str
    operation_prefix: str
    redacted_fields: frozenset[str] = frozenset()


_PROVIDER_CATEGORY = 'crypto_provider_config'
_SECURITY_CATEGORY = 'security_object'

_SECURITY_AUDIT_SPECS: Final[dict[str, SecurityAuditSpec]] = {
    'appsecrets.AppSecretBackendModel': SecurityAuditSpec(
        operation_prefix='APPSECRET_BACKEND',
        fields=('backend_kind',),
        category=_PROVIDER_CATEGORY,
    ),
    'appsecrets.AppSecretSoftwareConfigModel': SecurityAuditSpec(
        fields=('backend',),
        category=_PROVIDER_CATEGORY,
        operation_prefix='APPSECRET_SOFTWARE',
    ),
    'appsecrets.AppSecretPkcs11ConfigModel': SecurityAuditSpec(
        operation_prefix='APPSECRET_PKCS11',
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
        operation_prefix='CRYPTO_PROVIDER',
        fields=('name', 'backend_kind', 'active'),
        category=_PROVIDER_CATEGORY,
    ),
    'crypto.CryptoProviderPkcs11ConfigModel': SecurityAuditSpec(
        operation_prefix='CRYPTO_PKCS11_CONFIG',
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
        operation_prefix='CRYPTO_SOFTWARE_CONFIG',
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
        operation_prefix='CRYPTO_REST_CONFIG',
        fields=('profile', 'base_url', 'auth_type', 'auth_ref', 'timeout_seconds', 'verify_tls'),
        category=_PROVIDER_CATEGORY,
        redacted_fields=frozenset({'auth_ref'}),
    ),
    'management.SecurityConfig': SecurityAuditSpec(
        operation_prefix='SECURITY_CONFIG',
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
        operation_prefix='CA',
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
        operation_prefix='TRUSTSTORE',
        fields=('unique_name', 'intended_usage'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.TruststoreOrderModel': SecurityAuditSpec(
        operation_prefix='TRUSTSTORE_ENTRY',
        fields=('order', 'certificate', 'trust_store'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.DomainModel': SecurityAuditSpec(
        operation_prefix='DOMAIN',
        fields=('unique_name', 'issuing_ca', 'organization', 'domain_credential_profile', 'is_active'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.DomainAllowedCertificateProfileModel': SecurityAuditSpec(
        operation_prefix='DOMAIN_PROFILE',
        fields=('domain', 'certificate_profile', 'alias'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.CertificateProfileModel': SecurityAuditSpec(
        operation_prefix='CERT_PROFILE',
        fields=('unique_name', 'display_name', 'credential_type', 'profile_json', 'is_default'),
        category=_SECURITY_CATEGORY,
    ),
    'pki.DevIdRegistration': SecurityAuditSpec(
        operation_prefix='DEVID_REGISTRATION',
        fields=('unique_name', 'truststore', 'domain', 'serial_number_pattern'),
        category=_SECURITY_CATEGORY,
    ),
}


def _json_safe(value: Any) -> object:  # noqa: PLR0911
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
    if not isinstance(field, models.Field):
        msg = f'Security audit field {field_name!r} must be a concrete model field.'
        raise TypeError(msg)
    if isinstance(field, models.ForeignKey):
        return _json_safe(getattr(instance, field.attname))
    return _json_safe(field.value_from_object(instance))


def snapshot_security_state(instance: models.Model) -> dict[str, object]:
    """Return the auditable persisted state of a registered security-sensitive object."""
    spec = _get_spec(instance)
    state = {field_name: _field_value(instance, field_name) for field_name in spec.fields}
    # Membership belongs to the parent event; do not audit each through-model save as well.
    if spec.operation_prefix == 'DOMAIN':
        state['certificate_profiles'] = list(
            cast('DomainModel', instance)
            .certificate_profiles.order_by('certificate_profile_id')
            .values('certificate_profile_id', 'alias')
        )
    elif spec.operation_prefix == 'CA':
        config = cast('CaModel', instance).no_onboarding_config
        state['remote_truststore'] = config.trust_store_id if config else None
    elif spec.operation_prefix == 'TRUSTSTORE':
        state['certificates'] = list(
            cast('TruststoreModel', instance)
            .truststoreordermodel_set.order_by('order', 'certificate_id')
            .values('order', 'certificate_id')
        )
    return state


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
    actor: models.Model | AnonymousUser | None,
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

    operation_name = f'{spec.operation_prefix}_{action.upper()}'
    if spec.operation_prefix == 'SECURITY_CONFIG' and action == 'updated':
        operation_name = 'SECURITY_CONFIG_CHANGED'
    operation_type = AuditLog.OperationType[operation_name]

    return AuditLog.create_entry(
        operation_type=operation_type,
        target=target,
        target_display=_target_display(target),
        actor=None if isinstance(actor, AnonymousUser) else actor,
        details={
            'action': action,
            'security_change_category': spec.category,
            'changed_fields': changed_fields,
        },
    )


@contextmanager
def security_change(
    *,
    target: models.Model,
    actor: models.Model | AnonymousUser | None,
    action: str = 'updated',
) -> Iterator[None]:
    """Audit one explicit operation atomically, after all its saves have finished.

    This scope owns the event: replace existing audit calls for the same operation.
    Read the initial state from the database because ModelForm validation mutates
    its instance. Retain a copy for deletions, which clear the instance primary key.
    Callers creating objects use ``audit_security_change`` inside their transaction.
    """
    if action not in {'updated', 'deleted'}:
        msg = 'Use audit_security_change with before=None for object creation.'
        raise ValueError(msg)
    with transaction.atomic():
        manager = type(target)._default_manager  # noqa: SLF001 - Django exposes the default manager through metadata.
        persisted = manager.select_for_update().get(pk=target.pk)
        before = snapshot_security_state(persisted)
        audit_target = copy(persisted) if action == 'deleted' else target
        yield
        if action == 'updated':
            audit_target.refresh_from_db()
        audit_security_change(target=audit_target, actor=actor, before=before, action=action)


@contextmanager
def provider_configuration_changes(*, actor: models.Model | AnonymousUser | None) -> Iterator[None]:
    """Own auditing for an explicit backend configuration operation.

    Backend setup can create, update and delete several configuration objects.
    Snapshot these small configuration tables once at the operation boundary so
    intermediate saves and key initialization do not produce duplicate events.
    Secret key material is excluded by the field allowlists.
    """
    from django.apps import apps  # noqa: PLC0415 - Resolve models after Django initialization.

    if _PROVIDER_AUDIT_ACTIVE.get():
        yield
        return
    token = _PROVIDER_AUDIT_ACTIVE.set(True)
    try:
        with transaction.atomic():
            initial: dict[tuple[str, object], tuple[models.Model, dict[str, object]]] = {}
            final: dict[tuple[str, object], models.Model] = {}
            provider_models = [
                apps.get_model(label)
                for label, spec in _SECURITY_AUDIT_SPECS.items()
                if spec.category == _PROVIDER_CATEGORY
            ]
            for model in provider_models:
                for target in model.objects.select_for_update().all():
                    initial[(_model_label(target), target.pk)] = (target, snapshot_security_state(target))
            yield
            for model in provider_models:
                for target in model.objects.all():
                    final[(_model_label(target), target.pk)] = target
            for key, target in final.items():
                previous = initial.get(key)
                audit_security_change(
                    target=target,
                    actor=actor,
                    before=previous[1] if previous else None,
                    action='updated' if previous else 'created',
                )
            for key, (target, before) in initial.items():
                if key not in final:
                    audit_security_change(target=target, actor=actor, before=before, action='deleted')
    finally:
        _PROVIDER_AUDIT_ACTIVE.reset(token)
