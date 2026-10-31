# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Device enrollment credential policy, assignment, and issuance coordination."""

# ruff: noqa: SLF001
# Django model metadata identifies configurations without secret material.

from __future__ import annotations

import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta
from typing import TYPE_CHECKING, Any, TypeIs

from django.apps import apps
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol, OnboardingStatus
from request.request_context import BaseCertificateRequestContext

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cmp.models import CmpTransactionModel
    from devices.models import DeviceModel
    from management.models import SecurityConfig
    from management.models.audit_log import AuditLog
    from onboarding.models import (
        DeviceSecretAssignmentLock,
        DeviceSecretUse,
        NoOnboardingConfigModel,
        OnboardingConfigModel,
    )
    from request.request_context import BaseRequestContext

type Config = OnboardingConfigModel | NoOnboardingConfigModel
VERSIONS = {
    'cmp_shared_secret': 'cmp_secret_version',
    'est_password': 'est_password_version',
    'scep_challenge': 'scep_secret_version',
}
MAX_SECRET_LENGTH = 128
ASCII_PRINTABLE_MIN = 32
ASCII_PRINTABLE_MAX = 126
_ACTIVE_USES: ContextVar[frozenset[tuple[str, int, str, int | None]]] = ContextVar(
    'device_secret_uses',
    default=frozenset(),
)
CUSTOM_WARNING = 'User-selected secrets may be weak or reused and reduce enrollment security.'


def _security_config_model() -> type[SecurityConfig]:
    """Resolve SecurityConfig after Django has loaded its models."""
    return apps.get_model('management.SecurityConfig')


def _audit_log_model() -> type[AuditLog]:
    """Resolve AuditLog after Django has loaded its models."""
    return apps.get_model('management.AuditLog')


def _onboarding_config_model() -> type[OnboardingConfigModel]:
    """Resolve OnboardingConfigModel after Django has loaded its models."""
    return apps.get_model('onboarding.OnboardingConfigModel')


def _no_onboarding_config_model() -> type[NoOnboardingConfigModel]:
    """Resolve NoOnboardingConfigModel after Django has loaded its models."""
    return apps.get_model('onboarding.NoOnboardingConfigModel')


def _assignment_lock_model() -> type[DeviceSecretAssignmentLock]:
    """Resolve DeviceSecretAssignmentLock after Django has loaded its models."""
    return apps.get_model('onboarding.DeviceSecretAssignmentLock')


def _secret_use_model() -> type[DeviceSecretUse]:
    """Resolve DeviceSecretUse after Django has loaded its models."""
    return apps.get_model('onboarding.DeviceSecretUse')


def _cmp_transaction_model() -> type[CmpTransactionModel]:
    """Resolve CmpTransactionModel after Django has loaded its models."""
    return apps.get_model('cmp.CmpTransactionModel')


def _is_onboarding_config(config: Config | None) -> TypeIs[OnboardingConfigModel]:
    """Narrow configuration types without importing models during app initialization."""
    return isinstance(config, _onboarding_config_model())


def validate_custom_secret(value: object) -> str:
    """Validate exact printable ASCII, including edge spaces, without echoing the value."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_SECRET_LENGTH
        or any(not ASCII_PRINTABLE_MIN <= ord(c) <= ASCII_PRINTABLE_MAX for c in value)
    ):
        msg = 'Enter 1-128 printable ASCII characters. Spaces are preserved; controls are forbidden.'
        raise ValidationError(msg)
    return value


def custom_secrets_allowed() -> bool:
    """Fail closed if the effective policy cannot be resolved."""
    try:
        policy = _security_config_model().objects.get()
        policy.clean()
    except (
        _security_config_model().DoesNotExist,
        _security_config_model().MultipleObjectsReturned,
        ValueError,
        ValidationError,
    ):
        return False
    return policy.allow_user_defined_device_secrets and policy.credential_ttl_seconds is None


def assignment_lock() -> None:
    """Acquire a shared database writer lock (also serializes SQLite writers)."""
    if not _assignment_lock_model().objects.filter(pk=1).update(id=1):
        _assignment_lock_model().objects.get_or_create(pk=1)
        _assignment_lock_model().objects.filter(pk=1).update(id=1)


def ensure_eligible(config: Config, field: str) -> None:  # noqa: C901 - Protocol and lifecycle eligibility are checked together.
    """Reject closed lifecycle states, unsupported protocols and outstanding CMP work."""
    if field not in VERSIONS:
        msg = 'Unknown device credential.'
        raise ValidationError(msg)
    if _is_onboarding_config(config):
        if config.onboarding_status == OnboardingStatus.ONBOARDED:
            msg = 'Completed onboarding credentials cannot be changed.'
            raise ValidationError(msg)
        onboarding_protocols = {
            'cmp_shared_secret': (OnboardingProtocol.CMP_SHARED_SECRET,),
            'est_password': (
                OnboardingProtocol.EST_USERNAME_PASSWORD,
                OnboardingProtocol.REST_USERNAME_PASSWORD,
                OnboardingProtocol.AGENT,
            ),
            'scep_challenge': (),
        }
        if config.onboarding_protocol not in onboarding_protocols[field]:
            msg = 'This credential is not supported for the selected onboarding protocol.'
            raise ValidationError(msg)
    else:
        no_onboarding_protocols = {
            'cmp_shared_secret': (NoOnboardingPkiProtocol.CMP_SHARED_SECRET,),
            'est_password': (
                NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
                NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD,
            ),
            'scep_challenge': (NoOnboardingPkiProtocol.SCEP,),
        }
        if not any(config.has_pki_protocol(protocol) for protocol in no_onboarding_protocols[field]):
            msg = 'This credential is not enabled for this device.'
            raise ValidationError(msg)
    if field == 'scep_challenge' and config.scep_challenge_consumed_at is not None:
        msg = 'Consumed SCEP enrollment authorization cannot be replaced.'
        raise ValidationError(msg)
    uses = _secret_use_model().objects.filter(config_label=config._meta.label, config_pk=config.pk)
    if not _is_onboarding_config(config):
        uses = uses.filter(credential=field)
    if config.pk and uses.exists():
        msg = 'An enrollment operation is using this credential. Retry after it completes.'
        raise ValidationError(msg)
    if config.pk and field == 'cmp_shared_secret':
        device_filter = 'onboarding_config_id' if _is_onboarding_config(config) else 'no_onboarding_config_id'
        outstanding = (
            _cmp_transaction_model()
            .objects.filter(**{f'device__{device_filter}': config.pk})
            .filter(
                Q(status__in=['processing', 'waiting'])
                | Q(status='issued', implicit_confirm=False, confirmed_at__isnull=True)
            )
        )
        if outstanding.exists():
            msg = 'Complete or cancel the outstanding CMP transaction before changing its secret.'
            raise ValidationError(msg)


def _check_scep_unique(config: Config) -> None:
    digest = config.scep_challenge_digest
    if not digest:
        return
    for model in (_onboarding_config_model(), _no_onboarding_config_model()):
        matches = model.objects.filter(scep_challenge_digest=digest)
        if isinstance(config, model) and config.pk:
            matches = matches.exclude(pk=config.pk)
        if matches.exists():
            msg = 'This SCEP challenge is already assigned. Choose a different value.'
            raise ValidationError(msg)


@contextmanager
def guard_configuration_save(config: Config, kwargs: dict[str, Any]) -> Iterator[None]:  # noqa: C901 - Lifecycle and version checks must share this lock.
    """Protect lifecycle state and bump versions even for existing internal generation paths."""
    fields = kwargs.get('update_fields')
    with transaction.atomic():
        if fields is None or 'scep_challenge' in fields or 'scep_challenge_digest' in fields:
            assignment_lock()
        old = type(config).objects.select_for_update().filter(pk=config.pk).first() if config.pk else None
        if (
            _is_onboarding_config(old)
            and old.onboarding_status == OnboardingStatus.ONBOARDED
            and (fields is None or 'onboarding_status' in fields)
            and getattr(config, 'onboarding_status', None) != OnboardingStatus.ONBOARDED
        ):
            msg = 'Completed onboarding cannot be reopened.'
            raise ValidationError(msg)
        for field, version in VERSIONS.items():
            if fields is not None and field not in fields:
                continue
            if old is not None and (
                getattr(old, field) != getattr(config, field)
                or field in getattr(config, 'secret_assignment_actions', {})
            ):
                if getattr(config, version) != getattr(old, version):
                    msg = 'The device credential changed. Reload the device and retry.'
                    raise ValidationError(msg)
                # Clearing bootstrap secrets at completion is retirement, not replacement.
                retiring = (
                    _is_onboarding_config(config)
                    and config.onboarding_status == OnboardingStatus.ONBOARDED
                    and field != 'scep_challenge'
                    and not getattr(config, field)
                )
                if not retiring:
                    if _is_onboarding_config(old) and old.onboarding_status == OnboardingStatus.ONBOARDED:
                        msg = 'Completed onboarding credentials cannot be changed.'
                        raise ValidationError(msg)
                    ensure_eligible(old if field != 'scep_challenge' and not getattr(config, field) else config, field)
                setattr(config, version, getattr(old, version) + 1)
                if fields is not None:
                    kwargs['update_fields'] = [*kwargs['update_fields'], version]
        if (
            old is not None
            and old.scep_challenge_consumed_at is not None
            and (fields is None or 'scep_challenge_consumed_at' in fields)
            and config.scep_challenge_consumed_at != old.scep_challenge_consumed_at
        ):
            msg = 'Consumed SCEP enrollment authorization cannot be reopened.'
            raise ValidationError(msg)
        if (fields is None or 'scep_challenge_digest' in fields) and (
            old is None or old.scep_challenge_digest != config.scep_challenge_digest
        ):
            _check_scep_unique(config)
        if old is not None and fields is None:
            # Ordinary configuration saves must not overwrite newer retry evidence.
            config.scep_transactions = old.scep_transactions
        yield


def prepare_secret(config: Config, field: str, *, custom: bool = False, value: object = None) -> str:  # noqa: C901, PLR0912, PLR0915 - Atomic assignment policy.
    """Assign an unsaved configuration inside its caller's creation transaction."""
    assignment_lock()
    ensure_eligible(config, field)
    policy = _security_config_model().objects.select_for_update().first()
    if custom:
        if _is_onboarding_config(config) and config.onboarding_protocol == OnboardingProtocol.AGENT:
            msg = 'Custom agent credentials are outside this feature.'
            raise ValidationError(msg)
        if policy is None or _security_config_model().objects.count() != 1:
            msg = 'Device secret policy is unavailable.'
            raise ValidationError(msg)
        policy.clean()
        if not policy.allow_user_defined_device_secrets or policy.credential_ttl_seconds is not None:
            msg = 'Custom device secrets are disabled. Use automatic generation.'
            raise ValidationError(msg)
        permitted = (
            config.onboarding_protocol in policy.permitted_onboarding_protocols
            if _is_onboarding_config(config)
            else all(
                protocol.value in policy.permitted_no_onboarding_pki_protocols
                for protocol in config.get_pki_protocols()
            )
        )
        if not permitted:
            msg = 'The selected protocol is not permitted by the security policy.'
            raise ValidationError(msg)
        secret = validate_custom_secret(value)
    else:
        secret = secrets.token_urlsafe(32)
    if field == 'scep_challenge':
        assignment_lock()
        # Existing duplicates must be resolved before custom SCEP assignment.
        if custom:
            digests: set[str] = set()
            for model in (_onboarding_config_model(), _no_onboarding_config_model()):
                rows = model.objects.exclude(scep_challenge_digest='').values('scep_challenge_digest')
                if rows.annotate(count=Count('pk')).filter(count__gt=1).exists():
                    msg = 'Duplicate SCEP records require administrator resolution.'
                    raise ValidationError(msg)
                values = set(rows.values_list('scep_challenge_digest', flat=True))
                if digests & values:
                    msg = 'Duplicate SCEP records require administrator resolution.'
                    raise ValidationError(msg)
                digests |= values
        while True:
            config.scep_challenge = secret
            config.scep_challenge_digest = config.scep_digest_for(secret)
            try:
                _check_scep_unique(config)
                break
            except ValidationError:
                if custom:
                    raise
                secret = secrets.token_urlsafe(32)
        ttl = policy.credential_ttl_seconds if policy is not None else None
        config.scep_challenge_expires_at = timezone.now() + timedelta(seconds=ttl) if ttl is not None else None
    else:
        setattr(config, field, secret)
        if _is_onboarding_config(config):
            ttl = policy.credential_ttl_seconds if policy is not None else None
            config.credential_expires_at = timezone.now() + timedelta(seconds=ttl) if ttl is not None else None
    actions = getattr(config, 'secret_assignment_actions', {})
    actions[field] = 'custom' if custom else 'generate'
    config.secret_assignment_actions = actions
    return secret


def audit_assignments(config: Config, *, actor: Any = None, device: DeviceModel | None = None) -> None:
    """Record assignments without submitted or stored secret material."""
    for field, action in getattr(config, 'secret_assignment_actions', {}).items():
        _audit_log_model().create_entry(
            operation_type=_audit_log_model().OperationType.DEVICE_SECRET_CHANGED,
            target=device or config,
            target_display=f'Device enrollment credential: {field}',
            actor=actor,
            details={'credential': field, 'action': action, 'outcome': 'success'},
        )
    config.secret_assignment_actions = {}


@transaction.atomic
def _assign_secret(  # noqa: PLR0913 - Shared assignment boundary includes optional audit context.
    config: Config,
    field: str,
    *,
    custom: bool = False,
    value: object = None,
    device: DeviceModel | None = None,
    actor: Any = None,
) -> str:
    """Replace one credential atomically; retain consumed material and transaction evidence."""
    assignment_lock()
    fresh = type(config).objects.select_for_update().get(pk=config.pk) if config.pk else config
    result = prepare_secret(fresh, field, custom=custom, value=value)
    fresh.save()
    config.refresh_from_db()
    audit_assignments(fresh, device=device, actor=actor)
    config.secret_assignment_actions = {}
    return result


def assign_secret(  # noqa: PLR0913 - Operator and device identify the audited action.
    config: Config,
    field: str,
    *,
    custom: bool = False,
    value: object = None,
    device: DeviceModel | None = None,
    actor: Any = None,
) -> str:
    """Audit rejected replacements after rolling back their attempted changes."""
    if config.pk and field == 'cmp_shared_secret':
        from cmp.confirmation import expire_confirmation  # noqa: PLC0415 - Avoid model initialization cycles.

        device_filter = 'onboarding_config_id' if _is_onboarding_config(config) else 'no_onboarding_config_id'
        overdue = _cmp_transaction_model().objects.filter(
            **{f'device__{device_filter}': config.pk},
            status='issued', implicit_confirm=False, confirmed_at__isnull=True,
            confirmation_deadline__lte=timezone.now(),
        ).values_list('pk', flat=True)
        for transaction_pk in overdue:
            expire_confirmation(transaction_pk)
        config.refresh_from_db()
    try:
        return _assign_secret(config, field, custom=custom, value=value, device=device, actor=actor)
    except ValidationError:
        if config.pk:
            _audit_log_model().create_entry(
                operation_type=_audit_log_model().OperationType.DEVICE_SECRET_CHANGED,
                target=device or config,
                target_display='Device enrollment credential replacement',
                actor=actor,
                details={
                    'credential': field if field in VERSIONS else 'unknown',
                    'action': 'custom' if custom else 'generate',
                    'outcome': 'rejected',
                },
            )
        raise


@transaction.atomic
def invalidate_onboarding_secrets(config: OnboardingConfigModel) -> None:
    """Invalidate bootstrap material after failed onboarding without completing it.

    This internal lifecycle transition deliberately bypasses replacement policy:
    outstanding transactions must not prevent invalidation on a timeout. The
    row lock and version increments still invalidate in-flight secret proofs.
    """
    fresh = _onboarding_config_model().objects.select_for_update().get(pk=config.pk)
    _onboarding_config_model().objects.filter(pk=fresh.pk).update(
        cmp_shared_secret='',
        est_password='',
        credential_expires_at=None,
        cmp_secret_version=fresh.cmp_secret_version + bool(fresh.cmp_shared_secret),
        est_password_version=fresh.est_password_version + bool(fresh.est_password),
    )
    config.refresh_from_db()


@transaction.atomic
def retire_onboarding_secrets(config: OnboardingConfigModel) -> None:
    """Close onboarding and clear bootstrap material at an existing successful completion boundary."""
    fresh = _onboarding_config_model().objects.select_for_update().get(pk=config.pk)
    fresh.onboarding_status = OnboardingStatus.ONBOARDED
    fresh.est_password = ''
    fresh.cmp_shared_secret = ''
    fresh.credential_expires_at = None
    fresh.save(update_fields=['onboarding_status', 'est_password', 'cmp_shared_secret', 'credential_expires_at'])
    config.refresh_from_db()


def remember_secret(context: BaseRequestContext, config: Config, field: str) -> None:
    """Bind the authenticated request to a configuration and credential generation."""
    context.authenticated_secret_field = field
    context.authenticated_secret_version = getattr(config, VERSIONS[field])
    context.authenticated_secret_config = config._meta.label
    context.authenticated_secret_pk = config.pk


def _secret_reference(context: BaseRequestContext) -> tuple[str, int, str, int | None] | None:
    """Also reserve manual domain-identity issuance against concurrent bootstrap issuance."""
    if context.authenticated_secret_field is not None:
        if context.authenticated_secret_field not in VERSIONS:
            msg = 'Unknown authenticated device credential.'
            raise ValueError(msg)
        if not context.authenticated_secret_config or context.authenticated_secret_pk is None:
            msg = 'The authenticated credential reference is incomplete.'
            raise ValueError(msg)
        return (
            context.authenticated_secret_config,
            context.authenticated_secret_pk,
            context.authenticated_secret_field,
            context.authenticated_secret_version,
        )

    if isinstance(context, BaseCertificateRequestContext) and context.device and context.domain:
        config = getattr(context.device, 'onboarding_config', None)
        profile = context.certificate_profile_model
        if (
            _is_onboarding_config(config)
            and config.onboarding_status == OnboardingStatus.PENDING
            and profile
            and profile.unique_name == context.domain.get_domain_credential_profile_name()
        ):
            return (config._meta.label, config.pk, 'onboarding', None)
    return None


@contextmanager
def secret_use(context: BaseRequestContext) -> Iterator[None]:
    """Reserve an authenticated generation across local and external CA operations."""
    key = _secret_reference(context)
    if key is None:
        yield
        return

    label, config_pk, field, version = key
    nested = key in _ACTIVE_USES.get()
    model = apps.get_model(label)
    with transaction.atomic():
        config = model.objects.select_for_update().get(pk=config_pk)
        if field in VERSIONS and (getattr(config, VERSIONS[field]) != version or not getattr(config, field)):
            msg = 'The enrollment credential changed. Authenticate again.'
            raise ValueError(msg)
        if _is_onboarding_config(config) and (
            config.onboarding_status == OnboardingStatus.ONBOARDED
            or (field in VERSIONS and config.is_credential_expired())
        ):
            msg = 'The onboarding credential is no longer available.'
            raise ValueError(msg)
        if (
            not nested
            and _is_onboarding_config(config)
            and _secret_use_model().objects.filter(config_label=label, config_pk=config_pk).exists()
        ):
            msg = 'Another onboarding operation is in progress. Retry after it completes.'
            raise ValueError(msg)
        reservation = (
            None
            if nested
            else _secret_use_model().objects.create(
                config_label=label,
                config_pk=config_pk,
                credential=field,
            )
        )
    token = _ACTIVE_USES.set(_ACTIVE_USES.get() | {key})
    try:
        yield
    finally:
        _ACTIVE_USES.reset(token)
        if reservation is not None:
            reservation.delete()
