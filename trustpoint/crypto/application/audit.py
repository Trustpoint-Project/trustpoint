"""Sanitized audit helpers for crypto backend operations."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from enum import Enum
from time import perf_counter
from typing import TYPE_CHECKING
from uuid import UUID

from django.db import DatabaseError

from crypto.domain.specs import EcKeySpec, RsaKeySpec
from management.models import AuditLog, LoggingConfig

if TYPE_CHECKING:
    from django.db import models

    from crypto.domain.policies import KeyPolicy
    from crypto.domain.specs import KeySpec, SignRequest
    from crypto.models import CryptoManagedKeyModel, CryptoProviderProfileModel

logger = logging.getLogger('trustpoint.crypto.backend.audit')

_ERROR_SUMMARY_MAX_LENGTH = 500


def key_spec_audit_details(key_spec: KeySpec) -> dict[str, object]:
    """Return sanitized key-spec metadata suitable for logs and audit rows."""
    if isinstance(key_spec, RsaKeySpec):
        return {
            'key_algorithm': 'rsa',
            'key_size': key_spec.key_size,
        }

    if isinstance(key_spec, EcKeySpec):
        return {
            'key_algorithm': 'ec',
            'curve': key_spec.curve.value,
        }

    return {'key_spec_type': type(key_spec).__name__}


def key_policy_audit_details(policy: KeyPolicy) -> dict[str, object]:
    """Return sanitized key-policy metadata suitable for logs and audit rows."""
    return {
        'signing_execution_mode': policy.signing_execution_mode.value,
    }


def sign_request_audit_details(request: SignRequest, *, data_length: int) -> dict[str, object]:
    """Return sanitized signing-request metadata without payload or signature bytes."""
    return {
        'signature_algorithm': request.signature_algorithm.value,
        'hash_algorithm': request.hash_algorithm.value,
        'prehashed': request.prehashed,
        'data_length': data_length,
    }


def crypto_backend_audit_enabled() -> bool:
    """Return whether persistent crypto backend audit rows should be written."""
    try:
        config = LoggingConfig.objects.only('crypto_backend_audit_enabled').first()
    except DatabaseError:  # pragma: no cover - defensive; auditing must never break crypto operations
        logger.debug('Unable to read crypto backend audit setting.', exc_info=True)
        return False

    return bool(config and config.crypto_backend_audit_enabled)


def audit_crypto_backend_operation(  # noqa: PLR0913
    *,
    operation: str,
    target: models.Model,
    target_display: str,
    started_at: float,
    status: str,
    profile: CryptoProviderProfileModel | None = None,
    managed_key: CryptoManagedKeyModel | None = None,
    details: Mapping[str, object] | None = None,
    error: BaseException | None = None,
) -> None:
    """Record a sanitized crypto backend operation in debug logs and optionally audit logs."""
    payload = _build_payload(
        started_at=started_at,
        status=status,
        profile=profile,
        managed_key=managed_key,
        details=details,
        error=error,
    )

    logger.debug('Crypto backend operation %s: %s', operation, payload)

    if not crypto_backend_audit_enabled():
        return

    try:
        AuditLog.create_entry(
            operation_type=_operation_type(operation),
            target=target,
            target_display=target_display,
            actor=None,
            details=payload,
        )
    except Exception:  # noqa: BLE001  # pragma: no cover - defensive; auditing must never break crypto operations
        logger.warning('Failed to write crypto backend audit entry.')
        logger.debug('Crypto backend audit write failure details.', exc_info=True)


def _build_payload(  # noqa: PLR0913
    *,
    started_at: float,
    status: str,
    profile: CryptoProviderProfileModel | None,
    managed_key: CryptoManagedKeyModel | None,
    details: Mapping[str, object] | None,
    error: BaseException | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        'status': status,
        'duration_ms': round((perf_counter() - started_at) * 1000, 3),
    }

    if profile is not None:
        payload.update(
            {
                'profile_name': profile.name,
                'backend_kind': profile.backend_kind,
            }
        )

    if managed_key is not None:
        payload.update(
            {
                'key_algorithm': managed_key.algorithm,
                'signing_execution_mode': managed_key.signing_execution_mode,
            }
        )

    if details:
        payload.update({key: _json_safe_value(value) for key, value in details.items()})

    if error is not None:
        payload['error_type'] = type(error).__name__
        payload['error_summary'] = str(error)[:_ERROR_SUMMARY_MAX_LENGTH]

    return payload


def _operation_type(operation: str) -> str:
    """Map service-level crypto operation names to concrete audit operation choices."""
    operation_types = {
        'verify_provider': AuditLog.OperationType.CRYPTO_VERIFY_PROVIDER,
        'generate_managed_key': AuditLog.OperationType.CRYPTO_GENERATE_MANAGED_KEY,
        'import_managed_private_key': AuditLog.OperationType.CRYPTO_IMPORT_MANAGED_KEY,
        'verify_managed_key': AuditLog.OperationType.CRYPTO_VERIFY_MANAGED_KEY,
        'get_public_key': AuditLog.OperationType.CRYPTO_GET_PUBLIC_KEY,
        'sign': AuditLog.OperationType.CRYPTO_SIGN,
        'destroy_managed_key': AuditLog.OperationType.CRYPTO_DESTROY_MANAGED_KEY,
    }
    return operation_types[operation]


def _json_safe_value(value: object) -> object:  # noqa: PLR0911
    """Convert simple domain values into JSON-compatible primitives."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return f'<{len(value)} bytes>'
    if isinstance(value, Mapping):
        return {str(key): _json_safe_value(nested_value) for key, nested_value in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe_value(nested_value) for nested_value in value]
    return str(value)
