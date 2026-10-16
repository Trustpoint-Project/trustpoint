# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for actor-aware security-sensitive change auditing."""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    Pkcs11AuthSource,
)
from management.models import AuditLog, SecurityConfig
from management.security_change_audit import audit_security_change, snapshot_security_state

pytestmark = pytest.mark.django_db


def test_provider_configuration_records_before_after_state_with_actor() -> None:
    """Provider changes reuse AuditLog and preserve the authenticated actor."""
    user_model = get_user_model()
    actor = user_model.objects.create_user(username='security-admin', password='test-password')
    profile = CryptoProviderProfileModel.objects.create(
        name='audit-provider',
        backend_kind=BackendKind.PKCS11,
        active=True,
    )
    config = CryptoProviderPkcs11ConfigModel.objects.create(
        profile=profile,
        module_path='/usr/lib/trustpoint-test-provider.so',
        token_label='token-a',
        token_serial='serial-a',
        auth_source=Pkcs11AuthSource.FILE,
        auth_source_ref='/run/secrets/pin-a',
        max_sessions=4,
        borrow_timeout_seconds=2.0,
        rw_sessions=True,
    )

    before = snapshot_security_state(config)
    config.token_label = 'token-b'
    config.auth_source_ref = '/run/secrets/pin-b'
    config.save(update_fields=['token_label', 'auth_source_ref'])

    entry = audit_security_change(target=config, actor=actor, before=before)

    assert entry is not None
    assert entry.operation_type == AuditLog.OperationType.MODEL_UPDATED
    assert entry.actor == actor
    assert entry.details['security_change_category'] == 'crypto_provider_config'
    assert entry.details['changed_fields']['token_label'] == {
        'before': 'token-a',
        'after': 'token-b',
    }
    assert entry.details['changed_fields']['auth_source_ref'] == {
        'before': '<redacted>',
        'after': '<redacted>',
    }
    assert '/run/secrets/pin-a' not in str(entry.details)
    assert '/run/secrets/pin-b' not in str(entry.details)


def test_security_config_records_before_after_policy_change() -> None:
    """SecurityConfig changes use the existing SECURITY_CONFIG_CHANGED operation type."""
    config = SecurityConfig.objects.create(
        pk=1,
        security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD,
        allow_imported_private_keys=True,
    )

    before = snapshot_security_state(config)
    config.allow_imported_private_keys = False
    config.save(update_fields=['allow_imported_private_keys'])

    entry = audit_security_change(target=config, actor=None, before=before)

    assert entry is not None
    assert entry.operation_type == AuditLog.OperationType.SECURITY_CONFIG_CHANGED
    assert entry.actor is None
    assert entry.details['security_change_category'] == 'security_object'
    assert entry.details['changed_fields']['allow_imported_private_keys'] == {
        'before': True,
        'after': False,
    }


def test_no_change_does_not_create_audit_entry() -> None:
    """The helper avoids noisy audit entries when no security state changed."""
    config = SecurityConfig.objects.create(pk=1)
    before = snapshot_security_state(config)

    entry = audit_security_change(target=config, actor=None, before=before)

    assert entry is None
    assert not AuditLog.objects.exists()
