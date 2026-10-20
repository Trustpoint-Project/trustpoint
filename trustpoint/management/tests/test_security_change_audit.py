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
    assert entry.operation_type == AuditLog.OperationType.CRYPTO_PKCS11_CONFIG_UPDATED
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


def test_scope_reads_database_state_and_coalesces_multiple_saves() -> None:
    """Form validation mutations and intermediate saves still produce one final diff."""
    from management.security_change_audit import security_change

    config = SecurityConfig.objects.create(pk=1, max_cert_validity_days=365)
    config.max_cert_validity_days = 180  # ModelForm validation changes the instance before saving.
    with security_change(target=config, actor=None):
        config.save(update_fields=['max_cert_validity_days'])
        config.max_cert_validity_days = 90
        config.save(update_fields=['max_cert_validity_days'])

    entry = AuditLog.objects.get()
    assert entry.operation_type == AuditLog.OperationType.SECURITY_CONFIG_CHANGED
    assert entry.details['changed_fields']['max_cert_validity_days'] == {'before': 365, 'after': 90}


def test_scope_ignores_unsaved_changes() -> None:
    """Only persisted changes belong in the audit log."""
    from management.security_change_audit import security_change

    config = SecurityConfig.objects.create(pk=1)
    with security_change(target=config, actor=None):
        config.max_cert_validity_days = 17
    assert not AuditLog.objects.exists()


def test_failed_operation_rolls_back_changes_and_audit() -> None:
    """An exception leaves neither a changed policy nor a success audit row."""
    from management.security_change_audit import security_change

    config = SecurityConfig.objects.create(pk=1, max_cert_validity_days=365)
    with pytest.raises(RuntimeError, match='operation failed'):
        with security_change(target=config, actor=None):
            config.max_cert_validity_days = 90
            config.save(update_fields=['max_cert_validity_days'])
            raise RuntimeError('operation failed')
    config.refresh_from_db()
    assert config.max_cert_validity_days == 365
    assert not AuditLog.objects.exists()


def test_audit_failure_rolls_back_policy_change(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful policy changes require their audit entry to persist too."""
    from management.security_change_audit import security_change

    config = SecurityConfig.objects.create(pk=1, max_cert_validity_days=365)

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError('audit unavailable')

    monkeypatch.setattr(AuditLog, 'create_entry', fail_audit)
    with pytest.raises(RuntimeError, match='audit unavailable'):
        with security_change(target=config, actor=None):
            config.max_cert_validity_days = 90
            config.save(update_fields=['max_cert_validity_days'])
    config.refresh_from_db()
    assert config.max_cert_validity_days == 365


def test_deletion_preserves_target_identity() -> None:
    """Instance deletion clears pk, but the audit retains the original target."""
    from management.security_change_audit import security_change
    from pki.models import CertificateProfileModel

    profile = CertificateProfileModel.objects.create(unique_name='audit-profile', profile_json={})
    original_pk = profile.pk
    with security_change(target=profile, actor=None, action='deleted'):
        profile.delete()
    entry = AuditLog.objects.get()
    assert entry.operation_type == AuditLog.OperationType.CERT_PROFILE_DELETED
    assert entry.target_object_id == str(original_pk)
    assert entry.target is None
    assert entry.details['changed_fields']['unique_name'] == {'before': 'audit-profile', 'after': None}


def test_domain_membership_change_is_one_parent_event() -> None:
    """Changes to through rows are captured even without a domain field change."""
    from management.security_change_audit import security_change
    from pki.models import CertificateProfileModel, DomainAllowedCertificateProfileModel, DomainModel

    domain = DomainModel.objects.create(unique_name='audit-domain')
    profile = CertificateProfileModel.objects.create(unique_name='audit-profile', profile_json={})
    with security_change(target=domain, actor=None):
        DomainAllowedCertificateProfileModel.objects.create(domain=domain, certificate_profile=profile, alias='audit')
    entry = AuditLog.objects.get()
    assert entry.operation_type == AuditLog.OperationType.DOMAIN_UPDATED
    assert entry.details['changed_fields']['certificate_profiles']['after'] == [
        {'certificate_profile_id': profile.pk, 'alias': 'audit'}
    ]


def test_provider_setup_coalesces_updates_and_skips_repeated_configuration() -> None:
    """Each changed provider object gets one specific entry despite repeated saves."""
    from management.security_change_audit import provider_configuration_changes

    with provider_configuration_changes(actor=None):
        profile = CryptoProviderProfileModel.objects.create(
            name='provider-initial', backend_kind=BackendKind.PKCS11, active=True
        )
        profile.name = 'provider-final'
        profile.save()
    entry = AuditLog.objects.get()
    assert entry.operation_type == AuditLog.OperationType.CRYPTO_PROVIDER_CREATED
    assert entry.details['changed_fields']['name'] == {'before': None, 'after': 'provider-final'}
    with provider_configuration_changes(actor=None):
        profile.save()
    assert AuditLog.objects.count() == 1
    with provider_configuration_changes(actor=None):
        profile.delete()
    assert AuditLog.objects.count() == 2
    assert AuditLog.objects.first().operation_type == AuditLog.OperationType.CRYPTO_PROVIDER_DELETED


def test_certificate_profile_api_owns_one_event_per_mutation() -> None:
    """Exercise actual create/update/no-op/delete paths and count persisted events."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    from pki.views.cert_profiles import CertProfileViewSet

    actor = get_user_model().objects.create_superuser(username='audit-api', password='test-password')
    from django.contrib.auth.models import Permission
    actor.role.permissions.add(*Permission.objects.filter(codename__in=['manage_certificate_profiles', 'use_rest_api']))
    factory = APIRequestFactory()

    def call(method: str, data: dict | None = None, pk: int | None = None):
        request = getattr(factory, method)('/profiles/', data=data or {}, format='json')
        force_authenticate(request, user=actor)
        action = {'post': 'create', 'patch': 'partial_update', 'delete': 'destroy'}[method]
        return CertProfileViewSet.as_view({method: action})(request, **({'pk': pk} if pk else {}))

    response = call('post', {'unique_name': 'audit-api-profile', 'profile_json': {}})
    assert response.status_code == 201, response.data
    pk = response.data['id']
    assert AuditLog.objects.count() == 1
    assert AuditLog.objects.get().operation_type == AuditLog.OperationType.CERT_PROFILE_CREATED
    response = call('patch', {'display_name': 'Changed'}, pk)
    assert response.status_code == 200, response.data
    assert AuditLog.objects.count() == 2
    assert AuditLog.objects.first().actor == actor
    assert AuditLog.objects.first().operation_type == AuditLog.OperationType.CERT_PROFILE_UPDATED
    response = call('patch', {'display_name': 'Changed'}, pk)
    assert response.status_code == 200
    assert AuditLog.objects.count() == 2
    response = call('delete', pk=pk)
    assert response.status_code == 204
    assert AuditLog.objects.count() == 3
    assert AuditLog.objects.first().operation_type == AuditLog.OperationType.CERT_PROFILE_DELETED
    assert AuditLog.objects.first().target_object_id == str(pk)


def test_nested_provider_setup_has_one_owner() -> None:
    """Lazy local setup inside bootstrap must not audit the same object twice."""
    from management.security_change_audit import provider_configuration_changes

    with provider_configuration_changes(actor=None):
        with provider_configuration_changes(actor=None):
            CryptoProviderProfileModel.objects.create(name='nested-provider', backend_kind=BackendKind.PKCS11)
    assert AuditLog.objects.count() == 1
    assert AuditLog.objects.get().operation_type == AuditLog.OperationType.CRYPTO_PROVIDER_CREATED


def test_security_settings_view_replaces_old_entry_and_includes_final_defaults() -> None:
    """The view writes exactly one entry after applying all mode-dependent changes."""
    from unittest.mock import Mock

    from django.contrib.auth.models import Permission
    from django.contrib.messages.storage.fallback import FallbackStorage
    from django.test import RequestFactory

    from management.forms import SecurityConfigForm
    from management.views.settings import SecuritySettingsView

    actor = get_user_model().objects.create_user(username='settings-audit', password='test-password')
    actor.role.permissions.add(Permission.objects.get(codename='manage_security_configuration'))
    config = SecurityConfig.objects.create(
        pk=1, security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD, credential_ttl_seconds=60
    )
    config.security_mode = SecurityConfig.SecurityModeChoices.HARDENED
    form = Mock(spec=SecurityConfigForm)
    form.instance = config
    form.changed_data = ['security_mode']
    form.cleaned_data = {'security_mode': config.security_mode}
    form.save.side_effect = config.save
    request = RequestFactory().post('/settings/security/')
    request.user = actor
    request.session = {}
    request._messages = FallbackStorage(request)
    view = SecuritySettingsView()
    view.setup(request)
    view.sec = Mock()

    def apply_remaining_defaults(*args: object) -> None:
        SecurityConfig.objects.filter(pk=1).update(credential_ttl_seconds=30)

    view.sec.reset_settings.side_effect = apply_remaining_defaults
    response = view.form_valid(form)
    assert response.status_code == 302
    entry = AuditLog.objects.get()
    assert entry.actor == actor
    assert entry.operation_type == AuditLog.OperationType.SECURITY_CONFIG_CHANGED
    assert entry.details['changed_fields']['credential_ttl_seconds'] == {'before': 60, 'after': 30}
    assert entry.details['changed_fields']['security_mode'] == {
        'before': SecurityConfig.SecurityModeChoices.BROWNFIELD,
        'after': SecurityConfig.SecurityModeChoices.HARDENED,
    }
    form.changed_data = []
    response = view.form_valid(form)
    assert response.status_code == 302
    assert AuditLog.objects.count() == 1


def test_anonymous_actor_is_recorded_as_system() -> None:
    """Unauthenticated setup has no user foreign key in the audit row."""
    from django.contrib.auth.models import AnonymousUser
    from management.security_change_audit import security_change

    config = SecurityConfig.objects.create(pk=1, max_cert_validity_days=365)
    with security_change(target=config, actor=AnonymousUser()):
        config.max_cert_validity_days = 90
        config.save(update_fields=['max_cert_validity_days'])
    assert AuditLog.objects.get().actor is None
