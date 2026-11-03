# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Imported keys participate in attachment checks using the target database's DEK."""

import base64
import os
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.db import connection

from appsecrets.service import AAD_CONTEXT, CIPHERTEXT_PREFIX, SoftwareAppSecretService, load_software_kek
from crypto.domain.public_keys import public_key_fingerprint_sha256
from crypto.models import (
    CryptoManagedKeyModel,
    CryptoManagedKeyPkcs11BindingModel,
    CryptoManagedKeyProtectedImportBindingModel,
    CryptoManagedKeySoftwareBindingModel,
    CryptoProviderProfileModel,
)
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_attach import (
    OperationalAppSecretMaterial,
    OperationalAttachmentValidator,
    OperationalStateSnapshot,
    OperationalTargetInspector,
)
from setup_wizard.tests.test_operational_attach import _target
from setup_wizard.views import managed_key_backend_reconciliation_checks

pytestmark = pytest.mark.django_db


@pytest.fixture(params=['software', 'pkcs11'])
def imported_keys(request, ec_private_key, monkeypatch):
    kind = request.param
    profile = CryptoProviderProfileModel.objects.create(name='target-provider', backend_kind=kind, active=True)
    fingerprint = public_key_fingerprint_sha256(ec_private_key.public_key())
    native = CryptoManagedKeyModel.objects.create(
        alias='native',
        provider_profile=profile,
        algorithm='ec',
        public_key_fingerprint_sha256=fingerprint,
    )
    if kind == 'pkcs11':
        CryptoManagedKeyPkcs11BindingModel.objects.create(
            managed_key=native,
            provider_profile=profile,
            key_id_hex='01020304',
        )
    else:
        encrypted_der = ec_private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b'test-provider-password'),
        )
        CryptoManagedKeySoftwareBindingModel.objects.create(
            managed_key=native,
            provider_profile=profile,
            key_handle='native',
            encrypted_private_key_pkcs8_der=encrypted_der,
        )
    imported = CryptoManagedKeyModel.objects.create(
        alias='imported',
        provider_profile=profile,
        algorithm='ec',
        public_key_fingerprint_sha256=fingerprint,
    )
    # Deliberately differs from the DEK configured by the bootstrap test fixtures.
    dek = b't' * 32
    private_der = ec_private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    nonce = os.urandom(12)
    encrypted = AESGCM(dek).encrypt(nonce, base64.b64encode(private_der), AAD_CONTEXT)
    ciphertext = CIPHERTEXT_PREFIX + base64.b64encode(nonce + encrypted[-16:] + encrypted[:-16]).decode('ascii')
    binding = CryptoManagedKeyProtectedImportBindingModel.objects.create(
        managed_key=imported,
        provider_profile=profile,
        key_handle='imported',
        encrypted_private_key_pkcs8_der_b64=ciphertext,
    )
    tables = set(connection.introspection.table_names())
    monkeypatch.setattr(
        OperationalTargetInspector,
        '_table_exists',
        classmethod(lambda cls, cursor, *, table_name: table_name in tables),
    )
    cursor = Mock()
    cursor.fetchall.return_value = [
        (
            imported.alias,
            imported.provider_label,
            imported.algorithm,
            fingerprint,
            imported.signing_execution_mode,
            binding.key_handle,
            ciphertext,
            binding.encryption_metadata,
        )
    ]
    (material,) = OperationalTargetInspector._read_protected_import_managed_key_material(cursor)
    return SimpleNamespace(
        kind=kind, profile=profile, native=native, imported=imported, binding=binding, material=material, dek=dek
    )


def test_import_bindings_are_counted_alongside_native_bindings(imported_keys):
    inspector = OperationalTargetInspector()
    with connection.cursor() as cursor:
        assert inspector._read_managed_key_binding_count(cursor, crypto_backend_kind=imported_keys.kind) == 2
        assert inspector._read_managed_key_missing_binding_count(cursor, crypto_backend_kind=imported_keys.kind) == 0
        assert inspector._read_managed_key_binding_issue_count(cursor, crypto_backend_kind=imported_keys.kind) == 0
        assert (
            inspector._read_managed_key_binding_profile_mismatch_count(cursor, crypto_backend_kind=imported_keys.kind)
            == 0
        )
        assert inspector._read_managed_key_orphan_binding_count(cursor, crypto_backend_kind=imported_keys.kind) == 0
    assert imported_keys.material.backend_kind == 'protected_import'
    assert imported_keys.material.binding['encrypted_private_key_pkcs8_der_b64'] == (
        imported_keys.binding.encrypted_private_key_pkcs8_der_b64
    )
    with patch.object(
        OperationalTargetInspector,
        '_read_protected_import_managed_key_material',
        return_value=(imported_keys.material,),
    ):
        with connection.cursor() as cursor:
            native_reader = (
                '_read_pkcs11_managed_key_material'
                if imported_keys.kind == 'pkcs11'
                else '_read_software_managed_key_material'
            )
            with patch.object(inspector.__class__, native_reader, return_value=()):
                assert inspector._read_managed_key_material(cursor, crypto_backend_kind=imported_keys.kind) == (
                    imported_keys.material,
                )


@pytest.mark.parametrize('failure', ['missing', 'empty', 'profile'])
def test_import_binding_integrity_is_checked(imported_keys, failure):
    if failure == 'missing':
        imported_keys.binding.delete()
        method = '_read_managed_key_missing_binding_count'
        code = 'managed_keys.bindings_missing'
        snapshot_field = 'managed_key_missing_binding_count'
    elif failure == 'empty':
        CryptoManagedKeyProtectedImportBindingModel.objects.update(encrypted_private_key_pkcs8_der_b64='')
        method = '_read_managed_key_binding_issue_count'
        code = 'managed_keys.binding_payload_invalid'
        snapshot_field = 'managed_key_binding_issue_count'
    else:
        other = CryptoProviderProfileModel.objects.create(name='other-provider', backend_kind=imported_keys.kind)
        CryptoManagedKeyProtectedImportBindingModel.objects.update(provider_profile=other)
        method = '_read_managed_key_binding_profile_mismatch_count'
        code = 'managed_keys.binding_profile_mismatch'
        snapshot_field = 'managed_key_binding_profile_mismatch_count'
    with connection.cursor() as cursor:
        count = getattr(OperationalTargetInspector, method)(cursor, crypto_backend_kind=imported_keys.kind)
    assert count == 1
    snapshot = OperationalStateSnapshot(
        app_version='1.0.0',
        setup_completed=True,
        crypto_backend_kind=imported_keys.kind,
        app_secret_backend_kind='software',
        managed_key_count=2,
        managed_key_binding_count=2,
        app_secret_material_present=True,
        **{snapshot_field: count},
    )
    checks = OperationalAttachmentValidator._state_coherence_checks(snapshot=snapshot)
    assert any(check.code == code and check.severity == 'error' for check in checks)


@pytest.mark.parametrize('failure', [None, 'mismatch', 'corrupt', 'wrong-kek'])
def test_reconciliation_decrypts_imports_with_target_software_dek(imported_keys, failure, monkeypatch, tmp_path):
    material = imported_keys.material
    if failure == 'mismatch':
        material = replace(material, public_key_fingerprint_sha256='0' * 64)
    elif failure == 'corrupt':
        binding = dict(material.binding)
        ciphertext = base64.b64decode(binding['encrypted_private_key_pkcs8_der_b64'][len(CIPHERTEXT_PREFIX) :])
        binding['encrypted_private_key_pkcs8_der_b64'] = CIPHERTEXT_PREFIX + base64.b64encode(
            ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        ).decode('ascii')
        material = replace(material, binding=binding)
    secret_material = OperationalAppSecretMaterial(
        backend_kind='software',
        wrapped_dek=SoftwareAppSecretService.wrap_dek(load_software_kek(), imported_keys.dek),
    )
    if failure == 'wrong-kek':
        wrong_key = tmp_path / 'wrong-kek'
        wrong_key.write_text('cd' * 32)
        monkeypatch.setenv('TRUSTPOINT_SOFTWARE_KEK_FILE', str(wrong_key))
    backend = Mock()
    snapshot = OperationalStateSnapshot(
        app_version='1.0.0',
        setup_completed=True,
        crypto_backend_kind=imported_keys.kind,
        app_secret_backend_kind='software',
        managed_key_count=1,
        managed_key_binding_count=1,
        app_secret_material_present=True,
    )
    storage = SetupWizardConfigModel.CryptoStorageType
    config = SetupWizardConfigModel(
        crypto_storage=storage.HsmStorage if imported_keys.kind == 'pkcs11' else storage.SoftwareStorage
    )
    with (
        patch.object(OperationalTargetInspector, 'inspect_managed_key_material', return_value=(material,)),
        patch.object(OperationalTargetInspector, 'inspect_app_secret_material', return_value=secret_material),
        patch('setup_wizard.views._managed_key_reconciliation_backend', return_value=backend),
        patch(
            'crypto.application.protected_import.decrypt_app_secret', side_effect=AssertionError('bootstrap DEK used')
        ),
    ):
        checks = managed_key_backend_reconciliation_checks(
            config_model=config,
            target=_target(crypto_backend_kind=imported_keys.kind),
            snapshot=snapshot,
        )
    assert checks[0].code == (
        'managed_keys.backend_reconciliation_failed' if failure else 'managed_keys.backend_reconciliation_ok'
    )
    backend.verify_managed_key.assert_not_called()
    backend.close.assert_called_once()


@pytest.mark.parametrize('imported_keys', ['pkcs11'], indirect=True)
@pytest.mark.parametrize('recovery_fails', [False, True])
def test_reconciliation_uses_staged_hsm_to_recover_target_import_key(imported_keys, recovery_fails):
    config = SetupWizardConfigModel(crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage)
    snapshot = OperationalStateSnapshot(
        app_version='1.0.0',
        setup_completed=True,
        crypto_backend_kind='pkcs11',
        app_secret_backend_kind='pkcs11',
        managed_key_count=1,
        managed_key_binding_count=1,
        app_secret_material_present=True,
    )
    secret_material = OperationalAppSecretMaterial(
        backend_kind='pkcs11', wrapped_dek=b'target-envelope', kek_label='target-kek'
    )
    with (
        patch.object(
            OperationalTargetInspector, 'inspect_managed_key_material', return_value=(imported_keys.material,)
        ),
        patch.object(OperationalTargetInspector, 'inspect_app_secret_material', return_value=secret_material),
        patch('setup_wizard.views._managed_key_reconciliation_backend') as native,
        patch('setup_wizard.views._build_staged_pkcs11_app_secret_config') as config_builder,
        patch('setup_wizard.views.Pkcs11AppSecretService') as service,
        patch(
            'crypto.application.protected_import.decrypt_app_secret', side_effect=AssertionError('bootstrap DEK used')
        ),
    ):
        service.return_value.recover_existing_dek.return_value = imported_keys.dek
        if recovery_fails:
            service.return_value.recover_existing_dek.side_effect = RuntimeError('HSM unavailable')
        checks = managed_key_backend_reconciliation_checks(
            config_model=config,
            target=_target(crypto_backend_kind='pkcs11', app_secret_backend_kind='pkcs11'),
            snapshot=snapshot,
        )
    assert checks[0].code == (
        'managed_keys.backend_reconciliation_failed' if recovery_fails else 'managed_keys.backend_reconciliation_ok'
    )
    config_builder.assert_called_once_with(config, wrapped_dek=b'target-envelope', kek_label='target-kek')
    service.return_value.recover_existing_dek.assert_called_once()
    native.return_value.verify_managed_key.assert_not_called()
