"""Tests for operational attach compatibility reporting."""

# ruff: noqa: D103, S106, S107

from unittest.mock import patch

from appsecrets.service import AppSecretConfigurationError
from crypto.domain.refs import ManagedKeyVerificationStatus
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_attach import (
    CompatibilitySeverity,
    OperationalAppSecretMaterial,
    OperationalAttachmentValidator,
    OperationalAttachMode,
    OperationalBackendBinding,
    OperationalDatabaseConfig,
    OperationalManagedKeyMaterial,
    OperationalStateSnapshot,
    OperationalTargetConfig,
)
from setup_wizard.views import app_secret_decryptability_checks, managed_key_backend_reconciliation_checks


def _target(
    *,
    crypto_backend_kind: str = 'software',
    app_secret_backend_kind: str = 'software',
) -> OperationalTargetConfig:
    return OperationalTargetConfig(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        database=OperationalDatabaseConfig(
            host='postgres',
            port=5432,
            name='trustpoint',
            user='trustpoint',
            password='secret',
        ),
        crypto_backend=OperationalBackendBinding(backend_kind=crypto_backend_kind),
        app_secret_backend=OperationalBackendBinding(backend_kind=app_secret_backend_kind),
    )


def test_missing_target_and_snapshot_blocks_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        target=None,
        snapshot=None,
    )

    assert not report.can_apply
    assert {check.code for check in report.checks} == {'target.missing', 'snapshot.missing'}


def test_matching_target_can_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        target=_target(),
        snapshot=OperationalStateSnapshot(
            app_version='1.0.0',
            setup_completed=True,
            crypto_backend_kind='software',
            app_secret_backend_kind='software',
            app_secret_material_present=True,
        ),
    )

    assert report.can_apply
    assert not report.has_errors


def test_newer_database_blocks_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.RESTORE_BACKUP,
        target=_target(),
        snapshot=OperationalStateSnapshot(
            app_version='1.1.0',
            setup_completed=True,
            crypto_backend_kind='software',
            app_secret_backend_kind='software',
            app_secret_material_present=True,
        ),
    )

    assert not report.can_apply
    assert any(
        check.code == 'version.container_too_old' and check.severity == CompatibilitySeverity.ERROR
        for check in report.checks
    )


def test_backend_kind_mismatch_blocks_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        target=_target(crypto_backend_kind='software'),
        snapshot=OperationalStateSnapshot(
            app_version='1.0.0',
            setup_completed=True,
            crypto_backend_kind='pkcs11',
            app_secret_backend_kind='software',
            app_secret_material_present=True,
        ),
    )

    assert not report.can_apply
    assert any(check.code == 'crypto.kind_mismatch' for check in report.checks)


def test_matching_binding_counts_with_missing_binding_blocks_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        target=_target(),
        snapshot=OperationalStateSnapshot(
            app_version='1.0.0',
            setup_completed=True,
            crypto_backend_kind='software',
            app_secret_backend_kind='software',
            managed_key_count=2,
            managed_key_binding_count=2,
            managed_key_missing_binding_count=1,
            app_secret_material_present=True,
        ),
    )

    assert not report.can_apply
    assert any(
        check.code == 'managed_keys.bindings_missing'
        and check.severity == CompatibilitySeverity.ERROR
        for check in report.checks
    )


def test_orphan_backend_binding_blocks_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        target=_target(),
        snapshot=OperationalStateSnapshot(
            app_version='1.0.0',
            setup_completed=True,
            crypto_backend_kind='software',
            app_secret_backend_kind='software',
            managed_key_count=2,
            managed_key_binding_count=2,
            managed_key_orphan_binding_count=1,
            app_secret_material_present=True,
        ),
    )

    assert not report.can_apply
    assert any(
        check.code == 'managed_keys.orphan_bindings'
        and check.severity == CompatibilitySeverity.ERROR
        for check in report.checks
    )


def test_multiple_active_crypto_profiles_blocks_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        target=_target(),
        snapshot=OperationalStateSnapshot(
            app_version='1.0.0',
            setup_completed=True,
            crypto_backend_kind='software',
            app_secret_backend_kind='software',
            active_crypto_profile_count=2,
            app_secret_material_present=True,
        ),
    )

    assert not report.can_apply
    assert any(
        check.code == 'crypto.active_profile_count'
        and check.severity == CompatibilitySeverity.ERROR
        for check in report.checks
    )


def test_completed_target_without_app_secret_material_blocks_apply() -> None:
    validator = OperationalAttachmentValidator(current_version='1.0.0')

    report = validator.build_report(
        mode=OperationalAttachMode.CONNECT_EXISTING,
        target=_target(),
        snapshot=OperationalStateSnapshot(
            app_version='1.0.0',
            setup_completed=True,
            crypto_backend_kind='software',
            app_secret_backend_kind='software',
            app_secret_material_present=False,
        ),
    )

    assert not report.can_apply
    assert any(
        check.code == 'appsecret.material_missing'
        and check.severity == CompatibilitySeverity.ERROR
        for check in report.checks
    )


def test_software_app_secret_decryptability_accepts_valid_dek() -> None:
    config_model = SetupWizardConfigModel(crypto_storage=SetupWizardConfigModel.CryptoStorageType.SoftwareStorage)
    snapshot = OperationalStateSnapshot(
        app_version='1.0.0',
        setup_completed=True,
        crypto_backend_kind='software',
        app_secret_backend_kind='software',
        app_secret_material_present=True,
    )

    with patch(
        'setup_wizard.views.OperationalTargetInspector.inspect_app_secret_material',
        return_value=OperationalAppSecretMaterial(backend_kind='software', raw_dek=b'a' * 32),
    ):
        checks = app_secret_decryptability_checks(
            config_model=config_model,
            target=_target(),
            snapshot=snapshot,
        )

    assert checks[0].code == 'appsecret.decryptability_ok'
    assert checks[0].severity == CompatibilitySeverity.INFO


def test_pkcs11_app_secret_decryptability_uses_staged_backend() -> None:
    config_model = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_token_label='Trustpoint-SoftHSM',
    )
    snapshot = OperationalStateSnapshot(
        app_version='1.0.0',
        setup_completed=True,
        crypto_backend_kind='pkcs11',
        app_secret_backend_kind='pkcs11',
        app_secret_material_present=True,
    )

    with patch(
        'setup_wizard.views.OperationalTargetInspector.inspect_app_secret_material',
        return_value=OperationalAppSecretMaterial(
            backend_kind='pkcs11',
            wrapped_dek=b'wrapped-dek',
            kek_label='trustpoint-app-secret-kek',
        ),
    ), patch(
        'setup_wizard.views.apply_pkcs11_probe_fallbacks',
        return_value=('/usr/lib/pkcs11.so', '/run/pin.txt', []),
    ), patch('setup_wizard.views.Pkcs11AppSecretService') as service_class:
        service_class.return_value.recover_existing_dek.return_value = b'a' * 32
        checks = app_secret_decryptability_checks(
            config_model=config_model,
            target=_target(crypto_backend_kind='pkcs11', app_secret_backend_kind='pkcs11'),
            snapshot=snapshot,
        )

    assert checks[0].code == 'appsecret.decryptability_ok'
    assert checks[0].severity == CompatibilitySeverity.INFO
    service_class.return_value.recover_existing_dek.assert_called_once_with()


def test_pkcs11_app_secret_decryptability_blocks_when_recovery_fails() -> None:
    config_model = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_token_label='Trustpoint-SoftHSM',
    )
    snapshot = OperationalStateSnapshot(
        app_version='1.0.0',
        setup_completed=True,
        crypto_backend_kind='pkcs11',
        app_secret_backend_kind='pkcs11',
        app_secret_material_present=True,
    )

    with patch(
        'setup_wizard.views.OperationalTargetInspector.inspect_app_secret_material',
        return_value=OperationalAppSecretMaterial(
            backend_kind='pkcs11',
            wrapped_dek=b'wrapped-dek',
            kek_label='trustpoint-app-secret-kek',
        ),
    ), patch(
        'setup_wizard.views.apply_pkcs11_probe_fallbacks',
        return_value=('/usr/lib/pkcs11.so', '/run/pin.txt', []),
    ), patch('setup_wizard.views.Pkcs11AppSecretService') as service_class:
        service_class.return_value.recover_existing_dek.side_effect = AppSecretConfigurationError('missing kek')
        checks = app_secret_decryptability_checks(
            config_model=config_model,
            target=_target(crypto_backend_kind='pkcs11', app_secret_backend_kind='pkcs11'),
            snapshot=snapshot,
        )

    assert checks[0].code == 'appsecret.decryptability_failed'
    assert checks[0].severity == CompatibilitySeverity.ERROR


def _pkcs11_key_material(alias: str = 'ca/root') -> OperationalManagedKeyMaterial:
    return OperationalManagedKeyMaterial(
        backend_kind='pkcs11',
        alias=alias,
        provider_label=alias,
        algorithm='rsa',
        public_key_fingerprint_sha256='a' * 64,
        signing_execution_mode='complete_backend',
        binding={'key_id_hex': '01020304'},
    )


def _pkcs11_snapshot() -> OperationalStateSnapshot:
    return OperationalStateSnapshot(
        app_version='1.0.0',
        setup_completed=True,
        crypto_backend_kind='pkcs11',
        app_secret_backend_kind='pkcs11',
        managed_key_count=1,
        managed_key_binding_count=1,
        app_secret_material_present=True,
    )


def test_managed_key_reconciliation_accepts_matching_backend_key() -> None:
    config_model = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_token_label='Trustpoint-SoftHSM',
    )

    with patch(
        'setup_wizard.views.OperationalTargetInspector.inspect_managed_key_material',
        return_value=(_pkcs11_key_material(),),
    ), patch(
        'setup_wizard.views.apply_pkcs11_probe_fallbacks',
        return_value=('/usr/lib/pkcs11.so', '/run/pin.txt', []),
    ), patch('setup_wizard.views.Pkcs11Backend') as backend_class:
        backend_class.return_value.verify_managed_key.return_value.status = ManagedKeyVerificationStatus.PRESENT
        checks = managed_key_backend_reconciliation_checks(
            config_model=config_model,
            target=_target(crypto_backend_kind='pkcs11', app_secret_backend_kind='pkcs11'),
            snapshot=_pkcs11_snapshot(),
        )

    assert checks[0].code == 'managed_keys.backend_reconciliation_ok'
    assert checks[0].severity == CompatibilitySeverity.INFO
    backend_class.return_value.verify_managed_key.assert_called_once()
    backend_class.return_value.close.assert_called_once_with()


def test_managed_key_reconciliation_blocks_missing_backend_key() -> None:
    config_model = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_token_label='Trustpoint-SoftHSM',
    )

    with patch(
        'setup_wizard.views.OperationalTargetInspector.inspect_managed_key_material',
        return_value=(_pkcs11_key_material(),),
    ), patch(
        'setup_wizard.views.apply_pkcs11_probe_fallbacks',
        return_value=('/usr/lib/pkcs11.so', '/run/pin.txt', []),
    ), patch('setup_wizard.views.Pkcs11Backend') as backend_class:
        backend_class.return_value.verify_managed_key.return_value.status = ManagedKeyVerificationStatus.MISSING
        checks = managed_key_backend_reconciliation_checks(
            config_model=config_model,
            target=_target(crypto_backend_kind='pkcs11', app_secret_backend_kind='pkcs11'),
            snapshot=_pkcs11_snapshot(),
        )

    assert checks[0].code == 'managed_keys.backend_reconciliation_failed'
    assert checks[0].severity == CompatibilitySeverity.ERROR


def test_managed_key_reconciliation_blocks_when_binding_material_is_missing() -> None:
    config_model = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_token_label='Trustpoint-SoftHSM',
    )

    with patch(
        'setup_wizard.views.OperationalTargetInspector.inspect_managed_key_material',
        return_value=(),
    ):
        checks = managed_key_backend_reconciliation_checks(
            config_model=config_model,
            target=_target(crypto_backend_kind='pkcs11', app_secret_backend_kind='pkcs11'),
            snapshot=_pkcs11_snapshot(),
        )

    assert checks[0].code == 'managed_keys.backend_reconciliation_failed'
    assert checks[0].severity == CompatibilitySeverity.ERROR
