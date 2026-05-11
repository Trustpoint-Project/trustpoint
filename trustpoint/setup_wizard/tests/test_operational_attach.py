"""Tests for operational attach compatibility reporting."""

from setup_wizard.operational_attach import (
    CompatibilitySeverity,
    OperationalAttachmentValidator,
    OperationalAttachMode,
    OperationalBackendBinding,
    OperationalDatabaseConfig,
    OperationalStateSnapshot,
    OperationalTargetConfig,
)


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
        ),
    )

    assert not report.can_apply
    assert any(check.code == 'crypto.kind_mismatch' for check in report.checks)
