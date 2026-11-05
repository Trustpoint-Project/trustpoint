# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Protect existing installations and setup recovery at lifecycle boundaries."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import CommandError, call_command, get_commands

from appsecrets.models import AppSecretBackendModel
from crypto.models import CryptoProviderProfileModel
from management.models import AppVersion
from setup_wizard import operational_handoff as handoff
from setup_wizard import pkcs11_probe
from setup_wizard.management.commands import apply_bootstrap_config, auto_setup_from_env, finalize_setup
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_attach import OperationalAttachmentValidator, OperationalStateSnapshot
from setup_wizard.views import ConnectExistingSummaryView
from users.models import BuiltinRole


@pytest.mark.parametrize(
    'name',
    [
        'bootstrap_manager',
        'startup_manager',
        'apply_bootstrap_config',
        'auto_setup_from_env',
        'finalize_setup',
    ],
)
def test_setup_commands_are_owned_by_the_wizard(name):
    assert get_commands()[name] == 'setup_wizard'


def test_fresh_install_rejects_existing_database_before_migration(monkeypatch, tmp_path):
    config = SetupWizardConfigModel(operational_db_password='deployment-secret')
    monkeypatch.setenv('DATABASE_PASSWORD', config.operational_db_password)
    monkeypatch.delenv('DATABASE_PASSWORD_FILE', raising=False)
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_ENV_FILE', str(tmp_path / 'operational.env'))
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_READY_FILE', str(tmp_path / 'operational.ready'))
    ready = tmp_path / 'operational.ready'
    ready.write_text('preserve existing runtime')
    monkeypatch.setattr(
        handoff.OperationalTargetInspector,
        'inspect_database',
        Mock(return_value=Mock(app_version='1.0.0', setup_completed=True)),
    )
    migrate = Mock()
    monkeypatch.setattr(handoff, '_run_operational_manage_command', migrate)
    with pytest.raises(ValidationError, match='Connect Existing'):
        handoff.run_operational_handoff(config)
    migrate.assert_not_called()
    assert ready.read_text() == 'preserve existing runtime'
    assert not handoff.operational_payload_file_path().exists()


@pytest.mark.parametrize('command', [apply_bootstrap_config.Command, auto_setup_from_env.Command])
def test_setup_commands_refuse_a_configured_target(command):
    AppVersion.objects.create(version='1.0.0', container_id='existing-instance')
    with pytest.raises(CommandError, match='Connect Existing'):
        command().handle(config='must-not-be-read')


def test_fresh_install_never_replaces_an_existing_administrator():
    call_command('create_builtin_groups', verbosity=0)
    user = get_user_model().objects.create_user(
        username='existing-admin',
        password='original-password',
        role=Group.objects.get(name=BuiltinRole.ADMIN.value),
    )
    previous_password = user.password
    applier = apply_bootstrap_config.OperationalBootstrapApplier(
        {
            'fresh_install': {},
            'admin': {
                'username': user.username,
                'password_hash': 'replacement-hash',
                'email': 'changed@example.invalid',
            },
        }
    )
    with pytest.raises(ValidationError, match='already exists'):
        applier._create_operational_admin()
    user.refresh_from_db()
    assert user.password == previous_password
    assert user.email != 'changed@example.invalid'


@pytest.mark.parametrize('failed_apply', [False, True])
def test_fresh_install_commits_attach_metadata_with_its_target_state(monkeypatch, tmp_path, failed_apply):
    config = SetupWizardConfigModel.get_singleton()
    payload = {
        'fresh_install': {'crypto_storage': 0, 'inject_demo_data': False},
        'admin': {'username': 'interrupted-admin', 'password_hash': 'staged-password-hash', 'email': ''},
    }
    path = tmp_path / 'apply.json'
    path.write_text(json.dumps(payload))
    real_call_command = call_command

    def setup_command(name, *args, **kwargs):
        if name == 'create_builtin_groups':
            real_call_command(name, verbosity=0)

    # Keep the real transaction, administrator, and backend writes; stub provider/TLS I/O.
    monkeypatch.setattr(apply_bootstrap_config, 'call_command', setup_command)
    monkeypatch.setattr(
        apply_bootstrap_config.OperationalBootstrapApplier,
        '_probe_and_record_crypto_capabilities',
        Mock(),
    )
    monkeypatch.setattr(
        apply_bootstrap_config.OperationalBootstrapApplier,
        '_apply_staged_tls_credential',
        Mock(side_effect=ValidationError('TLS rejected') if failed_apply else None),
    )
    if failed_apply:
        with pytest.raises(CommandError, match='TLS rejected'):
            apply_bootstrap_config.Command().handle(config=str(path))
        assert not AppVersion.objects.exists()
        assert not get_user_model().objects.filter(username='interrupted-admin').exists()
        return

    monkeypatch.setattr(config, 'save', Mock(side_effect=OSError('bootstrap disk full')))
    with pytest.raises(OSError, match='bootstrap disk full'):
        apply_bootstrap_config.Command().handle(config=str(path))
        config.operational_config_applied = True
        config.save(update_fields=['operational_config_applied'])

    assert not SetupWizardConfigModel.get_singleton().operational_config_applied
    version = AppVersion.objects.get(pk=1)
    assert version.version == settings.APP_VERSION
    backend = AppSecretBackendModel.objects.get()
    snapshot = OperationalStateSnapshot(
        app_version=version.version,
        setup_completed=True,
        crypto_backend_kind=CryptoProviderProfileModel.objects.get(active=True).backend_kind,
        app_secret_backend_kind=backend.backend_kind,
        app_secret_material_present=backend.dek_initialized,
    )
    view = ConnectExistingSummaryView()
    target = view._build_target(config)
    report = OperationalAttachmentValidator(current_version=settings.APP_VERSION).build_report(
        mode=view.attach_mode,
        target=target,
        snapshot=snapshot,
    )
    assert report.can_apply, report.checks
    with pytest.raises(CommandError, match='Connect Existing'):
        apply_bootstrap_config.Command().handle(config=str(tmp_path / 'must-not-be-read'))
    assert get_user_model().objects.get(username='interrupted-admin').password == 'staged-password-hash'


@pytest.mark.parametrize('enforce', [False, True])
def test_attach_validates_crypto_and_app_secret_backends_independently(enforce):
    config = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_enforce_app_secret_protection=enforce,
    )
    view = ConnectExistingSummaryView()
    target = view._build_target(config)
    expected = 'pkcs11' if enforce else 'software'
    assert target.crypto_backend.backend_kind == 'pkcs11'
    assert target.app_secret_backend.backend_kind == expected
    snapshot = OperationalStateSnapshot(
        app_version=settings.APP_VERSION,
        setup_completed=True,
        crypto_backend_kind='pkcs11',
        app_secret_backend_kind=expected,
        app_secret_material_present=True,
    )
    report = OperationalAttachmentValidator(current_version=settings.APP_VERSION).build_report(
        mode=view.attach_mode,
        target=target,
        snapshot=snapshot,
    )
    assert report.can_apply, report.checks


@pytest.mark.parametrize('failure', [False, True])
def test_auto_setup_finalization_preserves_retry_state_until_ready(monkeypatch, tmp_path, failure):
    ready = tmp_path / 'operational.ready'
    marker = tmp_path / 'auto-setup.marker'
    marker.touch()
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_READY_FILE', str(ready))
    real_path = Path
    monkeypatch.setattr(
        finalize_setup,
        'Path',
        lambda value: marker if str(value).endswith('auto-setup.marker') else real_path(value),
    )
    if failure:
        monkeypatch.setattr(finalize_setup, 'write_operational_ready_file', Mock(side_effect=OSError('disk full')))
        with pytest.raises(OSError, match='disk full'):
            finalize_setup.Command().handle()
        assert marker.exists()
        assert not ready.exists()
    else:
        finalize_setup.Command().handle()
        assert ready.read_text() == 'ready\n'
        assert stat.S_IMODE(ready.stat().st_mode) == 0o600
        assert not marker.exists()


@pytest.mark.parametrize(
    'probe',
    [
        pkcs11_probe.probe_staged_pkcs11_config_isolated,
        pkcs11_probe.validate_staged_pkcs11_app_secret_protection_isolated,
    ],
)
def test_stuck_provider_becomes_a_validation_error(monkeypatch, probe):
    runner = Mock(side_effect=subprocess.TimeoutExpired('probe', 30))
    monkeypatch.setattr(pkcs11_probe.subprocess, 'run', runner)
    config = Mock()
    with pytest.raises(ValidationError, match='timed out'):
        probe(config, profile_name='test-profile')
    assert runner.call_args.kwargs['timeout'] == pkcs11_probe.PKCS11_PROBE_TIMEOUT_SECONDS
    config.refresh_from_db.assert_not_called()


def test_probe_timeout_kills_a_real_stuck_child(monkeypatch):
    monkeypatch.setattr(pkcs11_probe, 'PKCS11_PROBE_TIMEOUT_SECONDS', 0.05)
    with pytest.raises(ValidationError, match='timed out'):
        pkcs11_probe._run_isolated_probe([sys.executable, '-c', 'import time; time.sleep(30)'])


def test_staged_credentials_survive_a_new_application_process(tmp_path):
    root = Path(__file__).resolve().parents[3]
    bootstrap = tmp_path / 'persistent-bootstrap'
    env = {
        **os.environ,
        'DJANGO_SETTINGS_MODULE': 'trustpoint.settings_bootstrap',
        'TRUSTPOINT_BOOTSTRAP_DB_PATH': str(bootstrap / 'bootstrap.sqlite3'),
    }
    imports = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(root / 'trustpoint')!r})
import django
django.setup()
from setup_wizard.tls_credential import TLS_STAGING_ROOT, TlsServerCredentialGenerator, load_staged_tls_credential, stage_tls_credential
from setup_wizard.views import stage_pkcs11_user_pin
assert TLS_STAGING_ROOT.is_relative_to(Path({str(bootstrap)!r}))
"""
    create = (
        imports
        + """
stage_tls_credential(TlsServerCredentialGenerator(ipv4_addresses=[], ipv6_addresses=[], domain_names=['localhost']).generate_tls_server_credential())
print(stage_pkcs11_user_pin('original-pin'))
"""
    )
    result = subprocess.run(
        [sys.executable, '-c', create],
        env=env,
        text=True,
        capture_output=True,
        check=True,
        timeout=15,
    )
    pin = result.stdout.strip().splitlines()[-1]
    verify = (
        imports
        + f"""
assert load_staged_tls_credential() is not None
pin = Path({pin!r})
assert pin.is_relative_to(Path({str(bootstrap)!r}))
assert pin.read_text() == 'original-pin'
assert pin.stat().st_mode & 0o777 == 0o600
"""
    )
    subprocess.run([sys.executable, '-c', verify], cwd=tmp_path, env=env, check=True, capture_output=True, timeout=15)
