# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise handoff files and failure recovery without starting an operational runtime."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from django.core.exceptions import ValidationError

from setup_wizard import operational_handoff as handoff
from setup_wizard.models import SetupWizardConfigModel


@pytest.fixture
def handoff_paths(monkeypatch, tmp_path):
    """Keep all persisted handoff state inside a temporary directory."""
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_ENV_FILE', str(tmp_path / 'operational.env'))
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_READY_FILE', str(tmp_path / 'operational.ready'))
    return tmp_path


@pytest.fixture
def config(monkeypatch):
    """Use an unsaved config so tests cannot change real operational state."""
    monkeypatch.setenv('DATABASE_PASSWORD', 'test password')
    monkeypatch.delenv('DATABASE_PASSWORD_FILE', raising=False)
    return SetupWizardConfigModel(
        operational_db_host='postgres',
        operational_db_name='testdb',
        operational_db_user='testuser',
        operational_db_password='test password',
        operational_admin_username='operator',
        operational_admin_password_hash='already-hashed',
    )


@pytest.mark.parametrize('docker', [False, True])
def test_default_env_path_uses_runtime_mode(monkeypatch, settings, docker):
    monkeypatch.delenv('TRUSTPOINT_OPERATIONAL_ENV_FILE', raising=False)
    settings.DOCKER_CONTAINER = docker
    expected = handoff.DEFAULT_CONTAINER_OPERATIONAL_ENV_FILE if docker else handoff.DEFAULT_LOCAL_OPERATIONAL_ENV_FILE
    assert handoff.operational_env_file_path() == expected


def test_related_paths_follow_custom_env_location(monkeypatch, handoff_paths):
    monkeypatch.delenv('TRUSTPOINT_OPERATIONAL_READY_FILE')
    assert handoff.pending_operational_env_file_path() == handoff_paths / 'operational.pending.env'
    assert handoff.operational_ready_file_path() == handoff_paths / 'operational.ready'
    assert handoff.operational_payload_file_path() == handoff_paths / 'bootstrap-apply.json'


def test_environment_preserves_allowed_values_and_rewrites_uploaded_config(monkeypatch, config):
    monkeypatch.setenv('EMAIL_HOST', 'mail.test')
    monkeypatch.setenv('UNRELATED_SECRET', 'excluded')
    config.fresh_install_pkcs11_config_env_var = 'VENDOR_CONFIG'
    config.fresh_install_pkcs11_config_path = '/temporary/upload.cfg'
    values = handoff.build_operational_environment(config)
    assert 'DATABASE_PASSWORD' not in values
    assert values['DATABASE_PORT'] == '5432'
    assert values['TRUSTPOINT_PHASE'] == 'operational'
    assert values['EMAIL_HOST'] == 'mail.test'
    assert values['VENDOR_CONFIG'] == str(handoff.FINAL_WIZARD_PKCS11_CONFIG_PATH)
    assert 'UNRELATED_SECRET' not in values


def test_env_file_preserves_shell_metacharacters_as_json_data_and_is_private(tmp_path):
    path = tmp_path / 'nested' / 'operational.env'
    values = {'PASSWORD': "a b'c;$HOME\nsecond line", 'HOST': 'postgres'}
    handoff.write_operational_env_file(values, path)
    assert json.loads(path.read_text()) == values
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize('same_path', [False, True])
def test_promote_env_preserves_contents_and_private_permissions(tmp_path, same_path):
    source = tmp_path / 'pending.env'
    source.write_text('{"DATABASE_HOST": "postgres"}\n')
    final = source if same_path else tmp_path / 'final' / 'operational.env'
    handoff.promote_operational_env_file(source, final)
    assert final.read_text() == '{"DATABASE_HOST": "postgres"}\n'
    assert stat.S_IMODE(final.stat().st_mode) == 0o600
    if not same_path:
        assert not source.exists()


def test_fresh_handoff_prepares_pending_state_without_marking_ready(monkeypatch, handoff_paths, config):
    ready = handoff_paths / 'operational.ready'
    ready.write_text('stale')
    commands = []

    def run(args, env):
        assert not ready.exists()
        assert not handoff.pending_operational_env_file_path().exists()
        assert env['POSTGRES_DB'] == 'testdb'
        commands.append(args)

    monkeypatch.setattr(handoff, '_run_operational_manage_command', run)
    result = handoff.run_operational_handoff(config)
    assert commands == [
        ['migrate', '--noinput'],
        ['apply_bootstrap_config', '--config', str(result.payload_file)],
    ]
    payload = json.loads(result.payload_file.read_text())
    assert payload['admin']['password_hash'] == 'already-hashed'
    assert 'password' not in payload['database']
    assert stat.S_IMODE(result.payload_file.stat().st_mode) == 0o600
    assert result.pending_env_file.is_file()
    assert not result.env_file.exists()
    assert not result.ready_file.exists()


@pytest.mark.parametrize('failed_command', ['migrate', 'apply_bootstrap_config'])
def test_failed_apply_never_publishes_ready_or_final_env(monkeypatch, handoff_paths, config, failed_command):
    ready = handoff_paths / 'operational.ready'
    ready.write_text('stale')

    def run(args, env):
        if args[0] == failed_command:
            raise ValidationError('apply failed')

    monkeypatch.setattr(handoff, '_run_operational_manage_command', run)
    with pytest.raises(ValidationError, match='apply failed'):
        handoff.run_operational_handoff(config)
    assert not ready.exists()
    assert not handoff.operational_env_file_path().exists()
    assert not handoff.pending_operational_env_file_path().exists()


def test_attach_handoff_does_not_modify_existing_database(monkeypatch, handoff_paths, config):
    runner = Mock(side_effect=AssertionError('attach must not reapply database state'))
    monkeypatch.setattr(handoff, '_run_operational_manage_command', runner)
    result = handoff.run_operational_attach_handoff(config)
    runner.assert_not_called()
    assert result.pending_env_file.is_file()
    assert not result.payload_file.exists()
    assert not result.ready_file.exists()


@pytest.mark.parametrize('returncode,stdout,stderr', [(0, '', ''), (1, '', ''), (1, 'x' * 5000, 'last error')])
def test_management_command_passes_environment_and_bounds_errors(monkeypatch, returncode, stdout, stderr):
    runner = Mock(return_value=subprocess.CompletedProcess([], returncode, stdout, stderr))
    monkeypatch.setattr(handoff.subprocess, 'run', runner)
    monkeypatch.setenv('HANDOFF_TEST_PARENT', 'preserved')
    if returncode:
        with pytest.raises(ValidationError) as error:
            handoff._run_operational_manage_command(['migrate', '--noinput'], {'TRUSTPOINT_PHASE': 'operational'})
        message = error.value.messages[0]
        assert len(message) < 4100
        assert message.endswith('last error' if stderr else 'no command output')
    else:
        handoff._run_operational_manage_command(['migrate', '--noinput'], {'TRUSTPOINT_PHASE': 'operational'})
    args, kwargs = runner.call_args
    assert args[0][-2:] == ['migrate', '--noinput']
    assert kwargs['env']['TRUSTPOINT_PHASE'] == 'operational'
    assert kwargs['env']['HANDOFF_TEST_PARENT'] == 'preserved'
    assert kwargs['capture_output'] is True


@pytest.fixture
def switch_script(monkeypatch, settings, handoff_paths):
    settings.DOCKER_CONTAINER = True
    script = handoff_paths / 'switch.sh'
    script.touch()
    monkeypatch.setattr(handoff, 'SWITCH_TO_OPERATIONAL_SCRIPT', script)
    return script


def test_runtime_switch_is_unavailable_outside_container(monkeypatch, settings):
    settings.DOCKER_CONTAINER = False
    runner = Mock()
    monkeypatch.setattr(handoff.subprocess, 'run', runner)
    assert handoff.run_operational_runtime_switch().switched is False
    runner.assert_not_called()


def test_missing_runtime_script_fails_before_running_commands(monkeypatch, settings, handoff_paths):
    settings.DOCKER_CONTAINER = True
    monkeypatch.setattr(handoff, 'SWITCH_TO_OPERATIONAL_SCRIPT', handoff_paths / 'missing.sh')
    runner = Mock()
    monkeypatch.setattr(handoff.subprocess, 'run', runner)
    with pytest.raises(ValidationError, match='script is missing'):
        handoff.run_operational_runtime_switch()
    runner.assert_not_called()


@pytest.mark.parametrize('explicit', [False, True])
def test_successful_switch_promotes_pending_env_then_marks_ready(monkeypatch, switch_script, explicit):
    pending = handoff.pending_operational_env_file_path()
    pending.write_text('{"DATABASE_HOST": "postgres"}\n')
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, ' started \n', ''))
    monkeypatch.setattr(handoff.subprocess, 'run', runner)
    result = handoff.run_operational_runtime_switch(pending if explicit else None)
    assert result.switched is True
    assert result.detail == 'started'
    assert runner.call_args.args[0] == [handoff.SUDO_EXECUTABLE, str(switch_script), '--pending']
    assert not pending.exists()
    assert handoff.operational_env_file_path().read_text() == '{"DATABASE_HOST": "postgres"}\n'
    ready = handoff.operational_ready_file_path()
    assert ready.read_text() == 'ready\n'
    assert stat.S_IMODE(ready.stat().st_mode) == 0o600


@pytest.mark.parametrize('stderr', ['', 'x' * 5000 + 'last error'])
def test_failed_runtime_switch_keeps_pending_env_and_no_ready_marker(monkeypatch, switch_script, stderr):
    pending = handoff.pending_operational_env_file_path()
    pending.write_text('pending')
    monkeypatch.setattr(handoff.subprocess, 'run', Mock(return_value=subprocess.CompletedProcess([], 1, '', stderr)))
    with pytest.raises(ValidationError) as error:
        handoff.run_operational_runtime_switch()
    assert len(error.value.messages[0]) < 4100
    assert error.value.messages[0].endswith('last error' if stderr else 'no script output')
    assert pending.read_text() == 'pending'
    assert not handoff.operational_env_file_path().exists()
    assert not handoff.operational_ready_file_path().exists()


def test_marker_write_failure_is_reported_after_successful_switch(monkeypatch, switch_script):
    pending = handoff.pending_operational_env_file_path()
    pending.write_text('pending')
    monkeypatch.setattr(handoff.subprocess, 'run', Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
    monkeypatch.setattr(handoff, 'write_operational_ready_file', Mock(side_effect=OSError('disk full')))
    with pytest.raises(ValidationError, match='final handoff marker could not be written: disk full'):
        handoff.run_operational_runtime_switch()
    assert not handoff.operational_ready_file_path().exists()


def test_mounted_password_is_referenced_without_copying_it(monkeypatch, config, tmp_path):
    secret = tmp_path / 'mounted-secret'
    secret.write_text('test password\n')
    monkeypatch.setenv('DATABASE_PASSWORD_FILE', str(secret))
    monkeypatch.setenv('DATABASE_PASSWORD', 'stale-container-default')
    values = handoff.build_operational_environment(config)
    env_file = tmp_path / 'operational.env'
    handoff.write_operational_env_file(values, env_file)
    assert values['DATABASE_PASSWORD_FILE'] == str(secret)
    assert 'DATABASE_PASSWORD' not in values
    assert 'test password' not in env_file.read_text()
    assert 'stale-container-default' not in env_file.read_text()
    assert secret.read_text() == 'test password\n'


def test_inherited_password_is_not_written_to_handoff(config, tmp_path):
    values = handoff.build_operational_environment(config)
    path = tmp_path / 'operational.env'
    handoff.write_operational_env_file(values, path)
    assert 'test password' not in path.read_text()
    assert 'DATABASE_PASSWORD' not in path.read_text()


@pytest.mark.parametrize('source', ['missing', 'mismatch', 'missing-file', 'file-mismatch'])
def test_invalid_external_credential_fails_before_applying_state(monkeypatch, config, handoff_paths, source):
    monkeypatch.delenv('DATABASE_PASSWORD', raising=False)
    if source == 'mismatch':
        monkeypatch.setenv('DATABASE_PASSWORD', 'different-password')
    elif source in {'missing-file', 'file-mismatch'}:
        secret = handoff_paths / 'mounted-secret'
        if source == 'file-mismatch':
            secret.write_text('different-password')
        monkeypatch.setenv('DATABASE_PASSWORD_FILE', str(secret))
    ready = handoff.operational_ready_file_path()
    ready.write_text('existing ready marker')
    runner = Mock()
    monkeypatch.setattr(handoff, '_run_operational_manage_command', runner)
    with pytest.raises(ValidationError) as error:
        handoff.run_operational_handoff(config)
    assert 'test password' not in str(error.value)
    assert 'different-password' not in str(error.value)
    assert ready.read_text() == 'existing ready marker'
    assert not handoff.operational_payload_file_path().exists()
    assert not handoff.pending_operational_env_file_path().exists()
    runner.assert_not_called()


@pytest.mark.parametrize('key', ['DATABASE_PASSWORD', 'PGPASSWORD'])
def test_env_writer_rejects_plaintext_database_passwords(tmp_path, key):
    path = tmp_path / 'operational.env'
    path.write_text('original configuration')
    with pytest.raises(ValidationError, match='must not be persisted'):
        handoff.write_operational_env_file({key: 'sensitive-value'}, path)
    assert path.read_text() == 'original configuration'


def test_private_permissions_apply_before_atomic_publication(tmp_path, monkeypatch):
    path = tmp_path / 'operational.env'
    path.write_text('original configuration')
    path.chmod(0o644)
    original_replace = Path.replace
    replaced = []

    def inspect_replace(source, destination):
        assert destination == path
        assert stat.S_IMODE(source.stat().st_mode) == 0o600
        assert path.read_text() == 'original configuration'
        replaced.append(source)
        return original_replace(source, destination)

    monkeypatch.setattr(Path, 'replace', inspect_replace)
    handoff.write_operational_env_file({'DATABASE_HOST': 'postgres'}, path)
    assert len(replaced) == 1
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == {'DATABASE_HOST': 'postgres'}


def test_failed_publication_keeps_previous_file_and_cleans_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / 'operational.env'
    path.write_text('original configuration')
    monkeypatch.setattr(Path, 'replace', Mock(side_effect=OSError('disk full')))
    with pytest.raises(OSError, match='disk full'):
        handoff.write_operational_env_file({'DATABASE_HOST': 'postgres'}, path)
    assert path.read_text() == 'original configuration'
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize('mounted_secret', [False, True])
def test_parsed_handoff_loads_database_credential_in_a_fresh_process(monkeypatch, config, tmp_path, mounted_secret):
    """Restarted settings resolve the external credential without a password in the handoff file."""
    if mounted_secret:
        secret = tmp_path / 'mounted-secret'
        secret.write_text('test password\n')
        monkeypatch.setenv('DATABASE_PASSWORD_FILE', str(secret))
        monkeypatch.setenv('DATABASE_PASSWORD', 'stale-default')
    env_file = tmp_path / 'operational.env'
    handoff.write_operational_env_file(handoff.build_operational_environment(config), env_file)
    assert 'test password' not in env_file.read_text()
    source = """
import os
import runpy
import sys
runtime = runpy.run_path(sys.argv[1])
os.environ.update(runtime['parse_handoff'](open(sys.argv[2]).read()))
from trustpoint import settings
assert settings.DATABASE_PASSWORD == 'test password'
assert settings.DATABASES['default']['PASSWORD'] == 'test password'
assert settings.DATABASES['default']['HOST'] == 'postgres'
"""
    subprocess.run(
        [
            sys.executable,
            '-c',
            source,
            str(handoff.settings.REPO_ROOT / 'docker/trustpoint/runtime_config.py'),
            str(env_file),
        ],
        env={**os.environ, 'PYTHONPATH': str(handoff.settings.BASE_DIR)},
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )


def test_runtime_switch_rejects_arbitrary_handoff_paths(monkeypatch, switch_script, tmp_path):
    runner = Mock()
    monkeypatch.setattr(handoff.subprocess, 'run', runner)
    with pytest.raises(ValidationError, match='only the configured pending or final'):
        handoff.run_operational_runtime_switch(tmp_path / 'arbitrary.env')
    runner.assert_not_called()


def test_auto_setup_uses_the_same_non_executable_handoff_writer(monkeypatch, settings, config, tmp_path):
    from management.management.commands import bootstrap_manager

    config.save()
    settings.TRUSTPOINT_IS_OPERATIONAL = False
    monkeypatch.setenv('TP_AUTO_SETUP', 'true')
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_ENV_FILE', str(tmp_path / 'operational.env'))
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_READY_FILE', str(tmp_path / 'operational.ready'))
    monkeypatch.setattr(bootstrap_manager.SetupWizardCompletedModel, 'setup_wizard_completed', lambda: False)
    original_path = Path
    monkeypatch.setattr(
        bootstrap_manager,
        'Path',
        lambda value: (
            tmp_path / 'auto-setup.marker' if str(value).endswith('/auto-setup.marker') else original_path(value)
        ),
    )
    bootstrap_manager.Command._trigger_auto_setup_if_requested(Mock())
    values = json.loads((tmp_path / 'operational.env').read_text())
    assert values['DATABASE_HOST'] == 'postgres'
    assert 'DATABASE_PASSWORD' not in values
    assert (tmp_path / 'auto-setup.marker').is_file()


@pytest.mark.parametrize('credential_source', ['environment', 'file'])
def test_fresh_bootstrap_seeds_database_before_auto_setup(monkeypatch, settings, handoff_paths, credential_source):
    from management.management.commands import bootstrap_manager

    settings.TRUSTPOINT_IS_BOOTSTRAP = True
    settings.TRUSTPOINT_IS_OPERATIONAL = False
    settings.DATABASE_PASSWORD = 'deployment-test-secret'
    settings.DATABASE_USER = 'deployment_user'
    settings.APP_VERSION = '1.0.0'
    monkeypatch.setenv('TP_AUTO_SETUP', 'true')
    monkeypatch.setenv('DATABASE_HOST', 'deployment-postgres')
    monkeypatch.setenv('DATABASE_PORT', '5433')
    monkeypatch.setenv('POSTGRES_DB', 'deployment_db')
    monkeypatch.setenv('DATABASE_USER', 'deployment_user')
    monkeypatch.delenv('DATABASE_PASSWORD_FILE', raising=False)
    if credential_source == 'file':
        secret = handoff_paths / 'database-secret'
        secret.write_text('deployment-test-secret\n')
        monkeypatch.setenv('DATABASE_PASSWORD_FILE', str(secret))
        monkeypatch.delenv('DATABASE_PASSWORD', raising=False)
    else:
        monkeypatch.setenv('DATABASE_PASSWORD', 'deployment-test-secret')

    # Leave seeding and handoff creation real, starting with a fresh wizard row.
    config = SetupWizardConfigModel.get_singleton()
    assert config.operational_db_password == ''
    for method in ('_prepare_bootstrap_database', '_create_bootstrap_login', '_collect_static_files', '_compile_messages'):
        monkeypatch.setattr(bootstrap_manager.Command, method, Mock())
    monkeypatch.setattr(bootstrap_manager.Command, '_has_staged_tls', Mock(return_value=False))
    monkeypatch.setattr(bootstrap_manager.BootstrapTlsMaterialStrategy, 'apply', Mock())
    original_path = Path
    monkeypatch.setattr(
        bootstrap_manager,
        'Path',
        lambda value: (
            handoff_paths / 'auto-setup.marker' if str(value).endswith('/auto-setup.marker') else original_path(value)
        ),
    )

    bootstrap_manager.Command().handle()

    config.refresh_from_db()
    assert config.operational_db_password == 'deployment-test-secret'
    values = json.loads((handoff_paths / 'operational.env').read_text())
    assert values['DATABASE_HOST'] == 'deployment-postgres'
    assert values['DATABASE_PORT'] == '5433'
    assert values['POSTGRES_DB'] == 'deployment_db'
    assert values['DATABASE_USER'] == 'deployment_user'
    assert 'DATABASE_PASSWORD' not in values
    assert 'deployment-test-secret' not in (handoff_paths / 'operational.env').read_text()
    if credential_source == 'file':
        assert values['DATABASE_PASSWORD_FILE'] == str(secret)
    assert (handoff_paths / 'operational.ready').exists()
    assert (handoff_paths / 'auto-setup.marker').exists()
