# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise handoff files and failure recovery without starting an operational runtime."""

import json
import shlex
import stat
import subprocess
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
def config():
    """Use an unsaved config so tests cannot change real operational state."""
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
    assert values['DATABASE_PASSWORD'] == 'test password'
    assert values['DATABASE_PORT'] == '5432'
    assert values['TRUSTPOINT_PHASE'] == 'operational'
    assert values['EMAIL_HOST'] == 'mail.test'
    assert values['VENDOR_CONFIG'] == str(handoff.FINAL_WIZARD_PKCS11_CONFIG_PATH)
    assert 'UNRELATED_SECRET' not in values


def test_env_file_quotes_shell_metacharacters_and_is_private(tmp_path):
    path = tmp_path / 'nested' / 'operational.env'
    values = {'PASSWORD': "a b'c;$HOME\nsecond line", 'HOST': 'postgres'}
    handoff.write_operational_env_file(values, path)
    assignments = shlex.split(path.read_text(), comments=True)
    assert assignments == ['export', 'HOST=postgres', 'export', f'PASSWORD={values["PASSWORD"]}']
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize('same_path', [False, True])
def test_promote_env_preserves_contents_and_private_permissions(tmp_path, same_path):
    source = tmp_path / 'pending.env'
    source.write_text('export HOST=postgres\n')
    final = source if same_path else tmp_path / 'final' / 'operational.env'
    handoff.promote_operational_env_file(source, final)
    assert final.read_text() == 'export HOST=postgres\n'
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
    pending.write_text('export HOST=postgres\n')
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, ' started \n', ''))
    monkeypatch.setattr(handoff.subprocess, 'run', runner)
    result = handoff.run_operational_runtime_switch(pending if explicit else None)
    assert result.switched is True
    assert result.detail == 'started'
    assert runner.call_args.args[0] == [handoff.SUDO_EXECUTABLE, str(switch_script), str(pending)]
    assert not pending.exists()
    assert handoff.operational_env_file_path().read_text() == 'export HOST=postgres\n'
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
