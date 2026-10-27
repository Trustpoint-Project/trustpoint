# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise the standalone root boundary without requiring a running container."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

RUNTIME_PATH = Path(__file__).resolve().parents[3] / 'docker' / 'trustpoint' / 'runtime_config.py'
spec = importlib.util.spec_from_file_location('trustpoint_runtime_config', RUNTIME_PATH)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def test_shell_substitutions_are_literal_data(tmp_path):
    marker = tmp_path / 'must-not-exist'
    value = f'$(touch {marker}) `touch {marker}`; echo injected'
    data = json.dumps({'DATABASE_HOST': value, 'DATABASE_PORT': '5432'})
    assert runtime.parse_handoff(data)['DATABASE_HOST'] == value
    assert not marker.exists()


@pytest.mark.parametrize(
    'text',
    [
        'export DATABASE_HOST=postgres; touch /tmp/injected',
        'export DATABASE_HOST=postgres\nid',
        'export DATABASE_HOST="unterminated',
        '{"DATABASE_HOST": "a", "DATABASE_HOST": "b"}',
        '{"DATABASE_HOST": 42}',
        '{"DATABASE_HOST": null}',
        '[]',
        '{"PATH": "/tmp/bin"}',
        '{"BASH_ENV": "/tmp/payload"}',
        '{"LD_PRELOAD": "/tmp/payload.so"}',
        '{"PYTHONPATH": "/tmp/payload"}',
        '{"DJANGO_SETTINGS_MODULE": "attacker.settings"}',
        '{"TRUSTPOINT_PHASE": "bootstrap"}',
        '{"DATABASE_PORT": "5432;id"}',
        '{"DATABASE_PORT": "0"}',
        '{"DATABASE_PORT": "65536"}',
        '{"DATABASE_PORT": "５４３２"}',
        '{"DATABASE_HOST": "bad\\u0000value"}',
    ],
)
def test_invalid_or_executable_configuration_is_rejected(text):
    with pytest.raises((ValueError, TypeError)):
        runtime.parse_handoff(text)


@pytest.mark.parametrize(
    'text',
    [
        'DATABASE_HOST=postgres\nDATABASE_PORT=5432\n',
        'export DATABASE_HOST=postgres\nexport DATABASE_PORT=5432\n',
        '# Existing installation\nDATABASE_HOST=postgres\n',
        '',
    ],
)
def test_shell_format_handoffs_are_rejected(text):
    with pytest.raises(ValueError):
        runtime.parse_handoff(text)


def test_password_is_not_allowed_in_handoff():
    with pytest.raises(ValueError, match='unsupported setting'):
        runtime.parse_handoff(json.dumps({'DATABASE_PASSWORD': 'deployment secret'}))


@pytest.mark.parametrize('provider', ['PATH', 'HOME', 'LD_PRELOAD', 'PYTHONPATH', 'BASH_ENV', 'TRUSTPOINT_HSM_ROOT'])
def test_custom_provider_variable_cannot_enable_arbitrary_environment_keys(provider):
    with pytest.raises(ValueError):
        runtime.parse_handoff(json.dumps({'TRUSTPOINT_PKCS11_CONFIG_ENV_VAR': provider, provider: '/tmp/payload'}))


@pytest.mark.parametrize('provider', ['SOFTHSM2_CONF', 'VENDOR_CONFIG'])
def test_provider_configuration_environment_is_supported(provider):
    data = {'TRUSTPOINT_PKCS11_CONFIG_ENV_VAR': provider, provider: '/var/lib/trustpoint/hsm/config/provider.cfg'}
    assert runtime.parse_handoff(json.dumps(data)) == data


def test_handoff_settings_do_not_change_root_paths_or_process_configuration(monkeypatch):
    deployment = {**runtime.DEPLOYMENT_DEFAULTS, 'TRUSTPOINT_HSM_CONFIG_DIR': '/protected/hsm'}
    handoff = {
        'TRUSTPOINT_HSM_CONFIG_DIR': '/etc',
        'TRUSTPOINT_HSM_ROOT': '/root',
        'DATABASE_HOST': "postgres'; touch /tmp/payload; #",
        'DATABASE_PORT': '5432',
    }
    monkeypatch.setenv('TRUSTPOINT_HSM_CONFIG_DIR', '/attacker-controlled')
    monkeypatch.setenv('BASH_ENV', '/tmp/payload')
    monkeypatch.setenv('LD_PRELOAD', '/tmp/payload.so')
    monkeypatch.setenv('PYTHONPATH', '/tmp/payload')
    monkeypatch.setenv('WWW_DATA_HOME', '/etc')
    monkeypatch.setenv('DATABASE_PASSWORD', 'external-credential')
    environment = runtime.root_environment(deployment, handoff)
    assert environment['TRUSTPOINT_HSM_CONFIG_DIR'] == '/protected/hsm'
    assert environment['TRUSTPOINT_HSM_ROOT'] == '/var/lib/trustpoint/hsm'
    assert environment['WWW_DATA_HOME'] == '/run/trustpoint/home'
    assert 'DATABASE_HOST' not in environment
    assert environment['DATABASE_PASSWORD'] == 'external-credential'
    assert environment['PATH'] == runtime.SAFE_PATH
    assert not {'BASH_ENV', 'LD_PRELOAD', 'PYTHONPATH'} & environment.keys()
    assert json.loads(environment[runtime.APP_ENV_KEY]) == handoff


def test_configuration_symlinks_are_rejected(tmp_path):
    original = tmp_path / 'original'
    original.write_text('{"DATABASE_HOST": "postgres"}')
    link = tmp_path / 'link'
    link.symlink_to(original)
    with pytest.raises(OSError):
        runtime.read_configuration(link)


def test_non_regular_configuration_is_rejected_without_blocking(tmp_path):
    pipe = tmp_path / 'pipe'
    os.mkfifo(pipe)
    with pytest.raises(ValueError, match='regular file'):
        runtime.read_configuration(pipe)


def test_world_writable_deployment_settings_are_rejected(tmp_path):
    path = tmp_path / 'deployment.json'
    path.write_text('{}')
    path.chmod(0o666)
    with pytest.raises(ValueError, match='root-owned'):
        runtime.read_configuration(path, root_owned=True)


def test_oversized_handoff_is_rejected(tmp_path):
    text = json.dumps({'DATABASE_HOST': 'a' * runtime.MAX_CONFIG_BYTES})
    with pytest.raises(ValueError, match='size limit'):
        runtime.parse_handoff(text)
    path = tmp_path / 'oversized'
    path.write_text(text)
    with pytest.raises(ValueError, match='size limit'):
        runtime.read_configuration(path)
