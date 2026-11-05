# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Read wizard data without shell evaluation at the container privilege boundary.

Install this standalone, standard-library-only program under /etc/trustpoint,
owned by root. Always invoke it with the system Python in isolated mode (-I).
"""
# ruff: noqa: INP001 - standalone root-owned container entry point, not an import package.

from __future__ import annotations

import json
import os
import pwd
import re
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

APP_DIR = Path('/var/www/html/trustpoint')
INSTALL_DIR = Path('/etc/trustpoint')
DEPLOYMENT_FILE = Path('/run/trustpoint/deployment.json')
MAX_CONFIG_BYTES = 65536
MAX_TCP_PORT = 65535
OPERATION_ARGUMENT_COUNT = 2
SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
APP_ENV_KEY = '_TRUSTPOINT_APPLICATION_ENV'
APP_BASE_KEY = 'TRUSTPOINT_APPLICATION_ENV'

HANDOFF_KEYS = frozenset(
    {
        'DJANGO_SETTINGS_MODULE',
        'TRUSTPOINT_PHASE',
        'TRUSTPOINT_OPERATIONAL_DATABASE',
        'DATABASE_ENGINE',
        'DATABASE_HOST',
        'DATABASE_PORT',
        'POSTGRES_DB',
        'DATABASE_USER',
        'DATABASE_PASSWORD_FILE',
        'PKCS11_PROXY_SOCKET',
        'SOFTHSM2_CONF',
        'TRUSTPOINT_HSM_ROOT',
        'TRUSTPOINT_HSM_CONFIG_DIR',
        'TRUSTPOINT_HSM_LIB_DIR',
        'TRUSTPOINT_HSM_DEFAULT_PKCS11_MODULE_PATH',
        'TRUSTPOINT_HSM_DEFAULT_USER_PIN_FILE',
        'TRUSTPOINT_HSM_DEFAULT_TOKEN_LABEL',
        'TRUSTPOINT_LOCAL_HSM_ENABLED',
        'TRUSTPOINT_LOCAL_HSM_MODULE_PATH',
        'TRUSTPOINT_LOCAL_HSM_TOKEN_LABEL',
        'TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL',
        'TRUSTPOINT_LOCAL_HSM_PROFILE_NAME',
        'TRUSTPOINT_LOCAL_HSM_USER_PIN_FILE',
        'TRUSTPOINT_LOCAL_HSM_PROXY_SOCKET',
        'TRUSTPOINT_LOCAL_HSM_CONFIG_ENV_VAR',
        'TRUSTPOINT_LOCAL_HSM_SOFTHSM2_CONF',
        'TRUSTPOINT_PKCS11_CONFIG_ENV_VAR',
        'EMAIL_HOST',
        'EMAIL_PORT',
        'EMAIL_USE_TLS',
        'EMAIL_USE_SSL',
        'DEFAULT_FROM_EMAIL',
    }
)
DEPLOYMENT_DEFAULTS = {
    'TRUSTPOINT_OPERATIONAL_ENV_FILE': '/var/lib/trustpoint/bootstrap/operational.env',
    'TRUSTPOINT_OPERATIONAL_READY_FILE': '/var/lib/trustpoint/bootstrap/operational.ready',
    'TRUSTPOINT_OPERATIONAL_GUNICORN_PORT': '8001',
    'TRUSTPOINT_BOOTSTRAP_GUNICORN_PORT': '8000',
    'TRUSTPOINT_HSM_ROOT': '/var/lib/trustpoint/hsm',
    'TRUSTPOINT_BOOTSTRAP_DB_PATH': '/var/lib/trustpoint/bootstrap/bootstrap.sqlite3',
    'TRUSTPOINT_SERVICE_ROLE': 'web',
    'UV_CACHE_DIR': '/run/trustpoint/uv-cache',
    'UV_NO_CACHE': '1',
    'WWW_DATA_HOME': '/run/trustpoint/home',
}
DEPLOYMENT_KEYS = frozenset(DEPLOYMENT_DEFAULTS) | (
    HANDOFF_KEYS
    - {
        'DATABASE_PASSWORD',
        'DATABASE_PASSWORD_FILE',
        'DJANGO_SETTINGS_MODULE',
        'TRUSTPOINT_PHASE',
        'TRUSTPOINT_PKCS11_CONFIG_ENV_VAR',
    }
)
PRIVILEGED_SCRIPTS = frozenset(
    {
        'update_tls.sh',
        'update_tls_nginx.sh',
        'install_pkcs11_assets.sh',
        'wizard_restore.sh',
    }
)


def _string_mapping(pairs: Sequence[tuple[str, object]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result or not isinstance(value, str) or '\0' in key or '\0' in value:
            msg = 'Configuration must contain unique string assignments.'
            raise ValueError(msg)
        result[key] = value
    return result


def _port(value: str) -> None:
    if not value.isascii() or not value.isdecimal() or not 0 < int(value) <= MAX_TCP_PORT:
        msg = 'Invalid configured TCP port.'
        raise ValueError(msg)


def _validate_provider_key(provider_key: str) -> None:
    if not provider_key or provider_key in {'SOFTHSM2_CONF', 'PKCS11_PROXY_SOCKET'}:
        return
    if (
        not re.fullmatch(r'[A-Z][A-Z0-9_]*', provider_key)
        or provider_key.startswith(('LD_', 'PYTHON', 'BASH', 'DYLD_', 'TRUSTPOINT_'))
        or provider_key in HANDOFF_KEYS | {'PATH', 'HOME', 'ENV', 'IFS', 'SHELLOPTS', APP_ENV_KEY}
    ):
        msg = 'Invalid PKCS#11 provider environment variable.'
        raise ValueError(msg)


def parse_handoff(text: str) -> dict[str, str]:
    """Parse an allowlisted JSON object; never expand or execute values."""
    if len(text.encode('utf-8')) > MAX_CONFIG_BYTES:
        msg = 'Operational configuration exceeds the size limit.'
        raise ValueError(msg)
    values = json.loads(text, object_pairs_hook=_string_mapping)
    if not isinstance(values, dict):
        msg = 'Operational configuration must be an object.'
        raise TypeError(msg)
    values = _string_mapping(list(values.items()))
    provider_key = values.get('TRUSTPOINT_PKCS11_CONFIG_ENV_VAR', '')
    _validate_provider_key(provider_key)
    allowed = HANDOFF_KEYS | ({provider_key} if provider_key else set())
    if values.keys() - allowed:
        msg = 'Operational configuration contains an unsupported setting.'
        raise ValueError(msg)
    for key, expected in {
        'DJANGO_SETTINGS_MODULE': 'trustpoint.settings',
        'TRUSTPOINT_PHASE': 'operational',
        'TRUSTPOINT_OPERATIONAL_DATABASE': 'postgresql',
        'DATABASE_ENGINE': 'django.db.backends.postgresql',
    }.items():
        if key in values and values[key] != expected:
            msg = 'Operational configuration contains an invalid runtime setting.'
            raise ValueError(msg)
    if 'DATABASE_PORT' in values:
        _port(values['DATABASE_PORT'])
    return values


def read_configuration(path: Path, *, root_owned: bool = False) -> str:
    """Read a bounded regular file without following a final symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            msg = 'Configuration must be a regular file.'
            raise ValueError(msg)
        if root_owned and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
            msg = 'Deployment configuration must be root-owned and not writable by other users.'
            raise ValueError(msg)
        text = stream.read(MAX_CONFIG_BYTES + 1)
    if len(text.encode('utf-8')) > MAX_CONFIG_BYTES:
        msg = 'Configuration exceeds the size limit.'
        raise ValueError(msg)
    return text


def initialize_deployment() -> dict[str, str]:
    """Snapshot non-secret deployment settings before any web process starts."""
    values = {**DEPLOYMENT_DEFAULTS, **{key: os.environ[key] for key in DEPLOYMENT_KEYS if key in os.environ}}
    for key in ('TRUSTPOINT_OPERATIONAL_GUNICORN_PORT', 'TRUSTPOINT_BOOTSTRAP_GUNICORN_PORT'):
        _port(values[key])
    DEPLOYMENT_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = DEPLOYMENT_FILE.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        msg = 'Deployment directory must be controlled by root.'
        raise ValueError(msg)
    DEPLOYMENT_FILE.parent.chmod(0o755)
    account = pwd.getpwnam('www-data')
    for key in ('WWW_DATA_HOME', 'UV_CACHE_DIR'):
        path = Path(values[key])
        parent = path.parent.stat()
        if parent.st_uid != 0 or parent.st_mode & 0o022 or path.is_symlink():
            msg = 'Application cache/home directories require a root-controlled parent.'
            raise ValueError(msg)
        if path.exists():
            if not path.is_dir() or path.stat().st_uid != account.pw_uid:
                msg = 'Existing application cache/home directories must belong to www-data.'
                raise ValueError(msg)
        else:
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
    descriptor = os.open(DEPLOYMENT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(values, stream)
    return values


def load_deployment() -> dict[str, str]:
    """Load the root-owned settings; sudo callers cannot replace them via environment."""
    values: dict[str, str] = json.loads(
        read_configuration(DEPLOYMENT_FILE, root_owned=True), object_pairs_hook=_string_mapping
    )
    if values.keys() - DEPLOYMENT_KEYS:
        msg = 'Unsupported deployment setting.'
        raise ValueError(msg)
    for key in ('TRUSTPOINT_OPERATIONAL_GUNICORN_PORT', 'TRUSTPOINT_BOOTSTRAP_GUNICORN_PORT'):
        _port(values[key])
    return values


def root_environment(deployment: dict[str, str], handoff: dict[str, str]) -> dict[str, str]:
    """Keep all wizard values out of the environment used by root."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.startswith('TP_')
        or key
        in {
            'DATABASE_PASSWORD',
            'DATABASE_PASSWORD_FILE',
            'WORKFLOWS2_WORKER_ID',
            'WORKFLOWS2_WORKER_LEASE',
            'WORKFLOWS2_WORKER_BATCH',
            'WORKFLOWS2_WORKER_SLEEP',
        }
    }
    # sudo retains only explicit application credentials; root controls these paths.
    environment.update(deployment)
    environment['PATH'] = SAFE_PATH
    environment['HOME'] = '/root'
    environment['LANG'] = 'C.UTF-8'
    environment['LC_ALL'] = 'C.UTF-8'
    # Opaque application data: never merge it into an environment used by root.
    environment[APP_BASE_KEY] = os.environ.get(APP_BASE_KEY, json.dumps(dict(os.environ)))
    environment[APP_ENV_KEY] = json.dumps(handoff)
    return environment


def _exec_script(name: str, arguments: list[str], environment: dict[str, str]) -> None:
    path = INSTALL_DIR / name
    if name == 'entrypoint.sh':
        environment['_TRUSTPOINT_VALIDATED'] = '1'
        arguments = ['--validated', *arguments]
    os.execve(  # noqa: S606 - fixed root-owned shell and script, arguments are data.
        '/bin/bash',
        ['/bin/bash', '--noprofile', '--norc', str(path), *arguments],
        environment,
    )


def run_application(job: str) -> None:
    """Drop all root identities before applying wizard environment or executing application code."""
    handoff = parse_handoff(os.environ.get(APP_ENV_KEY, '{}'))
    account = pwd.getpwnam('www-data')
    if os.geteuid() == 0:
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    if os.geteuid() != account.pw_uid:
        msg = 'Application commands must run as www-data.'
        raise ValueError(msg)
    base_text = os.environ.get(APP_BASE_KEY, '{}')
    if len(base_text.encode('utf-8')) > MAX_CONFIG_BYTES:
        msg = 'Application environment exceeds the size limit.'
        raise ValueError(msg)
    base = json.loads(base_text, object_pairs_hook=_string_mapping)
    if not isinstance(base, dict):
        msg = 'Application environment must be an object.'
        raise TypeError(msg)
    environment = {**os.environ, **base}
    environment.pop(APP_ENV_KEY, None)
    environment.pop(APP_BASE_KEY, None)
    environment.pop('_TRUSTPOINT_VALIDATED', None)
    environment.update(handoff)
    environment['HOME'] = os.environ['WWW_DATA_HOME']
    environment['PATH'] = SAFE_PATH
    phase = os.environ.get('TRUSTPOINT_PHASE', 'operational') if job == 'web' else 'operational'
    if job == 'bootstrap':
        phase = 'bootstrap'
    environment['TRUSTPOINT_PHASE'] = phase
    environment['DJANGO_SETTINGS_MODULE'] = (
        'trustpoint.settings_bootstrap' if phase == 'bootstrap' else 'trustpoint.settings'
    )
    commands = {
        'bootstrap': [str(APP_DIR / '.venv/bin/python'), 'trustpoint/manage.py', 'bootstrap_manager'],
        'startup': [str(APP_DIR / '.venv/bin/python'), 'trustpoint/manage.py', 'startup_manager'],
        'migrate': [str(APP_DIR / '.venv/bin/python'), 'trustpoint/manage.py', 'migrate'],
        'auto-setup': [str(APP_DIR / '.venv/bin/python'), 'trustpoint/manage.py', 'auto_setup_from_env'],
        'qcluster': [str(APP_DIR / '.venv/bin/python'), 'trustpoint/manage.py', 'qcluster'],
        'db-ready': [
            '/usr/bin/pg_isready',
            '-h',
            environment.get('DATABASE_HOST', 'localhost'),
            '-p',
            environment.get('DATABASE_PORT', '5432'),
        ],
        'sync-security': [str(APP_DIR / '.venv/bin/python'), 'trustpoint/manage.py', 'sync_security_config'],
        'worker': [
            str(APP_DIR / '.venv/bin/python'),
            'trustpoint/manage.py',
            'workflows2_worker',
            '--id',
            os.environ.get('WORKFLOWS2_WORKER_ID', os.uname().nodename),
            '--lease',
            os.environ.get('WORKFLOWS2_WORKER_LEASE', '30'),
            '--batch',
            os.environ.get('WORKFLOWS2_WORKER_BATCH', '10'),
            '--sleep',
            os.environ.get('WORKFLOWS2_WORKER_SLEEP', '1'),
        ],
        'gunicorn': [
            str(APP_DIR / '.venv/bin/gunicorn'),
            '--chdir',
            str(APP_DIR / 'trustpoint'),
            '--bind',
            f'0.0.0.0:{os.environ["TRUSTPOINT_OPERATIONAL_GUNICORN_PORT"]}',
            '--workers',
            '4',
            '--timeout',
            '300',
            '--limit-request-line',
            '8190',
            '--limit-request-field_size',
            '65536',
            'trustpoint.wsgi:application',
        ],
    }
    commands['web'] = [*commands['gunicorn']]
    bind_index = commands['web'].index('--bind') + 1
    commands['web'][bind_index] = f'0.0.0.0:{os.environ["TRUSTPOINT_BOOTSTRAP_GUNICORN_PORT"]}'
    if job not in commands:
        msg = 'Unsupported application operation.'
        raise ValueError(msg)
    os.chdir(APP_DIR)
    os.execve(commands[job][0], commands[job], environment)  # noqa: S606 - fixed commands, privileges already dropped.


def enter_container() -> None:
    """Select startup phase and validate any persisted data before running the root entrypoint."""
    deployment = initialize_deployment()
    environment = root_environment(deployment, {})
    phase = os.environ.get('TRUSTPOINT_PHASE', 'auto')
    env_file = Path(deployment['TRUSTPOINT_OPERATIONAL_ENV_FILE'])
    ready = Path(deployment['TRUSTPOINT_OPERATIONAL_READY_FILE'])
    if phase == 'operational' or (phase == 'auto' and env_file.is_file() and ready.is_file()):
        if env_file.is_file():
            environment = root_environment(deployment, parse_handoff(read_configuration(env_file)))
        phase = 'operational'
    elif phase == 'auto':
        phase = 'bootstrap'
    if phase not in {'bootstrap', 'operational'}:
        msg = 'Invalid container startup phase.'
        raise ValueError(msg)
    environment['TRUSTPOINT_PHASE'] = phase
    _exec_script('entrypoint.sh', [], environment)


def main(arguments: list[str]) -> None:
    """Dispatch a fixed startup operation; no caller-selected executable is accepted."""
    if len(arguments) == OPERATION_ARGUMENT_COUNT and arguments[0] == 'app':
        run_application(arguments[1])
        return
    if os.geteuid() != 0:
        msg = 'Container startup operations require root.'
        raise ValueError(msg)
    if arguments == ['entrypoint']:
        enter_container()
        return
    deployment = load_deployment()
    if arguments in (['switch', '--pending'], ['switch', '--final']):
        path = Path(deployment['TRUSTPOINT_OPERATIONAL_ENV_FILE'])
        if arguments[1] == '--pending':
            path = path.with_name('operational.pending.env')
        environment = root_environment(deployment, parse_handoff(read_configuration(path)))
        environment['TRUSTPOINT_PHASE'] = 'operational'
        environment['OPERATIONAL_ENV_FILE'] = str(path)
        _exec_script('wizard/internal/switch_to_operational.sh', [], environment)
    elif arguments == ['resume-worker']:
        path = Path(deployment['TRUSTPOINT_OPERATIONAL_ENV_FILE'])
        environment = root_environment(deployment, parse_handoff(read_configuration(path)))
        environment['TRUSTPOINT_PHASE'] = 'operational'
        environment['DJANGO_SETTINGS_MODULE'] = 'trustpoint.settings'
        _exec_script('entrypoint.sh', [], environment)
    elif (
        len(arguments) >= OPERATION_ARGUMENT_COUNT
        and arguments[0] == 'privileged'
        and arguments[1] in PRIVILEGED_SCRIPTS
    ):
        _exec_script(f'wizard/internal/{arguments[1]}', arguments[2:], root_environment(deployment, {}))
    else:
        msg = 'Unsupported privileged operation.'
        raise ValueError(msg)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Configuration may contain credentials. Never print its contents or exception text.
        sys.stderr.write('Invalid or unavailable Trustpoint runtime configuration.\n')
        sys.exit(64)
