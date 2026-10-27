# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run only in the disposable Docker test image; exercise real Linux sudo and UIDs."""

import json
import os
import pwd
import runpy
import subprocess
from pathlib import Path

runtime = runpy.run_path('/etc/trustpoint/runtime_config.py')
account = pwd.getpwnam('www-data')
bootstrap = Path('/var/lib/trustpoint/bootstrap')
bootstrap.mkdir(parents=True)
os.chown(bootstrap, account.pw_uid, account.pw_gid)
pending = bootstrap / 'operational.pending.env'
final = bootstrap / 'operational.env'
ready = bootstrap / 'operational.ready'
marker = Path('/root/must-not-exist')
helper = '/etc/trustpoint/wizard/switch_to_operational.sh'
os.environ['DATABASE_PASSWORD'] = 'external-test-credential'
runtime['initialize_deployment']()

# Exercise the real auto-setup switch before replacing its body below. Service
# executables are stubs; a second TLS install would fail on the empty staging dir.
app = Path('/var/www/html/trustpoint')
(app / '.venv/bin').mkdir(parents=True)
(app / 'trustpoint').mkdir()
Path('/usr/bin/pg_isready').write_text('#!/bin/sh\nexit 0\n')
Path('/usr/bin/pg_isready').chmod(0o755)
for service in ('nginx', 'curl'):
    stub = Path('/usr/local/bin') / service
    stub.write_text('#!/bin/sh\nexit 0\n')
    stub.chmod(0o755)
site = Path('/etc/nginx/sites-available/trustpoint')
site.parent.mkdir(parents=True)
site.write_text('proxy_pass http://127.0.0.1:8000;\n')
(app / 'docker/trustpoint/nginx/tls').mkdir(parents=True)
app_program = app / '.venv/bin/python'
app_program.write_text("""#!/bin/sh
case "$*" in
  *migrate) exit 17 ;;
  *qcluster) exec /bin/sleep 60 ;;
esac
exit 0
""")
app_program.chmod(0o755)
gunicorn = app / '.venv/bin/gunicorn'
gunicorn.write_text('#!/bin/sh\nexec /bin/sleep 60\n')
gunicorn.chmod(0o755)
auto_marker = bootstrap / 'auto-setup.marker'
auto_marker.touch()
pending.write_text('{}')
os.chown(pending, account.pw_uid, account.pw_gid)
result = subprocess.run([helper, '--pending'], capture_output=True, text=True, timeout=15)
assert result.returncode == 17, result.stdout + result.stderr
assert auto_marker.exists(), 'Failed migrations must preserve the auto-setup marker'
app_program.write_text(app_program.read_text().replace('*migrate) exit 17', '*migrate) exit 0'))
result = subprocess.run([helper, '--pending'], capture_output=True, text=True, timeout=15)
assert result.returncode == 0, result.stdout + result.stderr
assert not auto_marker.exists()
assert 'Applying operational TLS files' not in result.stdout
assert 'runtime switched to operational mode' in result.stdout
for pid_path in Path('/run').glob('trustpoint-operational-*.pid'):
    os.kill(int(pid_path.read_text()), 15)
    pid_path.unlink()

# Replace only the actual system operations with observations. The real wrappers,
# parser, sudo policy, privilege drop, file ownership and process launch are used.
root_observer = """#!/bin/bash
exec /usr/local/bin/python3 -I -c '
import json, os
print(json.dumps({"uid": os.geteuid(), "host": os.environ.get("DATABASE_HOST"),
"opaque_host": json.loads(os.environ["_TRUSTPOINT_APPLICATION_ENV"]).get("DATABASE_HOST"),
"hsm_root": os.environ["TRUSTPOINT_HSM_ROOT"],
"port": os.environ["TRUSTPOINT_OPERATIONAL_GUNICORN_PORT"],
"provider": os.environ.get("VENDOR_CONFIG")}))'
"""
internal = Path('/etc/trustpoint/wizard/internal/switch_to_operational.sh')
internal.write_text(root_observer)
internal.chmod(0o755)


def switch(*arguments, extra_env=None):
    env = {**os.environ, **(extra_env or {})}
    return subprocess.run(
        [
            'sudo',
            '-u',
            'www-data',
            '/usr/bin/env',
            *[f'{key}={value}' for key, value in (extra_env or {}).items()],
            'sudo',
            '-n',
            helper,
            *arguments,
        ],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )


# Neither an arbitrary file nor the internal implementation is a permitted sudo command.
payload = Path('/tmp/payload.env')
payload.write_text(f'touch {marker}\n')
assert switch(str(payload)).returncode != 0
assert switch('--validated').returncode != 0
assert (
    subprocess.run(
        ['sudo', '-u', 'www-data', 'sudo', '-n', str(internal)],
        capture_output=True,
    ).returncode
    != 0
)
assert not marker.exists()

# Shell-format files are rejected, while shell-looking JSON values remain literal.
pending.write_text(f'export DATABASE_HOST=postgres\ntouch {marker}\n')
os.chown(pending, account.pw_uid, account.pw_gid)
assert switch('--pending').returncode != 0
assert not marker.exists()
pending.write_text(json.dumps({'DATABASE_HOST': f'$(id>{marker})', 'DATABASE_PORT': '5432'}))
result = switch(
    '--pending',
    extra_env={
        'TRUSTPOINT_HSM_ROOT': '/etc',
        'TRUSTPOINT_OPERATIONAL_GUNICORN_PORT': '9999',
        'BASH_ENV': str(payload),
        'PYTHONPATH': '/tmp/attacker',
    },
)
assert result.returncode == 0, result.stderr
observed = json.loads(result.stdout)
assert observed == {
    'uid': 0,
    'host': None,
    'opaque_host': f'$(id>{marker})',
    'hsm_root': '/var/lib/trustpoint/hsm',
    'port': '8001',
    'provider': None,
}
assert not marker.exists()

# Provider configuration and control-looking values are data for www-data only.
pending.write_text(
    json.dumps(
        {
            'DATABASE_HOST': 'postgres',
            'DATABASE_PORT': '5432',
            'TRUSTPOINT_HSM_ROOT': '/etc',
            'TRUSTPOINT_PKCS11_CONFIG_ENV_VAR': 'VENDOR_CONFIG',
            'VENDOR_CONFIG': str(payload),
        }
    )
)
result = switch('--pending')
assert result.returncode == 0, result.stderr
assert json.loads(result.stdout)['provider'] is None
assert json.loads(result.stdout)['hsm_root'] == '/var/lib/trustpoint/hsm'

# Root entrypoint parsing also rejects an executable handoff before starting services.
final.write_text(f'touch {marker}\n')
ready.touch()
result = subprocess.run(
    ['/usr/local/bin/python3', '-I', '/etc/trustpoint/runtime_config.py', 'entrypoint'],
    env={**os.environ, 'TRUSTPOINT_PHASE': 'auto'},
    capture_output=True,
    timeout=10,
)
assert result.returncode != 0
assert not marker.exists()

# Root-owned deployment settings are unreadable and unwritable by the web account.
for command in (
    ['cat', '/run/trustpoint/deployment.json'],
    ['/bin/sh', '-c', 'echo tampered > /run/trustpoint/deployment.json'],
):
    assert subprocess.run(['sudo', '-u', 'www-data', *command], capture_output=True).returncode != 0

# Application executables are reached with all root identities already dropped.
app = Path('/var/www/html/trustpoint')
app_program = app / '.venv/bin/python'
app_program.write_text("""#!/usr/local/bin/python3
import json, os
assert os.getuid() != 0 and os.geteuid() != 0 and os.getgid() != 0 and 0 not in os.getgroups()
print(json.dumps({"uid": os.geteuid(), "host": os.environ["DATABASE_HOST"],
                 "setting": os.environ["TRUSTPOINT_CLIENT_CERTIFICATE_PROXY_IPS"]}))
""")
app_program.chmod(0o755)
env = runtime['root_environment'](runtime['load_deployment'](), {'DATABASE_HOST': 'postgres', 'DATABASE_PORT': '5432'})
env['TRUSTPOINT_APPLICATION_ENV'] = json.dumps({'TRUSTPOINT_CLIENT_CERTIFICATE_PROXY_IPS': '192.0.2.1'})
result = subprocess.run(
    ['/usr/local/bin/python3', '-I', '/etc/trustpoint/runtime_config.py', 'app', 'startup'],
    env=env,
    text=True,
    capture_output=True,
    timeout=10,
)
assert result.returncode == 0, result.stderr
assert json.loads(result.stdout) == {'uid': account.pw_uid, 'host': 'postgres', 'setting': '192.0.2.1'}
assert not marker.exists()
print('PASS: auto-setup switch, migration failure, sudo restrictions, parsing, root isolation, and UID/GID drop.')
