# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run only in the disposable Docker test image; exercise real Linux sudo and UIDs."""

import json
import os
import pwd
import runpy
import sqlite3
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

# Real root ownership must not escape through a web-created bootstrap symlink.
storage = Path('/var/lib/trustpoint/storage-regression/new/bootstrap')
protected = Path('/etc/trustpoint/storage-protected-script')
protected.write_text('protected')
protected.chmod(0o644)
deployment = {
    **runtime['DEPLOYMENT_DEFAULTS'],
    'TRUSTPOINT_BOOTSTRAP_DB_PATH': str(storage / 'bootstrap.sqlite3'),
    'TRUSTPOINT_OPERATIONAL_ENV_FILE': str(storage / 'operational.env'),
    'TRUSTPOINT_OPERATIONAL_READY_FILE': str(storage / 'operational.ready'),
}
runtime['prepare_bootstrap_storage'](deployment)
assert storage.stat().st_uid == account.pw_uid and storage.stat().st_mode & 0o777 == 0o750
assert storage.parent.stat().st_uid == 0 and storage.parent.stat().st_mode & 0o777 == 0o755
write_probe = storage / 'application-write-probe'
subprocess.run(['sudo', '-u', 'www-data', 'touch', str(write_probe)], check=True)
write_probe.unlink()
database = storage / 'bootstrap.sqlite3'
subprocess.run(['sudo', '-u', 'www-data', 'ln', '-s', str(protected), str(database)], check=True)
try:
    runtime['prepare_bootstrap_storage'](deployment)
except OSError:
    pass
else:
    raise AssertionError('Root startup accepted a symlinked database')
assert protected.stat().st_uid == 0 and protected.stat().st_mode & 0o777 == 0o644
database.unlink()
with sqlite3.connect(database) as connection:
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('CREATE TABLE saved (value TEXT)')
    connection.execute("INSERT INTO saved VALUES ('committed state')")
    connection.commit()
    connection.execute('BEGIN IMMEDIATE')
    before = {path: path.read_bytes() for path in storage.iterdir()}
    runtime['prepare_bootstrap_storage'](deployment)
    assert {path: path.read_bytes() for path in storage.iterdir()} == before
    assert database.stat().st_uid == account.pw_uid
    assert connection.execute('SELECT value FROM saved').fetchone() == ('committed state',)
print('PASS: nested storage is writable by www-data; links are rejected and locked SQLite/WAL data is preserved.', flush=True)

# The privileged installer accepts persistent staging and rejects the old /tmp root.
staged = bootstrap / 'staging/pkcs11'
staged.mkdir(parents=True)
module = staged / 'test-module.so'
pin = staged / 'test-pin.txt'
module.write_bytes(b'fixture module; never loaded')
pin.write_text('synthetic-pin')
installer = '/etc/trustpoint/wizard/install_pkcs11_assets.sh'
result = subprocess.run(
    ['sudo', '-u', 'www-data', 'sudo', '-n', installer, str(module), str(pin)],
    capture_output=True, text=True,
)
assert result.returncode == 0, result.stdout + result.stderr
installed_pin = Path('/var/lib/trustpoint/hsm/config/user-pin.txt')
assert installed_pin.read_text() == 'synthetic-pin'
assert installed_pin.stat().st_uid == 0 and installed_pin.stat().st_mode & 0o777 == 0o640
assert not pin.exists() and not module.exists()
legacy = Path('/tmp/trustpoint-wizard/pkcs11/pin.txt')
legacy.parent.mkdir(parents=True)
legacy.write_text('reject-outside-persistent-staging')
result = subprocess.run(
    ['sudo', '-u', 'www-data', 'sudo', '-n', installer, str(legacy)], capture_output=True,
)
assert result.returncode != 0
assert installed_pin.read_text() == 'synthetic-pin'
print('PASS: sudo installer accepts persistent wizard staging and rejects legacy paths.', flush=True)

# The host initializer is explicit and idempotent; the application only reads.
initializer = runpy.run_path('/tests/init_secret.py')['initialize_secret']
signing_key = Path('/run/secrets/django_secret_key')
# Emulate Docker's secret-mount parent, not the private host source directory.
signing_key.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
assert initializer(signing_key)
original_key = signing_key.read_bytes()
assert not initializer(signing_key)
assert signing_key.read_bytes() == original_key
assert len(original_key) >= 50
assert signing_key.stat().st_uid == 0
assert signing_key.stat().st_gid == account.pw_gid
assert signing_key.stat().st_mode & 0o777 == 0o440
key_probe = """
from pathlib import Path
p = Path('/run/secrets/django_secret_key')
assert len(p.read_text()) >= 50
try:
    p.write_text('replacement')
except PermissionError:
    pass
else:
    raise AssertionError('www-data can overwrite the signing key')
"""
subprocess.run(['sudo', '-u', 'www-data', '/usr/local/bin/python3', '-I', '-c', key_probe], check=True)
software_kek = Path('/run/secrets/trustpoint_software_kek')
assert initializer(software_kek, kind='kek')
original_kek = software_kek.read_bytes()
assert len(bytes.fromhex(original_kek.decode())) == 32
assert software_kek.stat().st_uid == 0 and software_kek.stat().st_gid == account.pw_gid
assert software_kek.stat().st_mode & 0o777 == 0o440
assert not initializer(software_kek, kind='kek')
assert software_kek.read_bytes() == original_kek
kek_probe = key_probe.replace('django_secret_key', 'trustpoint_software_kek')
subprocess.run(['sudo', '-u', 'www-data', '/usr/local/bin/python3', '-I', '-c', kek_probe], check=True)


# Exercise the real auto-setup switch before replacing its body below. A retry
# must install restored TLS files even when the database setup already committed.
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
for name in ('nginx-tls-server-key.key', 'nginx-tls-server-cert.pem'):
    (app / 'docker/trustpoint/nginx/tls' / name).write_text('restored operational TLS')
app_program = app / '.venv/bin/python'
app_program.write_text("""#!/bin/sh
case "$*" in
  *migrate) exit 17 ;;
  *finalize_setup)
    touch "$TRUSTPOINT_OPERATIONAL_READY_FILE"
    rm -f /var/lib/trustpoint/bootstrap/auto-setup.marker
    exit 0 ;;
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
final.write_text('{}')
os.chown(final, account.pw_uid, account.pw_gid)
result = subprocess.run([helper, '--final'], capture_output=True, text=True, timeout=15)
assert result.returncode == 17, result.stdout + result.stderr
assert auto_marker.exists(), 'Failed migrations must preserve the auto-setup marker'
app_program.write_text(app_program.read_text().replace('*migrate) exit 17', '*migrate) exit 0'))
result = subprocess.run([helper, '--final'], capture_output=True, text=True, timeout=15)
assert result.returncode == 0, result.stdout + result.stderr
assert not auto_marker.exists()
assert ready.exists()
assert 'Applying operational TLS files' in result.stdout
assert Path('/etc/trustpoint/tls/nginx-tls-server-cert.pem').read_text() == 'restored operational TLS'
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
# Apply exactly the production image ownership policy to a representative tree.
protected = [
    app / 'trustpoint/manage.py',
    app / 'trustpoint/trustpoint/settings.py',
    app / '.venv/lib/python3.14/site-packages/example.py',
    app / 'docs/source/conf.py',
    app / 'pyproject.toml',
    app / 'uv.lock',
]
for path in protected:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('# image artifact\n')
    os.chown(path, account.pw_uid, account.pw_gid)
subprocess.run(['/bin/bash', '/etc/trustpoint/lock_application.sh'], check=True)
permission_probe = """
from pathlib import Path
app = Path('/var/www/html/trustpoint')
for name in ('trustpoint/manage.py', 'trustpoint/trustpoint/settings.py',
             '.venv/lib/python3.14/site-packages/example.py', 'docs/source/conf.py',
             'pyproject.toml', 'uv.lock', '.venv/bin/python'):
    path = app / name
    assert path.stat().st_uid == 0
    try:
        with path.open('a') as stream:
            stream.write('# modified')
    except PermissionError:
        pass
    else:
        raise AssertionError(f'Application can modify {name}')
    try:
        path.rename(path.with_name(path.name + '.replaced'))
    except PermissionError:
        pass
    else:
        raise AssertionError(f'Application can replace {name}')
for name in ('sitecustomize.py', '.venv/lib/python3.14/site-packages/persistence.pth',
             'trustpoint/trustpoint/persistence.py', 'docs/source/persistence.py'):
    try:
        (app / name).touch()
    except PermissionError:
        pass
    else:
        raise AssertionError(f'Application can create executable code: {name}')
for name in ('trustpoint/media', 'trustpoint/collected_static',
             'docker/trustpoint/nginx/tls', 'docs/build'):
    path = app / name / 'runtime-write-probe'
    path.write_text('data')
    path.unlink()
"""
subprocess.run(['sudo', '-u', 'www-data', '/usr/local/bin/python3', '-I', '-c', permission_probe], check=True)
print('PASS: host-provisioned signing key, idempotent initialization, permissions, auto-setup, sudo restrictions, and protected code.')
