# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Optional end-to-end test: fresh isolated Compose project, synthetic data, no published ports.

Build the application test image first. Set TRUSTPOINT_TEST_COMPOSE_FILE to
'docker-compose.softhsm.yml' to include SoftHSM, using its separately built
trustpoint-softhsm-regression:local image. The real deployment is never accessed.
"""

import json, os, pathlib, shutil, subprocess, tempfile, uuid

root = pathlib.Path(__file__).resolve().parents[2]
image = os.environ.get('TRUSTPOINT_TEST_IMAGE', 'trustpoint-compose-regression:local')
compose_file = os.environ.get('TRUSTPOINT_TEST_COMPOSE_FILE', 'docker-compose.worker.yml')
project = 'tp-compose-smoke-' + uuid.uuid4().hex[:10]
temp = pathlib.Path(tempfile.mkdtemp(prefix='trustpoint-compose-smoke-'))
compose = ['docker', 'compose', '-p', project, '-f', str(temp / 'stack.json'), '--profile', 'worker']


def call(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(
            'Command failed: ' + ' '.join(args[:5]) + '\n' + result.stderr[-1800:] + '\n' + result.stdout[-1800:]
        )
    return result.stdout


try:
    # Synthetic data only. Docker Desktop cannot emulate Linux host chown
    # through a guest bind mount; real root:33/0440 permissions are checked in
    # the separate Linux security fixture.
    (temp / 'secrets').mkdir(mode=0o700)
    fixture = temp / 'secrets/django_secret_key'
    fixture.write_text('synthetic-integration-signing-key-' + 'x' * 64)
    fixture.chmod(0o444)
    kek_fixture = temp / 'secrets/trustpoint_software_kek'
    kek_fixture.write_text('ab' * 32)
    kek_fixture.chmod(0o444)
    shutil.copyfile(root / compose_file, temp / compose_file)
    (temp / 'db_user.txt').write_text('admin')
    (temp / 'db_password.txt').write_text('synthetic-integration-password')
    (temp / 'db_user.txt').chmod(0o444)
    (temp / 'db_password.txt').chmod(0o444)
    (temp / '.env').write_text(
        'TRUSTPOINT_IMAGE=' + image + '\nDATABASE_PASSWORD=synthetic-integration-password\n'
        'TP_AUTO_SETUP=true\nTP_ADMIN_USERNAME=admin\nTP_ADMIN_PASSWORD=synthetic-integration-admin-password\n'
        'TP_TLS_DNS_NAMES=localhost\nTP_INJECT_DEMO_DATA=false\n'
    )
    render_env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(('COMPOSE_', 'TRUSTPOINT_', 'DJANGO_', 'DATABASE_', 'POSTGRES_', 'TP_', 'WORKFLOWS2_'))
    }
    rendered = call(
        [
            'docker',
            'compose',
            '-p',
            project,
            '-f',
            str(temp / compose_file),
            '--profile',
            'worker',
            'config',
            '--format',
            'json',
        ],
        cwd=temp,
        env=render_env,
    )
    config = json.loads(rendered)
    config['networks']['default']['name'] = project + '-network'
    if 'softhsm' in config['services']:
        # This legacy auto-setup regression exercises software storage, even on
        # the SoftHSM stack. Real HSM envelopes are tested by envelope_smoke.py.
        config['secrets']['trustpoint_software_kek'] = {'file': str(kek_fixture)}
        for name in ('trustpoint', 'trustpoint-worker'):
            config['services'][name]['secrets'].append({'source': 'trustpoint_software_kek',
                                                       'target': '/run/secrets/trustpoint_software_kek'})
            config['services'][name]['environment']['TRUSTPOINT_SOFTWARE_KEK_FILE'] = '/run/secrets/trustpoint_software_kek'
        config['services']['softhsm']['image'] = os.environ.get(
            'TRUSTPOINT_TEST_SOFTHSM_IMAGE', 'trustpoint-softhsm-regression:local'
        )
    for service in config['services'].values():
        service.pop('container_name', None)
        service.pop('build', None)
        service['ports'] = []
    (temp / 'stack.json').write_text(json.dumps(config))
    call(
        [
            'docker',
            'run',
            '--rm',
            '--network=none',
            '--entrypoint',
            '/bin/sh',
            image,
            '-c',
            'test ! -e /run/secrets/django_secret_key && test ! -e /etc/trustpoint/secrets/django_secret_key.env',
        ]
    )
    print('PASS: application image contains no signing key.', flush=True)
    missing = subprocess.run(
        [
            'docker',
            'run',
            '--rm',
            '--network=none',
            '--user',
            '33:33',
            '--entrypoint',
            '/var/www/html/trustpoint/.venv/bin/python',
            image,
            '-c',
            "import sys; sys.path.insert(0,'/var/www/html/trustpoint/trustpoint'); import trustpoint.settings",
        ],
        capture_output=True,
        text=True,
    )
    assert missing.returncode and 'signing-key file cannot be read' in missing.stderr
    print('PASS: production settings fail clearly without a secret.', flush=True)
    for name, mode in [('empty', 0o444), ('unreadable', 0o000)]:
        bad = temp / name
        bad.write_text('' if name == 'empty' else 'synthetic-unreadable-value')
        bad.chmod(mode)
        result = subprocess.run(
            [
                'docker',
                'run',
                '--rm',
                '--network=none',
                '--user',
                '33:33',
                '--mount',
                f'type=bind,src={bad},dst=/run/secrets/django_secret_key,readonly',
                '--entrypoint',
                '/var/www/html/trustpoint/.venv/bin/python',
                image,
                '-c',
                "import sys; sys.path.insert(0,'/var/www/html/trustpoint/trustpoint'); import trustpoint.settings",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode and (
            'signing-key file' in result.stderr
            or 'permission denied' in result.stderr.lower()
            or 'operation not permitted' in result.stderr.lower()
        ), f'{name}: exit={result.returncode}, diagnostic={result.stderr[-500:]}'
        bad.chmod(0o600)
    print('PASS: empty and unreadable secrets fail production startup.', flush=True)

    print('Starting isolated web, PostgreSQL, and worker services...', flush=True)
    call(compose + ['up', '-d', '--no-build', '--wait', '--wait-timeout', '300'], cwd=temp)
    probe = """import sys,json,hashlib,os
sys.path.insert(0,'/var/www/html/trustpoint/trustpoint')
os.environ['DJANGO_SETTINGS_MODULE']='trustpoint.settings'
import django
django.setup()
from django.conf import settings
from appsecrets.service import get_app_secret_service
from appsecrets.models import AppSecretBackendModel, AppSecretSoftwareConfigModel
service=get_app_secret_service()
dek=service.require_dek()
assert service.decrypt_text(service.encrypt_text('integration encrypted value'))=='integration encrypted value'
print(json.dumps({'digest':hashlib.sha256(settings.SECRET_KEY.encode()).hexdigest(),
                 'dek_digest':hashlib.sha256(dek).hexdigest(),
                 'leaked':any(settings.SECRET_KEY in v or ('ab'*32) in v for v in os.environ.values())}))
"""

    def key(service):
        return json.loads(
            call(
                compose
                + ['exec', '-T', '--user', '33:33', service, '/var/www/html/trustpoint/.venv/bin/python', '-c', probe],
                cwd=temp,
            )
        )

    if 'softhsm' in config['services']:
        hsm_probe = (
            'import pkcs11; from pathlib import Path; '
            "token=pkcs11.lib('/usr/lib/libsofthsm2.so').get_token(token_label='Trustpoint-SoftHSM'); "
            "session=token.open(user_pin=Path('/var/lib/trustpoint/hsm/config/user-pin.txt').read_text().strip()); "
            'session.close()'
        )
        call(
            compose
            + [
                'exec',
                '-T',
                '--user',
                '33:33',
                'trustpoint',
                '/var/www/html/trustpoint/.venv/bin/python',
                '-c',
                hsm_probe,
            ],
            cwd=temp,
        )
        print('PASS: application can open the shared SoftHSM token with its persisted PIN.', flush=True)
    first = key('trustpoint')
    assert first == key('trustpoint-worker') and not first['leaked']
    print('PASS: web and worker share signing key and DEK; secrets are absent from environment variables.', flush=True)
    readonly = "from pathlib import Path; p=Path('/run/secrets/django_secret_key'); p.write_text('must-fail')"
    result = subprocess.run(
        compose + ['exec', '-T', '--user', '0', 'trustpoint', '/usr/local/bin/python3', '-c', readonly],
        capture_output=True,
        text=True,
        cwd=temp,
    )
    assert result.returncode and 'Read-only file system' in result.stderr
    print('PASS: the Compose signing secret is read-only even to container root.', flush=True)
    kek_readonly = readonly.replace('django_secret_key', 'trustpoint_software_kek')
    result = subprocess.run(
        compose + ['exec', '-T', '--user', '0', 'trustpoint', '/usr/local/bin/python3', '-c', kek_readonly],
        capture_output=True, text=True, cwd=temp,
    )
    assert result.returncode and 'Read-only file system' in result.stderr
    print('PASS: software KEK is read-only even to container root.', flush=True)
    call(compose + ['restart', 'trustpoint', 'trustpoint-worker'], cwd=temp)
    call(
        compose
        + [
            'up',
            '-d',
            '--no-deps',
            '--no-build',
            '--no-recreate',
            '--wait',
            '--wait-timeout',
            '180',
            'trustpoint',
            'trustpoint-worker',
        ],
        cwd=temp,
    )
    assert first == key('trustpoint') == key('trustpoint-worker')
    print('PASS: restart preserves the signing key and DEK.', flush=True)
    upgrade_image = os.environ.get('TRUSTPOINT_TEST_UPGRADE_IMAGE')
    if upgrade_image:
        for name in ('trustpoint', 'trustpoint-worker'):
            config['services'][name]['image'] = upgrade_image
        (temp / 'stack.json').write_text(json.dumps(config))
    call(
        compose
        + [
            'up',
            '-d',
            '--no-deps',
            '--no-build',
            '--force-recreate',
            '--wait',
            '--wait-timeout',
            '180',
            'trustpoint',
            'trustpoint-worker',
        ],
        cwd=temp,
    )
    assert first == key('trustpoint') == key('trustpoint-worker')
    print('PASS: container recreation/image update preserves signing key, DEK, and operational data.', flush=True)
    concurrent_probe = r'''import os, sys
sys.path.insert(0, '/var/www/html/trustpoint/trustpoint')
os.environ['DJANGO_SETTINGS_MODULE']='trustpoint.settings'
import django
django.setup()
from django.conf import settings
import psycopg
from django.db import connections, close_old_connections
from django.core.management import call_command
from concurrent.futures import ThreadPoolExecutor
from appsecrets.models import AppSecretBackendModel, AppSecretSoftwareConfigModel
from appsecrets.service import SoftwareAppSecretService, clear_app_secret_cache
cfg=settings.DATABASES['default']
with psycopg.connect(dbname=cfg['NAME'],user=cfg['USER'],password=cfg['PASSWORD'],host=cfg['HOST'],port=cfg['PORT'],autocommit=True) as admin:
    admin.execute('CREATE DATABASE envelope_concurrency_test')
connections.close_all()
cfg['NAME']='envelope_concurrency_test'
call_command('migrate',interactive=False,verbosity=0)
b=AppSecretBackendModel.objects.create(backend_kind='software')
AppSecretSoftwareConfigModel.objects.create(backend=b)
clear_app_secret_cache()
def initialize(_):
    close_old_connections()
    try:
        return SoftwareAppSecretService(AppSecretSoftwareConfigModel.objects.get()).require_dek()
    finally:
        close_old_connections()
with ThreadPoolExecutor(max_workers=8) as pool:
    keys=list(pool.map(initialize,range(8)))
assert all(key==keys[0] for key in keys)
assert AppSecretBackendModel.objects.get().dek_initialized
assert AppSecretSoftwareConfigModel.objects.count()==1
print('PASS: eight PostgreSQL initializers recovered the same committed DEK.')
'''
    call(compose + ['exec', '-T', '--user', '33:33', 'trustpoint',
                    '/var/www/html/trustpoint/.venv/bin/python', '-c', concurrent_probe], cwd=temp)
    print('PASS: PostgreSQL concurrent initialization commits one shared DEK.', flush=True)
except Exception:
    if (temp / 'stack.json').exists():
        diagnostic = (
            'import os,runpy; '
            "env=dict(item.split('=',1) for item in open('/proc/1/environ').read().split(chr(0)) if '=' in item); "
            'os.environ.clear(); os.environ.update(env); '
            "runpy.run_path('/etc/trustpoint/runtime_config.py')['run_application']('db-ready')"
        )
        probe = subprocess.run(
            compose + ['exec', '-T', 'trustpoint', '/usr/local/bin/python3', '-I', '-c', diagnostic],
            cwd=temp,
            capture_output=True,
            text=True,
            timeout=10,
        )
        print('Database readiness probe:', probe.returncode, probe.stdout[-1200:], probe.stderr[-1600:])
        container = subprocess.run(
            compose + ['ps', '--all', '--quiet', 'trustpoint'], cwd=temp, capture_output=True, text=True
        ).stdout.strip()
        if container:
            health = subprocess.run(
                ['docker', 'inspect', '--format', '{{json .State.Health}}', container], capture_output=True, text=True
            )
            print('Application health diagnostics:', health.stdout[-2000:])

        result = subprocess.run(
            compose + ['logs', '--tail', '45', 'trustpoint', 'trustpoint-worker'],
            cwd=temp,
            capture_output=True,
            text=True,
        )
        # Synthetic test credentials only; the real deployment is never accessed.
        print(result.stdout[-4500:])
    raise
finally:
    if (temp / 'stack.json').exists():
        subprocess.run(compose + ['down', '--volumes', '--remove-orphans'], cwd=temp, capture_output=True, text=True)
    shutil.rmtree(temp, ignore_errors=True)
