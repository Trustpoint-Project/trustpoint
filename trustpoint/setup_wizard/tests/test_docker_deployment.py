# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Validate the shipped Compose configurations and conservative SoftHSM startup."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(shutil.which('docker') is None, reason='Docker Compose CLI is not installed')
@pytest.mark.parametrize('files,profile', [
    (['docker-compose.yml'], None),
    (['docker-compose.worker.yml'], None),
    (['docker-compose.softhsm.yml'], None),
    (['docker-compose.softhsm.yml'], 'worker'),
    (['docker-compose.yml', 'docker-compose.demo.yml'], None),
    (['docker-compose.yml', 'docker-compose.mdns.yml'], None),
])
def test_compose_services_share_readonly_secret_and_persistent_state(tmp_path, files, profile):
    for filename in files:
        shutil.copyfile(ROOT / filename, tmp_path / filename)
    (tmp_path / '.env').write_text('DATABASE_PASSWORD=synthetic-test-password\n')
    args = ['docker', 'compose']
    for filename in files:
        args += ['-f', filename]
    if profile:
        args += ['--profile', profile]
    args += ['config', '--format', 'json']
    result = subprocess.run(args, cwd=tmp_path, env={
        'PATH': os.environ['PATH'], 'HOME': os.environ['HOME'],
        'SFTPGO_ADMIN_PASSWORD': 'synthetic-test-password',
    }, text=True, capture_output=True, check=True, timeout=30)
    config = json.loads(result.stdout)
    assert config['secrets']['django_secret_key']['file'] == str(tmp_path / 'secrets/django_secret_key')
    for name, service in config['services'].items():
        if name not in {'trustpoint', 'trustpoint-worker'}:
            continue
        assert service['environment']['DJANGO_SECRET_KEY_FILE'] == '/run/secrets/django_secret_key'
        assert any(s['source'] == 'django_secret_key' and s['target'] == '/run/secrets/django_secret_key'
                   for s in service['secrets'])
        targets = {v['target'] for v in service['volumes']}
        assert '/var/lib/trustpoint/bootstrap' in targets
        assert '/var/www/html/trustpoint/trustpoint/media' in targets
        assert '/var/lib/trustpoint/hsm' in targets
        assert '/etc/trustpoint/secrets' not in targets
    assert 'trustpoint_secrets' not in config['volumes']


def test_existing_softhsm_token_with_missing_pins_is_not_reinitialized(tmp_path):
    config = tmp_path / 'config'
    config.mkdir()
    token_dir = tmp_path / 'tokens'
    token_dir.mkdir()
    token = token_dir / 'existing-token'
    token.write_text('preserve-key-material')
    conf = config / 'softhsm2.conf'
    conf.write_text(f'directories.tokendir = {token_dir}\n')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    marker = tmp_path / 'token-was-reset'
    utility = bin_dir / 'softhsm2-util'
    utility.write_text('''#!/bin/sh
if [ "$1" = "--show-slots" ]; then
    printf 'Slot 0\\n    Serial number: known-token\\n    Label: Trustpoint-SoftHSM\\n'
else
    touch "$TOKEN_RESET_MARKER"
    exit 91
fi
''')
    utility.chmod(0o755)
    result = subprocess.run(['bash', str(ROOT / 'docker/softhsm/scripts/bootstrap_local_dev_token.sh')],
        env={**os.environ, 'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'],
             'TRUSTPOINT_HSM_ROOT': str(tmp_path), 'SOFTHSM2_CONF': str(conf),
             'TOKEN_RESET_MARKER': str(marker)}, capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode != 0
    assert 'Restore the original PIN files' in result.stdout
    assert not marker.exists()
    assert not (config / 'user-pin.txt').exists()
    assert token.read_text() == 'preserve-key-material'
