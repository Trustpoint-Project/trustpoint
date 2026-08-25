# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for container runtime shell-script contracts."""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
UPDATE_TLS_SCRIPT = REPO_ROOT / 'docker/trustpoint/wizard/update_tls.sh'
TRUSTPOINT_SERVICE_SCRIPT = REPO_ROOT / 'scripts/tp_wizard/services/trustpoint.sh'
MISSING_CREDENTIAL_EXIT_CODE = 5


def _run_update_tls(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    staging_dir = tmp_path / 'staging'
    installed_dir = tmp_path / 'installed'
    staging_dir.mkdir(exist_ok=True)
    installed_dir.mkdir(exist_ok=True)
    env = {
        **os.environ,
        'TRUSTPOINT_TLS_STAGING_DIR': str(staging_dir),
        'TRUSTPOINT_NGINX_TLS_DIR': str(installed_dir),
        'TRUSTPOINT_LOG_FILE': str(tmp_path / 'trustpoint.log'),
        'TRUSTPOINT_NGINX_BIN': '/bin/true',
    }
    return subprocess.run(  # noqa: S603
        ['/bin/bash', str(UPDATE_TLS_SCRIPT)],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )


def test_update_tls_installs_staged_credential_and_is_restart_safe(tmp_path: Path) -> None:
    """A staged credential is installed once and reused on later starts."""
    staging_dir = tmp_path / 'staging'
    installed_dir = tmp_path / 'installed'
    staging_dir.mkdir()
    installed_dir.mkdir()
    (staging_dir / 'nginx-tls-server-key.key').write_text('new-key', encoding='ascii')
    (staging_dir / 'nginx-tls-server-cert.pem').write_text('new-cert', encoding='ascii')
    (staging_dir / 'nginx-tls-server-cert-chain.pem').write_text('new-chain', encoding='ascii')

    first_run = _run_update_tls(tmp_path)
    second_run = _run_update_tls(tmp_path)

    assert first_run.returncode == 0, first_run.stderr
    assert second_run.returncode == 0, second_run.stderr
    assert (installed_dir / 'nginx-tls-server-key.key').read_text(encoding='ascii') == 'new-key'
    assert (installed_dir / 'nginx-tls-server-cert.pem').read_text(encoding='ascii') == 'new-cert'
    assert (installed_dir / 'nginx-tls-server-cert-chain.pem').read_text(encoding='ascii') == 'new-chain'
    assert 'using the installed credential' in second_run.stdout


def test_update_tls_rejects_missing_credentials(tmp_path: Path) -> None:
    """Startup fails clearly when neither staged nor installed TLS files exist."""
    result = _run_update_tls(tmp_path)

    assert result.returncode == MISSING_CREDENTIAL_EXIT_CODE
    assert 'No complete staged or installed TLS credential is available' in result.stdout


def test_trustpoint_launcher_passes_public_ports_into_container() -> None:
    """Public ports configure both Docker mappings and Django's external URLs."""
    harness = f"""
set -euo pipefail
source "{TRUSTPOINT_SERVICE_SCRIPT}"
BUILD_LOCAL=false
TP_HTTP_PORT=8080
TP_HTTPS_PORT=8443
DB_NAME=trustpoint_db
DB_USER=admin
DB_PASS=password
TP_ADMIN_USERNAME=admin
TP_ADMIN_PASSWORD=password
TP_ADMIN_EMAIL=admin@example.test
TP_AUTO_SETUP=true
TP_INJECT_DEMO_DATA=true
TP_TLS_DNS_NAMES=trustpoint.local
TP_TLS_IPV4_ADDRESSES=
TP_TLS_IPV6_ADDRESSES=
ENABLE_METRICS=false
APP_IMAGE=trustpoint:test
build_trustpoint() {{ :; }}
remove_compose_service() {{ :; }}
remove_container() {{ :; }}
ok() {{ :; }}
start_container() {{ printf '<%s>\\n' "$@"; }}
start_trustpoint
"""
    result = subprocess.run(  # noqa: S603
        ['/bin/bash', '-c', harness],
        check=True,
        capture_output=True,
        text=True,
    )

    assert '<8080:80>' in result.stdout
    assert '<8443:443>' in result.stdout
    assert '<TP_HTTP_PORT=8080>' in result.stdout
    assert '<TP_HTTPS_PORT=8443>' in result.stdout
