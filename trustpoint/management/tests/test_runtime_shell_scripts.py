# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for container runtime shell-script contracts."""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
UPDATE_TLS_SCRIPT = REPO_ROOT / 'docker/trustpoint/wizard/update_tls.sh'
MANAGE_PCSCD_SCRIPT = REPO_ROOT / 'docker/trustpoint/wizard/manage_pcscd.sh'
TRUSTPOINT_ENTRYPOINT_SCRIPT = REPO_ROOT / 'docker/trustpoint/entrypoint.sh'
SWITCH_TO_OPERATIONAL_SCRIPT = REPO_ROOT / 'docker/trustpoint/wizard/switch_to_operational.sh'
NGINX_SITE_CONFIG = REPO_ROOT / 'docker/trustpoint/nginx/trustpoint-nginx-https.conf'
TRUSTPOINT_SERVICE_SCRIPT = REPO_ROOT / 'scripts/tp_wizard/services/trustpoint.sh'
TP_WIZARD_STATE_SCRIPT = REPO_ROOT / 'scripts/tp_wizard/state.sh'
TP_WIZARD_CLI_SCRIPT = REPO_ROOT / 'scripts/tp_wizard/commands/cli.sh'
MISSING_CREDENTIAL_EXIT_CODE = 5
NGINX_PROXIED_LOCATION_COUNT = 3


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
    assert 'nginx reload is not required' in second_run.stdout


def test_update_tls_rejects_missing_credentials(tmp_path: Path) -> None:
    """Startup fails clearly when neither staged nor installed TLS files exist."""
    result = _run_update_tls(tmp_path)

    assert result.returncode == MISSING_CREDENTIAL_EXIT_CODE
    assert 'No complete staged or installed TLS credential is available' in result.stdout


def test_container_pcscd_startup_does_not_require_polkit() -> None:
    """Bootstrap and operational PC/SC daemons accept container-local clients."""
    for script in (MANAGE_PCSCD_SCRIPT, TRUSTPOINT_ENTRYPOINT_SCRIPT):
        commands = [
            line.strip()
            for line in script.read_text(encoding='utf-8').splitlines()
            if line.strip().startswith('pcscd ')
        ]

        assert commands
        assert all('--disable-polkit' in command for command in commands)


def test_operational_handoff_uses_stable_nginx_upstream() -> None:
    """Runtime selection must not depend on rewriting or reloading nginx."""
    nginx_config = NGINX_SITE_CONFIG.read_text(encoding='utf-8')
    entrypoint = TRUSTPOINT_ENTRYPOINT_SCRIPT.read_text(encoding='utf-8')
    handoff = SWITCH_TO_OPERATIONAL_SCRIPT.read_text(encoding='utf-8')

    assert 'server 127.0.0.1:8001 max_fails=1 fail_timeout=1s;' in nginx_config
    assert 'server 127.0.0.1:8000 backup;' in nginx_config
    assert nginx_config.count('proxy_pass http://trustpoint_application;') == NGINX_PROXIED_LOCATION_COUNT
    assert 'proxy_pass http://127.0.0.1:' not in nginx_config
    assert 'BOOTSTRAP_GUNICORN_PORT=8000' in entrypoint
    assert 'OPERATIONAL_GUNICORN_PORT=8001' in entrypoint
    assert '--bind 0.0.0.0:${gunicorn_port}' in entrypoint
    assert 'nginx -s reload' not in handoff
    assert 'switch_nginx_proxy' not in handoff
    assert handoff.count('/etc/trustpoint/wizard/update_tls.sh') == 1


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
APP_DB_HOST=postgres
APP_DB_PORT=5432
TP_ADMIN_USERNAME=admin
TP_ADMIN_PASSWORD=password
TP_ADMIN_EMAIL=admin@example.test
TP_AUTO_SETUP=true
TP_INJECT_DEMO_DATA=true
TP_TLS_DNS_NAMES=trustpoint.local
TP_TLS_IPV4_ADDRESSES=
TP_TLS_IPV6_ADDRESSES=
ENABLE_METRICS=false
ENABLE_USB_PASSTHROUGH=false
APP_IMAGE=trustpoint:test
build_trustpoint() {{ :; }}
remove_compose_service() {{ :; }}
remove_container() {{ :; }}
state_has() {{ return 1; }}
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


def test_trustpoint_launcher_exposes_available_usb_bus(tmp_path: Path) -> None:
    """The common launcher makes USB available without selecting a different startup mode."""
    usb_bus = tmp_path / 'usb'
    usb_bus.mkdir()
    harness = f"""
set -euo pipefail
source "{TRUSTPOINT_SERVICE_SCRIPT}"
BUILD_LOCAL=false
TP_USB_BUS_PATH="{usb_bus}"
TP_HTTP_PORT=8080
TP_HTTPS_PORT=8443
DB_NAME=trustpoint_db
DB_USER=admin
DB_PASS=password
APP_DB_HOST=postgres
APP_DB_PORT=5432
TP_ADMIN_USERNAME=admin
TP_ADMIN_PASSWORD=password
TP_ADMIN_EMAIL=admin@example.test
TP_AUTO_SETUP=false
TP_INJECT_DEMO_DATA=false
TP_TLS_DNS_NAMES=trustpoint.local
TP_TLS_IPV4_ADDRESSES=
TP_TLS_IPV6_ADDRESSES=
ENABLE_METRICS=false
ENABLE_USB_PASSTHROUGH=true
APP_IMAGE=trustpoint:test
build_trustpoint() {{ :; }}
remove_compose_service() {{ :; }}
remove_container() {{ :; }}
state_has() {{ return 1; }}
ok() {{ :; }}
start_container() {{ printf '<%s>\n' "$@"; }}
start_trustpoint
"""

    result = subprocess.run(  # noqa: S603
        ['/bin/bash', '-c', harness],
        check=True,
        capture_output=True,
        text=True,
    )

    assert f'<type=bind,source={usb_bus},target=/dev/bus/usb>' in result.stdout
    assert '<c 189:* rwm>' in result.stdout


def test_trustpoint_launcher_does_not_expose_usb_without_opt_in(tmp_path: Path) -> None:
    """USB access is absent unless the setup-script option is selected."""
    usb_bus = tmp_path / 'usb'
    usb_bus.mkdir()
    harness = f"""
set -euo pipefail
source "{TRUSTPOINT_SERVICE_SCRIPT}"
BUILD_LOCAL=false
ENABLE_USB_PASSTHROUGH=false
TP_USB_BUS_PATH="{usb_bus}"
TP_HTTP_PORT=8080
TP_HTTPS_PORT=8443
DB_NAME=trustpoint_db
DB_USER=admin
DB_PASS=password
APP_DB_HOST=postgres
APP_DB_PORT=5432
TP_ADMIN_USERNAME=admin
TP_ADMIN_PASSWORD=password
TP_ADMIN_EMAIL=admin@example.test
TP_AUTO_SETUP=false
TP_INJECT_DEMO_DATA=false
TP_TLS_DNS_NAMES=trustpoint.local
TP_TLS_IPV4_ADDRESSES=
TP_TLS_IPV6_ADDRESSES=
ENABLE_METRICS=false
APP_IMAGE=trustpoint:test
build_trustpoint() {{ :; }}
remove_compose_service() {{ :; }}
remove_container() {{ :; }}
state_has() {{ return 1; }}
ok() {{ :; }}
start_container() {{ printf '<%s>\n' "$@"; }}
start_trustpoint
"""

    result = subprocess.run(  # noqa: S603
        ['/bin/bash', '-c', harness],
        check=True,
        capture_output=True,
        text=True,
    )

    assert '/dev/bus/usb' not in result.stdout
    assert '<TP_USB_HSM_PASSTHROUGH=false>' in result.stdout


def test_cli_up_usb_hsm_option_enables_passthrough() -> None:
    """Command mode exposes an explicit USB HSM passthrough option."""
    harness = f"""
set -euo pipefail
source "{TP_WIZARD_STATE_SCRIPT}"
runtime_start() {{ :; }}
summary() {{ :; }}
die() {{ printf '%s\n' "$1" >&2; return 1; }}
source "{TP_WIZARD_CLI_SCRIPT}"
cli_up trustpoint db --usb-hsm
$ENABLE_USB_PASSTHROUGH
state_has trustpoint
state_has db
"""

    subprocess.run(  # noqa: S603
        ['/bin/bash', '-c', harness],
        check=True,
        capture_output=True,
        text=True,
    )
