"""Helpers for explicitly handing bootstrap configuration to operational mode."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError

if TYPE_CHECKING:
    from setup_wizard.models import SetupWizardConfigModel

MANAGE_PY = settings.BASE_DIR / 'manage.py'
DEFAULT_CONTAINER_OPERATIONAL_ENV_FILE = Path('/var/lib/trustpoint/bootstrap/operational.env')
DEFAULT_LOCAL_OPERATIONAL_ENV_FILE = settings.REPO_ROOT / 'var' / 'bootstrap' / 'operational.env'
SWITCH_TO_OPERATIONAL_SCRIPT = Path('/etc/trustpoint/wizard/switch_to_operational.sh')
SUDO_EXECUTABLE = '/usr/bin/sudo'
MAX_CAPTURED_OUTPUT_LENGTH = 4000
PASSTHROUGH_OPERATIONAL_ENV_KEYS = (
    'PKCS11_PROXY_SOCKET',
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
    'EMAIL_HOST',
    'EMAIL_PORT',
    'EMAIL_USE_TLS',
    'EMAIL_USE_SSL',
    'DEFAULT_FROM_EMAIL',
)


@dataclass(frozen=True, slots=True)
class OperationalHandoffResult:
    """Result metadata for a completed operational handoff."""

    env_file: Path
    pending_env_file: Path
    ready_file: Path
    payload_file: Path


@dataclass(frozen=True, slots=True)
class OperationalRuntimeSwitchResult:
    """Result metadata for switching the running container to operational mode."""

    switched: bool
    detail: str


def operational_env_file_path() -> Path:
    """Return the persisted environment file used by container auto phase selection."""
    configured_path = os.getenv('TRUSTPOINT_OPERATIONAL_ENV_FILE')
    if configured_path:
        return Path(configured_path)
    if getattr(settings, 'DOCKER_CONTAINER', False):
        return DEFAULT_CONTAINER_OPERATIONAL_ENV_FILE
    return DEFAULT_LOCAL_OPERATIONAL_ENV_FILE


def pending_operational_env_file_path() -> Path:
    """Return the non-final environment file used while switching runtime in-place."""
    return operational_env_file_path().with_name('operational.pending.env')


def operational_ready_file_path() -> Path:
    """Return the marker that confirms the operational runtime switch succeeded."""
    configured_path = os.getenv('TRUSTPOINT_OPERATIONAL_READY_FILE')
    if configured_path:
        return Path(configured_path)
    return operational_env_file_path().with_name('operational.ready')


def operational_payload_file_path() -> Path:
    """Return the payload file consumed by the operational apply command."""
    return operational_env_file_path().with_name('bootstrap-apply.json')


def build_operational_environment(config_model: SetupWizardConfigModel) -> dict[str, str]:
    """Build the explicit operational environment from bootstrap-staged DB settings."""
    env_values = {
        'DJANGO_SETTINGS_MODULE': 'trustpoint.settings',
        'TRUSTPOINT_PHASE': 'operational',
        'TRUSTPOINT_OPERATIONAL_DATABASE': 'postgresql',
        'DATABASE_ENGINE': 'django.db.backends.postgresql',
        'DATABASE_HOST': config_model.operational_db_host,
        'DATABASE_PORT': str(config_model.operational_db_port),
        'POSTGRES_DB': config_model.operational_db_name,
        'DATABASE_USER': config_model.operational_db_user,
        'DATABASE_PASSWORD': config_model.operational_db_password,
    }
    for key in PASSTHROUGH_OPERATIONAL_ENV_KEYS:
        value = os.getenv(key)
        if value is not None:
            env_values[key] = value
    return env_values


def build_apply_payload(config_model: SetupWizardConfigModel) -> dict[str, Any]:
    """Serialize bootstrap-staged setup choices for the operational apply command."""
    return {
        'admin': {
            'username': config_model.operational_admin_username,
            'email': config_model.operational_admin_email,
            'password_hash': config_model.operational_admin_password_hash,
        },
        'database': {
            'host': config_model.operational_db_host,
            'port': config_model.operational_db_port,
            'name': config_model.operational_db_name,
            'user': config_model.operational_db_user,
        },
        'fresh_install': {
            'crypto_storage': int(config_model.crypto_storage),
            'inject_demo_data': bool(config_model.inject_demo_data),
            'pkcs11_module_path': config_model.fresh_install_pkcs11_module_path,
            'pkcs11_token_label': config_model.fresh_install_pkcs11_token_label,
            'pkcs11_token_serial': config_model.fresh_install_pkcs11_token_serial,
            'pkcs11_slot_id': config_model.fresh_install_pkcs11_slot_id,
            'pkcs11_auth_source': config_model.fresh_install_pkcs11_auth_source,
            'pkcs11_auth_source_ref': config_model.fresh_install_pkcs11_auth_source_ref,
            'tls_mode': config_model.fresh_install_tls_mode,
        },
    }


def write_operational_env_file(env_values: dict[str, str], env_file: Path) -> None:
    """Persist the operational environment in a shell-sourceable file."""
    env_file.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        '# Generated by the Trustpoint bootstrap setup wizard.',
        '# This file is the explicit handoff marker for operational mode.',
    ]
    lines.extend(f'export {key}={shlex.quote(value)}' for key, value in sorted(env_values.items()))
    env_file.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    env_file.chmod(0o600)


def promote_operational_env_file(source_env_file: Path, final_env_file: Path) -> None:
    """Promote a successfully used handoff env file to the auto-start marker path."""
    final_env_file.parent.mkdir(parents=True, exist_ok=True)
    if source_env_file.resolve() == final_env_file.resolve():
        final_env_file.chmod(0o600)
        return
    source_env_file.replace(final_env_file)
    final_env_file.chmod(0o600)


def write_operational_ready_file(ready_file: Path) -> None:
    """Persist the marker that allows future auto-starts to enter operational mode."""
    ready_file.parent.mkdir(parents=True, exist_ok=True)
    ready_file.write_text('ready\n', encoding='utf-8')
    ready_file.chmod(0o600)


def clear_operational_ready_file(ready_file: Path) -> None:
    """Remove a stale operational ready marker before attempting a new handoff."""
    try:
        ready_file.unlink()
    except FileNotFoundError:
        return


def write_apply_payload(payload: dict[str, Any], payload_file: Path) -> None:
    """Persist the operational apply payload."""
    payload_file.parent.mkdir(parents=True, exist_ok=True)
    payload_file.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')
    payload_file.chmod(0o600)


def _run_operational_manage_command(args: list[str], env_values: dict[str, str]) -> None:
    """Run a Django management command in operational mode."""
    env = os.environ.copy()
    env.update(env_values)
    completed_process = subprocess.run(  # noqa: S603
        [sys.executable, str(MANAGE_PY), *args],
        cwd=str(settings.REPO_ROOT),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed_process.returncode == 0:
        return

    output = '\n'.join(
        part.strip()
        for part in (completed_process.stdout, completed_process.stderr)
        if part and part.strip()
    )
    if len(output) > MAX_CAPTURED_OUTPUT_LENGTH:
        output = output[-MAX_CAPTURED_OUTPUT_LENGTH:]
    err_msg = f"Operational command {' '.join(args)!r} failed: {output or 'no command output'}"
    raise DjangoValidationError(err_msg)


def _format_completed_process_output(completed_process: subprocess.CompletedProcess[str]) -> str:
    """Return bounded stdout/stderr text for user-facing validation errors."""
    output = '\n'.join(
        part.strip()
        for part in (completed_process.stdout, completed_process.stderr)
        if part and part.strip()
    )
    if len(output) > MAX_CAPTURED_OUTPUT_LENGTH:
        return output[-MAX_CAPTURED_OUTPUT_LENGTH:]
    return output


def run_operational_handoff(config_model: SetupWizardConfigModel) -> OperationalHandoffResult:
    """Apply bootstrap configuration to the operational DB and persist the handoff marker."""
    env_file = operational_env_file_path()
    pending_env_file = pending_operational_env_file_path()
    ready_file = operational_ready_file_path()
    payload_file = operational_payload_file_path()
    env_values = build_operational_environment(config_model)
    payload = build_apply_payload(config_model)

    clear_operational_ready_file(ready_file)
    write_apply_payload(payload, payload_file)
    _run_operational_manage_command(['migrate', '--noinput'], env_values)
    _run_operational_manage_command(['apply_bootstrap_config', '--config', str(payload_file)], env_values)
    write_operational_env_file(env_values, pending_env_file)

    return OperationalHandoffResult(
        env_file=env_file,
        pending_env_file=pending_env_file,
        ready_file=ready_file,
        payload_file=payload_file,
    )


def refresh_pending_operational_env(config_model: SetupWizardConfigModel) -> OperationalHandoffResult:
    """Rewrite the pending operational env without re-applying operational database state."""
    env_file = operational_env_file_path()
    pending_env_file = pending_operational_env_file_path()
    ready_file = operational_ready_file_path()
    payload_file = operational_payload_file_path()

    clear_operational_ready_file(ready_file)
    write_operational_env_file(build_operational_environment(config_model), pending_env_file)

    return OperationalHandoffResult(
        env_file=env_file,
        pending_env_file=pending_env_file,
        ready_file=ready_file,
        payload_file=payload_file,
    )


def run_operational_runtime_switch(env_file: Path | None = None) -> OperationalRuntimeSwitchResult:
    """Switch a running Docker web container from bootstrap to operational mode."""
    if not getattr(settings, 'DOCKER_CONTAINER', False):
        return OperationalRuntimeSwitchResult(
            switched=False,
            detail='Runtime switch is only available inside the Trustpoint container.',
        )

    if not SWITCH_TO_OPERATIONAL_SCRIPT.is_file():
        err_msg = (
            f'Operational runtime switch script is missing: {SWITCH_TO_OPERATIONAL_SCRIPT}. '
            'Rebuild the Trustpoint container so the bootstrap handoff tooling is installed.'
        )
        raise DjangoValidationError(err_msg)

    handoff_env_file = env_file or operational_env_file_path()
    if env_file is None and not handoff_env_file.is_file():
        pending_env_file = pending_operational_env_file_path()
        if pending_env_file.is_file():
            handoff_env_file = pending_env_file

    completed_process = subprocess.run(  # noqa: S603
        [SUDO_EXECUTABLE, str(SWITCH_TO_OPERATIONAL_SCRIPT), str(handoff_env_file)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed_process.returncode == 0:
        try:
            promote_operational_env_file(handoff_env_file, operational_env_file_path())
            write_operational_ready_file(operational_ready_file_path())
        except OSError as exception:
            err_msg = f'Operational runtime started, but the final handoff marker could not be written: {exception}'
            raise DjangoValidationError(err_msg) from exception
        return OperationalRuntimeSwitchResult(switched=True, detail=completed_process.stdout.strip())

    output = _format_completed_process_output(completed_process)
    err_msg = f'Operational runtime switch failed: {output or "no script output"}'
    raise DjangoValidationError(err_msg)
