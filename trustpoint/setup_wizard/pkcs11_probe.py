# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Probe staged PKCS#11 providers outside the web worker."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11AuthSource,
    AppSecretPkcs11ConfigModel,
)
from appsecrets.service import Pkcs11AppSecretService
from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.pkcs11_local_dev import (
    local_dev_pkcs11_config_available,
    local_dev_pkcs11_config_env_var,
    local_dev_pkcs11_config_path,
)

logger = logging.getLogger(__name__)
FINAL_WIZARD_PKCS11_MODULE_PATH = Path(settings.HSM_LIB_DIR) / 'uploaded-pkcs11-module.so'
FINAL_WIZARD_PKCS11_PIN_PATH = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
FINAL_WIZARD_PKCS11_CONFIG_PATH = Path(settings.HSM_CONFIG_DIR) / 'uploaded-pkcs11-provider.cfg'
MAX_PKCS11_PROBE_OUTPUT_LENGTH = 4000
PKCS11_PROBE_TIMEOUT_SECONDS = 30


def apply_pkcs11_probe_fallbacks(config_model: SetupWizardConfigModel) -> tuple[str, str, list[str]]:
    """Apply runtime fallback PKCS#11 paths before probing a staged backend."""
    module_path = (config_model.fresh_install_pkcs11_module_path or '').strip()
    pin_file = (config_model.fresh_install_pkcs11_auth_source_ref or '').strip()
    config_file = (config_model.fresh_install_pkcs11_config_path or '').strip()
    config_env_var = (config_model.fresh_install_pkcs11_config_env_var or '').strip()
    fallback_update_fields: list[str] = []

    if (not module_path or not pkcs11_path_exists(Path(module_path))) and pkcs11_path_exists(
        FINAL_WIZARD_PKCS11_MODULE_PATH
    ):
        module_path = str(FINAL_WIZARD_PKCS11_MODULE_PATH)
        config_model.fresh_install_pkcs11_module_path = module_path
        fallback_update_fields.append('fresh_install_pkcs11_module_path')

    if (not pin_file or not pkcs11_path_exists(Path(pin_file))) and pkcs11_path_exists(FINAL_WIZARD_PKCS11_PIN_PATH):
        pin_file = str(FINAL_WIZARD_PKCS11_PIN_PATH)
        config_model.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        config_model.fresh_install_pkcs11_auth_source_ref = pin_file
        fallback_update_fields.extend(['fresh_install_pkcs11_auth_source', 'fresh_install_pkcs11_auth_source_ref'])

    if (not config_file or not pkcs11_path_exists(Path(config_file))) and pkcs11_path_exists(
        FINAL_WIZARD_PKCS11_CONFIG_PATH
    ):
        config_file = str(FINAL_WIZARD_PKCS11_CONFIG_PATH)
        config_model.fresh_install_pkcs11_config_path = config_file
        fallback_update_fields.append('fresh_install_pkcs11_config_path')
    elif (not config_file or not pkcs11_path_exists(Path(config_file))) and local_dev_pkcs11_config_available():
        config_file = str(local_dev_pkcs11_config_path())
        config_model.fresh_install_pkcs11_config_path = config_file
        fallback_update_fields.append('fresh_install_pkcs11_config_path')
        if not config_env_var:
            config_env_var = local_dev_pkcs11_config_env_var()
            config_model.fresh_install_pkcs11_config_env_var = config_env_var
            fallback_update_fields.append('fresh_install_pkcs11_config_env_var')
    elif config_file and not config_env_var and local_dev_pkcs11_config_available():
        local_dev_config = str(local_dev_pkcs11_config_path())
        if config_file == local_dev_config:
            config_env_var = local_dev_pkcs11_config_env_var()
            config_model.fresh_install_pkcs11_config_env_var = config_env_var
            fallback_update_fields.append('fresh_install_pkcs11_config_env_var')

    if config_file and config_env_var:
        os.environ[config_env_var] = config_file

    return module_path, pin_file, fallback_update_fields


def validate_pkcs11_probe_inputs(
    *,
    module_path: str,
    pin_file: str,
    token_label: str | None,
    slot_id: int | None,
) -> None:
    """Validate the minimum PKCS#11 settings needed for a probe."""
    if not module_path:
        err_msg = 'No PKCS#11 module path is configured for the setup wizard.'
        raise DjangoValidationError(err_msg)

    if not pin_file:
        err_msg = 'No PKCS#11 user PIN file is configured for the setup wizard.'
        raise DjangoValidationError(err_msg)

    if token_label is None and slot_id is None:
        err_msg = 'No PKCS#11 token selector is configured. Enter a token label or slot ID.'
        raise DjangoValidationError(err_msg)


def build_pkcs11_probe_profile(
    *,
    profile_name: str,
    module_path: str,
    pin_file: str,
    token_selector: Pkcs11TokenSelector,
) -> Pkcs11ProviderProfile:
    """Build a PKCS#11 profile for a staged wizard probe."""
    return Pkcs11ProviderProfile(
        name=profile_name,
        module_path=module_path,
        token=token_selector,
        user_pin_file=pin_file,
        max_sessions=2,
        borrow_timeout_seconds=5.0,
        rw_sessions=True,
    )


def refresh_pkcs11_probe_capabilities(
    profile: Pkcs11ProviderProfile,
) -> Any:
    """Authenticate and probe PKCS#11 capabilities for the given staged profile."""
    backend = Pkcs11Backend(profile=profile)
    try:
        backend.verify_authentication()
        capabilities = backend.probe_capabilities()
    except Exception as exception:
        backend.log_runtime_diagnostics(logging.WARNING)
        error_detail = str(exception).strip() or type(exception).__name__
        err_msg = f'PKCS#11 probe failed: {error_detail}. Diagnostics: {backend.diagnostic_summary()}'
        raise DjangoValidationError(err_msg) from exception
    else:
        return capabilities
    finally:
        backend.close()


def validate_pkcs11_app_secret_protection_support(profile: Pkcs11ProviderProfile) -> None:
    """Verify the staged PKCS#11 backend supports Trustpoint app-secret DEK protection."""
    if profile.user_pin_file:
        auth_source = AppSecretPkcs11AuthSource.FILE
        auth_source_ref = profile.user_pin_file
    elif profile.user_pin_env_var:
        auth_source = AppSecretPkcs11AuthSource.ENV
        auth_source_ref = profile.user_pin_env_var
    else:
        err_msg = 'App-secret PKCS#11 self-test requires a PIN file or PIN environment variable.'
        raise DjangoValidationError(err_msg)

    backend = AppSecretBackendModel(backend_kind=AppSecretBackendKind.PKCS11)
    app_secret_config = AppSecretPkcs11ConfigModel(
        backend=backend,
        module_path=profile.module_path,
        token_label=profile.token.token_label or '',
        token_serial=profile.token.token_serial or '',
        slot_id=profile.token.slot_id,
        auth_source=auth_source,
        auth_source_ref=auth_source_ref,
    )
    Pkcs11AppSecretService(app_secret_config).verify_temporary_dek_protection_support()


def build_staged_pkcs11_probe_profile(
    config_model: SetupWizardConfigModel,
    *,
    profile_name: str,
) -> tuple[Pkcs11ProviderProfile, list[str]]:
    """Build a PKCS#11 probe profile from staged wizard settings."""
    module_path, pin_file, update_fields = apply_pkcs11_probe_fallbacks(config_model)
    slot_id = config_model.fresh_install_pkcs11_slot_id
    token_label = (config_model.fresh_install_pkcs11_token_label or '').strip() or None
    token_serial = (config_model.fresh_install_pkcs11_token_serial or '').strip() or None

    validate_pkcs11_probe_inputs(
        module_path=module_path,
        pin_file=pin_file,
        token_label=token_label,
        slot_id=slot_id,
    )
    return (
        build_pkcs11_probe_profile(
            profile_name=profile_name,
            module_path=module_path,
            pin_file=pin_file,
            token_selector=Pkcs11TokenSelector(token_label=token_label, token_serial=token_serial, slot_id=slot_id),
        ),
        update_fields,
    )


def persist_pkcs11_probe_capabilities(
    config_model: SetupWizardConfigModel,
    capabilities: Any,
    update_fields: list[str],
) -> None:
    """Persist selector details discovered during a staged PKCS#11 probe."""
    if capabilities.token.label and capabilities.token.label != config_model.fresh_install_pkcs11_token_label:
        config_model.fresh_install_pkcs11_token_label = capabilities.token.label
        update_fields.append('fresh_install_pkcs11_token_label')

    if capabilities.token.serial and capabilities.token.serial != config_model.fresh_install_pkcs11_token_serial:
        config_model.fresh_install_pkcs11_token_serial = capabilities.token.serial
        update_fields.append('fresh_install_pkcs11_token_serial')

    if capabilities.token.slot_id != config_model.fresh_install_pkcs11_slot_id:
        config_model.fresh_install_pkcs11_slot_id = capabilities.token.slot_id
        update_fields.append('fresh_install_pkcs11_slot_id')

    if update_fields:
        config_model.save(update_fields=update_fields)


def probe_staged_pkcs11_config(config_model: SetupWizardConfigModel, *, profile_name: str) -> Any:
    """Authenticate against the staged PKCS#11 backend and persist discovered selector details."""
    profile, update_fields = build_staged_pkcs11_probe_profile(config_model, profile_name=profile_name)
    capabilities = refresh_pkcs11_probe_capabilities(profile)
    persist_pkcs11_probe_capabilities(config_model, capabilities, update_fields)
    return capabilities


def validate_staged_pkcs11_app_secret_protection(
    config_model: SetupWizardConfigModel,
    *,
    profile_name: str,
) -> None:
    """Verify staged PKCS#11 config can protect Trustpoint application secrets."""
    profile, _update_fields = build_staged_pkcs11_probe_profile(config_model, profile_name=profile_name)
    try:
        validate_pkcs11_app_secret_protection_support(profile)
    except Exception as exception:
        error_detail = str(exception).strip() or type(exception).__name__
        err_msg = f'PKCS#11 app-secret protection self-test failed: {error_detail}'
        raise DjangoValidationError(err_msg) from exception


def _format_pkcs11_probe_process_output(completed_process: subprocess.CompletedProcess[str]) -> str:
    """Return bounded stdout/stderr from an isolated PKCS#11 probe process."""
    output = '\n'.join(
        part.strip() for part in (completed_process.stdout, completed_process.stderr) if part and part.strip()
    )
    if len(output) > MAX_PKCS11_PROBE_OUTPUT_LENGTH:
        return output[-MAX_PKCS11_PROBE_OUTPUT_LENGTH:]
    return output


def _run_isolated_probe(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Bound native-provider calls and terminate a stuck child before returning an error."""
    try:
        return subprocess.run(  # noqa: S603 - fixed management commands, not shell input.
            command,
            cwd=str(settings.REPO_ROOT),
            env=os.environ.copy(),
            text=True,
            capture_output=True,
            check=False,
            timeout=PKCS11_PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exception:
        msg = f'PKCS#11 probe timed out after {PKCS11_PROBE_TIMEOUT_SECONDS} seconds. Check the provider connection.'
        raise DjangoValidationError(msg) from exception


def probe_staged_pkcs11_config_isolated(
    config_model: SetupWizardConfigModel,
    *,
    profile_name: str,
) -> Pkcs11Capabilities:
    """Run the staged PKCS#11 probe in a subprocess so native crashes cannot kill the web worker."""
    command = [
        sys.executable,
        str(settings.BASE_DIR / 'manage.py'),
        'probe_setup_wizard_pkcs11',
        '--profile-name',
        profile_name,
    ]

    completed_process = _run_isolated_probe(command)
    if completed_process.returncode != 0:
        failure = (
            f'signal {-completed_process.returncode}'
            if completed_process.returncode < 0
            else f'exit code {completed_process.returncode}'
        )
        output = _format_pkcs11_probe_process_output(completed_process)
        logger.error(
            'Isolated PKCS#11 setup-wizard probe failed with %s. Captured output: %s',
            failure,
            output or 'no process output',
        )
        if completed_process.returncode < 0:
            err_msg = (
                f'PKCS#11 probe process crashed with {failure}. '
                'The PKCS#11 provider library terminated the probe process.'
            )
        elif output:
            err_msg = f'PKCS#11 probe process failed with {failure}: {output}'
        else:
            err_msg = f'PKCS#11 probe process failed with {failure}. Check the Trustpoint log for details.'
        raise DjangoValidationError(err_msg)

    output_lines = [line for line in completed_process.stdout.splitlines() if line.strip()]
    if not output_lines:
        err_msg = 'PKCS#11 probe process completed without returning capabilities.'
        raise DjangoValidationError(err_msg)

    try:
        capabilities = Pkcs11Capabilities.from_json_dict(json.loads(output_lines[-1]))
    except (json.JSONDecodeError, TypeError, KeyError, ValueError) as exception:
        output = _format_pkcs11_probe_process_output(completed_process)
        logger.exception(
            'Isolated PKCS#11 setup-wizard probe returned invalid capabilities. Captured output: %s',
            output or 'no process output',
        )
        err_msg = 'PKCS#11 probe process returned invalid capabilities. Check the Trustpoint log for details.'
        raise DjangoValidationError(err_msg) from exception

    config_model.refresh_from_db()
    return capabilities


def validate_staged_pkcs11_app_secret_protection_isolated(
    config_model: SetupWizardConfigModel,
    *,
    profile_name: str,
) -> None:
    """Run the staged PKCS#11 app-secret protection self-test in an isolated subprocess."""
    completed_process = _run_isolated_probe(
        [
            sys.executable,
            str(settings.BASE_DIR / 'manage.py'),
            'test_setup_wizard_pkcs11_app_secret',
            '--profile-name',
            profile_name,
        ]
    )
    if completed_process.returncode == 0:
        config_model.refresh_from_db()
        return

    failure = (
        f'signal {-completed_process.returncode}'
        if completed_process.returncode < 0
        else f'exit code {completed_process.returncode}'
    )
    output = _format_pkcs11_probe_process_output(completed_process)
    logger.error(
        'Isolated PKCS#11 app-secret self-test failed with %s. Captured output: %s',
        failure,
        output or 'no process output',
    )
    if completed_process.returncode < 0:
        err_msg = (
            f'PKCS#11 app-secret self-test process crashed with {failure}. '
            'The PKCS#11 provider library terminated the self-test process.'
        )
    elif output:
        err_msg = f'PKCS#11 app-secret self-test process failed with {failure}: {output}'
    else:
        err_msg = f'PKCS#11 app-secret self-test process failed with {failure}. Check the Trustpoint log for details.'
    raise DjangoValidationError(err_msg)


def validate_staged_pkcs11_app_secret_protection_if_required(
    config_model: SetupWizardConfigModel,
    *,
    profile_name: str,
) -> None:
    """Run the isolated app-secret self-test when the staged policy requires it."""
    if config_model.fresh_install_pkcs11_enforce_app_secret_protection:
        validate_staged_pkcs11_app_secret_protection_isolated(config_model, profile_name=profile_name)


def pkcs11_path_exists(path: Path) -> bool:
    """Return whether a setup-wizard path exists without leaking permission errors."""
    try:
        return path.exists()
    except OSError:
        return False
