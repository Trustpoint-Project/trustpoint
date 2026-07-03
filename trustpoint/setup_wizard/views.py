"""Views for the users application."""

from __future__ import annotations

import contextlib
import enum
import gzip
import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import psycopg
from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management import CommandError, call_command
from django.db import DatabaseError, transaction
from django.db.models import ProtectedError
from django.forms import BaseForm
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views.generic import FormView, TemplateView, View

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11AuthSource,
    AppSecretPkcs11ConfigModel,
    AppSecretSoftwareConfigModel,
)
from appsecrets.service import (
    DEK_LENGTH_BYTES,
    AppSecretConfigurationError,
    Pkcs11AppSecretService,
    clear_app_secret_cache,
    get_app_secret_service,
)
from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding
from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector
from crypto.adapters.software.backend import SoftwareBackend
from crypto.adapters.software.bindings import SoftwareManagedKeyBinding
from crypto.adapters.software.config import SoftwareProviderProfile
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.errors import CryptoError
from crypto.domain.policies import SigningExecutionMode
from crypto.domain.refs import ManagedKeyVerificationStatus
from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    Pkcs11AuthSource,
    SoftwareKeyEncryptionSource,
)
from management.backup_artifacts import BackupManifestError, backup_manifest_path, verify_backup_manifest
from management.nginx_paths import (
    NGINX_CERT_CHAIN_PATH,
    NGINX_CERT_PATH,
    NGINX_KEY_PATH,
)
from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.operational_attach import (
    CompatibilityCheck,
    CompatibilitySeverity,
    OperationalAttachmentValidator,
    OperationalAttachMode,
    OperationalBackendBinding,
    OperationalCompatibilityReport,
    OperationalDatabaseConfig,
    OperationalStateSnapshot,
    OperationalTargetConfig,
    OperationalTargetInspector,
)
from setup_wizard.operational_handoff import (
    refresh_pending_operational_env,
    run_operational_attach_handoff,
    run_operational_handoff,
    run_operational_runtime_switch,
)
from setup_wizard.pkcs11_local_dev import (
    local_dev_pkcs11_config_available,
    local_dev_pkcs11_config_env_var,
    local_dev_pkcs11_config_path,
    local_dev_pkcs11_handoff_available,
    local_dev_pkcs11_module_path,
)
from setup_wizard.pkcs11_staging import (
    cleanup_wizard_pkcs11_staged_path,
    existing_wizard_pkcs11_staged_file,
    wizard_pkcs11_staging_root,
)
from setup_wizard.tls_credential import (
    TlsServerCredentialFileParser,
    TlsServerCredentialGenerator,
    clear_staged_tls_credential,
    extract_staged_tls_sans,
    get_staged_root_ca_certificate_serializer,
    load_staged_tls_credential,
    stage_tls_credential,
)
from trustpoint.logger import LoggerMixin

from .forms import (
    EmptyForm,
    FreshInstallAdminUserModelForm,
    FreshInstallBackendConfigModelForm,
    FreshInstallCryptoStorageModelForm,
    FreshInstallDatabaseModelForm,
    FreshInstallDemoDataModelForm,
    FreshInstallModelBaseForm,
    FreshInstallSummaryModelForm,
    FreshInstallTlsConfigForm,
    RestoreBackupImportForm,
)
from .models import SetupWizardCompletedModel, SetupWizardConfigModel

if TYPE_CHECKING:
    from django.utils.functional import Promise
    from trustpoint_core.serializer import CertificateSerializer

    from crypto.application.provider_backend import ManagedKeyBackendAdapter

logger = logging.getLogger(__name__)


STATE_FILE_DIR = Path('/etc/trustpoint/wizard/')
UPDATE_TLS_NGINX = STATE_FILE_DIR / Path('update_tls_nginx.sh')
INSTALL_PKCS11_ASSETS = STATE_FILE_DIR / Path('install_pkcs11_assets.sh')
FINAL_WIZARD_PKCS11_MODULE_PATH = Path(settings.HSM_LIB_DIR) / 'uploaded-pkcs11-module.so'
FINAL_WIZARD_PKCS11_PIN_PATH = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
FINAL_WIZARD_PKCS11_CONFIG_PATH = Path(settings.HSM_CONFIG_DIR) / 'uploaded-pkcs11-provider.cfg'
MAX_RESTORE_OUTPUT_LENGTH = 4000
MAX_PKCS11_PROBE_OUTPUT_LENGTH = 4000
GPG_EXECUTABLE = '/usr/bin/gpg'


def restore_backup_staging_root() -> Path:
    """Return the bootstrap-private directory for staged restore archives."""
    bootstrap_db_path = Path(str(settings.DATABASES['default']['NAME']))
    return bootstrap_db_path.parent / 'restore'


def staged_restore_archive(config_model: SetupWizardConfigModel) -> Path | None:
    """Return the staged restore archive path when it still exists."""
    configured_path = (config_model.restore_backup_archive_path or '').strip()
    if not configured_path:
        return None

    try:
        archive_path = Path(configured_path).resolve(strict=False)
    except (OSError, TypeError, ValueError):
        return None

    staging_root = restore_backup_staging_root().resolve(strict=False)
    if not archive_path.is_relative_to(staging_root) or not archive_path.is_file():
        return None
    return archive_path


def cleanup_staged_restore_archive(config_model: SetupWizardConfigModel) -> None:
    """Remove an obsolete staged restore archive."""
    archive_path = staged_restore_archive(config_model)
    if archive_path is None:
        return
    with contextlib.suppress(OSError):
        archive_path.unlink()


def stage_restore_backup_archive(uploaded_archive: Any) -> str:
    """Persist an uploaded restore archive in bootstrap-private storage."""
    original_name = str(getattr(uploaded_archive, 'name', '')).lower()
    suffixes = ('.dump.gz.gpg', '.dump.gpg', '.zip.gpg', '.dump.gz', '.dump', '.zip', '.gpg')
    suffix = next((value for value in suffixes if original_name.endswith(value)), '.dump')
    staging_root = restore_backup_staging_root()
    staging_root.mkdir(parents=True, exist_ok=True)
    staging_root.chmod(0o700)
    archive_path = staging_root / f'restore-{uuid.uuid4().hex}{suffix}'
    with archive_path.open('wb') as destination:
        for chunk in uploaded_archive.chunks():
            destination.write(chunk)
    archive_path.chmod(0o600)
    return str(archive_path)


def _looks_like_gzip(path: Path) -> bool:
    """Return whether the file starts with the gzip magic bytes."""
    with path.open('rb') as file:
        return file.read(2) == b'\x1f\x8b'


def _looks_like_gpg(path: Path) -> bool:
    """Return whether the file looks like an OpenPGP encrypted payload."""
    with path.open('rb') as file:
        prefix = file.read(64)
    return prefix.startswith(b'-----BEGIN PGP MESSAGE-----') or prefix[:1] in {b'\x85', b'\x8c', b'\x8d'}


def _open_restore_archive(archive_path: Path) -> Any:
    """Open a staged restore archive, transparently decompressing gzip files."""
    if _looks_like_gzip(archive_path):
        return gzip.open(archive_path, 'rb')
    return archive_path.open('rb')


def _restore_archive_is_custom_pg_dump(archive_path: Path) -> bool:
    """Return whether the staged archive is a PostgreSQL custom-format dump."""
    with _open_restore_archive(archive_path) as archive_file:
        return bool(archive_file.read(5) == b'PGDMP')


def _materialize_custom_restore_archive(archive_path: Path) -> Path:
    """Return a filesystem path containing an uncompressed PostgreSQL custom dump."""
    if not _looks_like_gzip(archive_path):
        return archive_path

    materialized_path = restore_backup_staging_root() / f'pgrestore-{uuid.uuid4().hex}.dump'
    try:
        with gzip.open(archive_path, 'rb') as source, materialized_path.open('wb') as destination:
            shutil.copyfileobj(source, destination)
        materialized_path.chmod(0o600)
    except OSError:
        with contextlib.suppress(OSError):
            materialized_path.unlink()
        raise
    return materialized_path


def _format_restore_process_output(completed_process: subprocess.CompletedProcess[bytes]) -> str:
    """Return bounded restore command output for the wizard."""
    stderr = completed_process.stderr.decode('utf-8', errors='replace').strip() if completed_process.stderr else ''
    stdout = completed_process.stdout.decode('utf-8', errors='replace').strip() if completed_process.stdout else ''
    output = stderr or stdout
    if len(output) > MAX_RESTORE_OUTPUT_LENGTH:
        return output[-MAX_RESTORE_OUTPUT_LENGTH:]
    return output


def _restore_failed_on_transaction_timeout(completed_process: subprocess.CompletedProcess[bytes]) -> bool:
    """Return whether pg_restore failed on a PostgreSQL transaction_timeout SET statement."""
    output = _format_restore_process_output(completed_process)
    return 'unrecognized configuration parameter "transaction_timeout"' in output


def _strip_transaction_timeout_from_plain_restore(sql_payload: bytes) -> bytes:
    """Remove pg_dump's PostgreSQL-17 transaction_timeout SET for older restore targets."""
    filtered_lines = [
        line for line in sql_payload.splitlines(keepends=True) if line.strip() != b'SET transaction_timeout = 0;'
    ]
    return b''.join(filtered_lines)


def _retry_custom_restore_without_transaction_timeout(
    *,
    materialized_restore_path: Path,
    common_args: list[str],
    env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    """Retry a custom dump restore after filtering unsupported transaction_timeout setup."""
    restore_options = ['--clean', '--if-exists', '--no-owner', '--no-privileges']
    dump_to_sql_command = [
        'pg_restore',
        '--format=custom',
        *restore_options,
        '--file=-',
        str(materialized_restore_path),
    ]
    dump_to_sql = subprocess.run(  # noqa: S603
        dump_to_sql_command,
        env=env,
        capture_output=True,
        check=False,
    )
    if dump_to_sql.returncode != 0:
        return dump_to_sql

    filtered_sql = _strip_transaction_timeout_from_plain_restore(dump_to_sql.stdout)
    psql_command = ['psql', '--set', 'ON_ERROR_STOP=1', '--single-transaction', *common_args]
    return subprocess.run(  # noqa: S603
        psql_command,
        input=filtered_sql,
        env=env,
        capture_output=True,
        check=False,
    )


def _decrypt_restore_archive_if_needed(archive_path: Path, backup_password: str) -> Path | None:
    """Decrypt a GPG-encrypted restore archive and return the temporary decrypted file path."""
    if not backup_password:
        return None
    if not _looks_like_gpg(archive_path):
        return None

    archive_name = archive_path.name.lower()
    if archive_name.endswith('.zip.gpg'):
        decrypted_suffix = '.zip'
    elif archive_name.endswith('.gz.gpg'):
        decrypted_suffix = '.dump.gz'
    else:
        decrypted_suffix = '.dump'
    decrypted_path = restore_backup_staging_root() / f'decrypted-{uuid.uuid4().hex}{decrypted_suffix}'
    completed_process = subprocess.run(  # noqa: S603
        [
            GPG_EXECUTABLE,
            '--batch',
            '--yes',
            '--pinentry-mode',
            'loopback',
            '--passphrase-fd',
            '0',
            '--output',
            str(decrypted_path),
            '--decrypt',
            str(archive_path),
        ],
        input=backup_password.encode('utf-8'),
        capture_output=True,
        check=False,
    )
    if completed_process.returncode == 0:
        decrypted_path.chmod(0o600)
        return decrypted_path

    output = _format_restore_process_output(completed_process)
    with contextlib.suppress(OSError):
        decrypted_path.unlink()
    msg = f'Backup archive decryption failed: {output or "gpg failed without output"}'
    raise DjangoValidationError(msg)


def _restore_payload_suffix(filename: str) -> str:
    """Return a safe suffix for an extracted PostgreSQL backup payload."""
    normalized_name = filename.lower()
    if normalized_name.endswith('.dump.gz'):
        return '.dump.gz'
    if normalized_name.endswith('.dump'):
        return '.dump'
    return '.dump'


def _backup_payload_infos(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Return PostgreSQL dump payload members from a Trustpoint backup bundle."""
    payload_infos: list[zipfile.ZipInfo] = []
    for member in archive.infolist():
        if member.is_dir():
            continue
        member_name = Path(member.filename).name.lower()
        if member_name.endswith('.manifest.json'):
            continue
        if member_name.endswith(('.dump', '.dump.gz')):
            payload_infos.append(member)
    return payload_infos


def _extract_restore_bundle_if_needed(archive_path: Path) -> Path | None:
    """Extract a Trustpoint ZIP backup bundle and verify its manifest sidecar."""
    if not zipfile.is_zipfile(archive_path):
        return None

    payload_path: Path | None = None
    manifest_path: Path | None = None
    try:
        with zipfile.ZipFile(archive_path) as backup_bundle:
            payload_infos = _backup_payload_infos(backup_bundle)
            if len(payload_infos) != 1:
                msg = 'Backup bundle must contain exactly one .dump or .dump.gz payload.'
                raise DjangoValidationError(msg)

            payload_info = payload_infos[0]
            payload_name = Path(payload_info.filename).name
            manifest_name = f'{payload_name}.manifest.json'
            manifest_info = next(
                (
                    member
                    for member in backup_bundle.infolist()
                    if not member.is_dir() and Path(member.filename).name == manifest_name
                ),
                None,
            )
            if manifest_info is None:
                msg = f'Backup bundle is missing matching manifest sidecar {manifest_name!r}.'
                raise DjangoValidationError(msg)

            staging_root = restore_backup_staging_root()
            staging_root.mkdir(parents=True, exist_ok=True)
            payload_path = staging_root / f'extracted-{uuid.uuid4().hex}{_restore_payload_suffix(payload_name)}'
            manifest_path = backup_manifest_path(payload_path)

            with backup_bundle.open(payload_info) as source, payload_path.open('wb') as destination:
                shutil.copyfileobj(source, destination)
            with backup_bundle.open(manifest_info) as source, manifest_path.open('wb') as destination:
                shutil.copyfileobj(source, destination)

            payload_path.chmod(0o600)
            manifest_path.chmod(0o600)
            verify_backup_manifest(payload_path)
            return payload_path
    except (BackupManifestError, OSError, zipfile.BadZipFile) as exc:
        for temporary_path in (manifest_path, payload_path):
            if temporary_path is not None:
                with contextlib.suppress(OSError):
                    temporary_path.unlink()
        msg = f'Backup bundle is invalid: {exc}'
        raise DjangoValidationError(msg) from exc


def restore_operational_database_from_backup(
    config_model: SetupWizardConfigModel,
    *,
    backup_password: str = '',
) -> None:
    """Restore the staged backup archive into the configured operational PostgreSQL database."""
    archive_path = staged_restore_archive(config_model)
    if archive_path is None:
        msg = 'No staged restore archive is available.'
        raise DjangoValidationError(msg)
    if _looks_like_gpg(archive_path) and not backup_password:
        msg_0 = 'This backup archive is encrypted. Enter the backup password.'
        raise DjangoValidationError(msg_0)

    decrypted_path: Path | None = None
    extracted_path: Path | None = None
    materialized_restore_path: Path | None = None
    try:
        decrypted_path = _decrypt_restore_archive_if_needed(archive_path, backup_password)
        extracted_path = _extract_restore_bundle_if_needed(decrypted_path or archive_path)
        restore_source_path = extracted_path or decrypted_path or archive_path

        env = os.environ.copy()
        env['PGPASSWORD'] = config_model.operational_db_password
        common_args = [
            '--host',
            config_model.operational_db_host,
            '--port',
            str(config_model.operational_db_port),
            '--username',
            config_model.operational_db_user,
            '--dbname',
            config_model.operational_db_name,
        ]
        if _restore_archive_is_custom_pg_dump(restore_source_path):
            materialized_restore_path = _materialize_custom_restore_archive(restore_source_path)
            command = [
                'pg_restore',
                '--format=custom',
                '--exit-on-error',
                '--single-transaction',
                '--clean',
                '--if-exists',
                '--no-owner',
                '--no-privileges',
                *common_args,
                str(materialized_restore_path),
            ]
            completed_process = subprocess.run(  # noqa: S603
                command,
                env=env,
                capture_output=True,
                check=False,
            )
            if completed_process.returncode != 0 and _restore_failed_on_transaction_timeout(completed_process):
                completed_process = _retry_custom_restore_without_transaction_timeout(
                    materialized_restore_path=materialized_restore_path,
                    common_args=common_args,
                    env=env,
                )
        else:
            command = ['psql', '--set', 'ON_ERROR_STOP=1', '--single-transaction', *common_args]
            with _open_restore_archive(restore_source_path) as archive_file:
                completed_process = subprocess.run(  # noqa: S603
                    command,
                    stdin=archive_file,
                    env=env,
                    capture_output=True,
                    check=False,
                )
    except FileNotFoundError as exception:
        error_message = f'Restore tool not available in this container: {exception.filename}.'
        raise DjangoValidationError(error_message) from exception
    finally:
        temporary_restore_paths = {archive_path, decrypted_path, extracted_path}
        if materialized_restore_path is not None and materialized_restore_path not in temporary_restore_paths:
            with contextlib.suppress(OSError):
                materialized_restore_path.unlink()
        if extracted_path is not None:
            with contextlib.suppress(OSError):
                backup_manifest_path(extracted_path).unlink()
            with contextlib.suppress(OSError):
                extracted_path.unlink()
        if decrypted_path is not None:
            with contextlib.suppress(OSError):
                decrypted_path.unlink()

    if completed_process.returncode == 0:
        return

    output = _format_restore_process_output(completed_process)
    msg = f'Database restore failed: {output or "restore command failed without output"}'
    raise DjangoValidationError(msg)


def record_bootstrap_progress(
    config_model: SetupWizardConfigModel,
    *,
    flow: SetupWizardConfigModel.BootstrapFlow | OperationalAttachMode,
    step_name: str,
) -> None:
    """Persist the currently visible bootstrap flow and step in SQLite."""
    config_model.bootstrap_active_flow = str(getattr(flow, 'value', flow))
    config_model.bootstrap_current_step = step_name
    config_model.save(update_fields=['bootstrap_active_flow', 'bootstrap_current_step'])


def is_pkcs11_test_connection_submission(request: HttpRequest) -> bool:
    """Return whether the current POST requests a PKCS#11 connection test."""
    return request.POST.get('wizard_action') == 'test_connection'


def is_clear_pkcs11_module_submission(request: HttpRequest) -> bool:
    """Return whether the current POST requests staged library removal."""
    return request.POST.get('wizard_action') == 'clear_module'


def is_clear_pkcs11_pin_submission(request: HttpRequest) -> bool:
    """Return whether the current POST requests staged PIN removal."""
    return request.POST.get('wizard_action') == 'clear_pin'


def is_clear_pkcs11_config_submission(request: HttpRequest) -> bool:
    """Return whether the current POST requests staged provider config removal."""
    return request.POST.get('wizard_action') == 'clear_pkcs11_config'


def is_clear_restore_backup_submission(request: HttpRequest) -> bool:
    """Return whether the current POST requests staged restore archive removal."""
    return request.POST.get('wizard_action') == 'clear_restore_backup'


def clear_staged_pkcs11_module(config_model: SetupWizardConfigModel) -> None:
    """Remove the currently staged PKCS#11 library for this wizard session."""
    cleanup_wizard_pkcs11_staged_path(config_model.fresh_install_pkcs11_module_path)
    execute_shell_script(INSTALL_PKCS11_ASSETS, '--clear-module')
    config_model.fresh_install_pkcs11_module_path = ''
    config_model.save(update_fields=['fresh_install_pkcs11_module_path'])


def clear_staged_pkcs11_pin(config_model: SetupWizardConfigModel) -> None:
    """Remove the currently staged PKCS#11 user PIN for this wizard session."""
    cleanup_wizard_pkcs11_staged_path(config_model.fresh_install_pkcs11_auth_source_ref)
    execute_shell_script(INSTALL_PKCS11_ASSETS, '--clear-pin')
    config_model.fresh_install_pkcs11_auth_source_ref = ''
    config_model.save(update_fields=['fresh_install_pkcs11_auth_source_ref'])


def clear_staged_pkcs11_config(config_model: SetupWizardConfigModel) -> None:
    """Remove the currently staged PKCS#11 provider config for this wizard session."""
    cleanup_wizard_pkcs11_staged_path(config_model.fresh_install_pkcs11_config_path)
    execute_shell_script(INSTALL_PKCS11_ASSETS, '--clear-config')
    config_model.fresh_install_pkcs11_config_path = ''
    config_model.fresh_install_pkcs11_config_env_var = ''
    config_model.save(update_fields=['fresh_install_pkcs11_config_path', 'fresh_install_pkcs11_config_env_var'])


def stage_uploaded_pkcs11_module(uploaded_module: Any) -> str:
    """Write an uploaded PKCS#11 library to private one-time wizard staging."""
    staging_root = wizard_pkcs11_staging_root()
    staging_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging_root.chmod(0o700)
    suffix = '.so' if '.so' in str(getattr(uploaded_module, 'name', '')).lower() else '.bin'
    staged_path = staging_root / f'pkcs11-module-{uuid.uuid4().hex}{suffix}'
    with staged_path.open('wb') as destination_file:
        for chunk in uploaded_module.chunks():
            destination_file.write(chunk)
    staged_path.chmod(0o600)
    return str(staged_path)


def stage_pkcs11_user_pin(user_pin: str) -> str:
    """Write the entered PKCS#11 user PIN to private one-time wizard staging."""
    staging_root = wizard_pkcs11_staging_root()
    staging_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging_root.chmod(0o700)
    staged_path = staging_root / f'pkcs11-user-pin-{uuid.uuid4().hex}.txt'
    staged_path.write_text(user_pin, encoding='utf-8')
    staged_path.chmod(0o600)
    return str(staged_path)


def stage_uploaded_pkcs11_config(uploaded_config: Any) -> str:
    """Write an optional provider PKCS#11 config to private one-time wizard staging."""
    staging_root = wizard_pkcs11_staging_root()
    staging_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging_root.chmod(0o700)
    suffix = Path(str(getattr(uploaded_config, 'name', 'provider.cfg'))).suffix or '.cfg'
    staged_path = staging_root / f'pkcs11-provider-config-{uuid.uuid4().hex}{suffix}'
    with staged_path.open('wb') as destination_file:
        for chunk in uploaded_config.chunks():
            destination_file.write(chunk)
    staged_path.chmod(0o600)
    return str(staged_path)


def _persist_local_dev_pkcs11_config_if_available(
    form: FreshInstallBackendConfigModelForm,
    update_fields: list[str],
    *,
    current_staged_config: Path | None,
    current_config_path: str,
    current_config_exists: bool,
) -> None:
    """Persist the local-dev PKCS#11 provider config when tp_wizard exposed one."""
    if current_staged_config is not None or not local_dev_pkcs11_config_available():
        return

    local_dev_config = str(local_dev_pkcs11_config_path())
    if current_config_path and current_config_path != local_dev_config and current_config_exists:
        return

    cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_config_path)
    form.instance.fresh_install_pkcs11_config_path = local_dev_config
    update_fields.append('fresh_install_pkcs11_config_path')
    if not form.instance.fresh_install_pkcs11_config_env_var:
        form.instance.fresh_install_pkcs11_config_env_var = local_dev_pkcs11_config_env_var()
        if 'fresh_install_pkcs11_config_env_var' not in update_fields:
            update_fields.append('fresh_install_pkcs11_config_env_var')


def persist_staged_pkcs11_backend_config(form: FreshInstallBackendConfigModelForm) -> None:
    """Persist staged PKCS#11 wizard inputs without advancing the wizard."""
    if form.instance.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
        return

    update_fields = [
        'fresh_install_pkcs11_token_label',
        'fresh_install_pkcs11_token_serial',
        'fresh_install_pkcs11_slot_id',
        'fresh_install_pkcs11_auth_source',
        'fresh_install_pkcs11_config_env_var',
        'fresh_install_pkcs11_enforce_app_secret_protection',
    ]

    previous_token_label = form.instance.fresh_install_pkcs11_token_label
    previous_slot_id = form.instance.fresh_install_pkcs11_slot_id
    form.instance.fresh_install_pkcs11_token_label = form.cleaned_data['fresh_install_pkcs11_token_label']
    form.instance.fresh_install_pkcs11_slot_id = form.cleaned_data.get('fresh_install_pkcs11_slot_id')
    form.instance.fresh_install_pkcs11_config_env_var = form.cleaned_data.get('pkcs11_config_env_var') or ''
    form.instance.fresh_install_pkcs11_enforce_app_secret_protection = form.cleaned_data[
        'fresh_install_pkcs11_enforce_app_secret_protection'
    ]

    uploaded_module = form.cleaned_data.get('pkcs11_module_upload')
    current_staged_module = existing_wizard_pkcs11_staged_file(form.instance.fresh_install_pkcs11_module_path)
    current_module_path = (form.instance.fresh_install_pkcs11_module_path or '').strip()
    current_module_exists = bool(current_module_path and Path(current_module_path).is_file())
    if uploaded_module is not None:
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_module_path)
        form.instance.fresh_install_pkcs11_module_path = stage_uploaded_pkcs11_module(uploaded_module)
        update_fields.append('fresh_install_pkcs11_module_path')
    elif current_staged_module is None and local_dev_pkcs11_handoff_available():
        local_dev_module = str(local_dev_pkcs11_module_path())
        if not current_module_path or current_module_path == local_dev_module or not current_module_exists:
            cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_module_path)
            form.instance.fresh_install_pkcs11_module_path = local_dev_module
            update_fields.append('fresh_install_pkcs11_module_path')

    user_pin = form.cleaned_data.get('pkcs11_user_pin') or ''
    if user_pin:
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_auth_source_ref)
        form.instance.fresh_install_pkcs11_auth_source_ref = stage_pkcs11_user_pin(user_pin)
        update_fields.append('fresh_install_pkcs11_auth_source_ref')

    uploaded_config = form.cleaned_data.get('pkcs11_config_upload')
    current_staged_config = existing_wizard_pkcs11_staged_file(form.instance.fresh_install_pkcs11_config_path)
    current_config_path = (form.instance.fresh_install_pkcs11_config_path or '').strip()
    current_config_exists = bool(current_config_path and Path(current_config_path).is_file())
    if uploaded_config is not None:
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_config_path)
        form.instance.fresh_install_pkcs11_config_path = stage_uploaded_pkcs11_config(uploaded_config)
        update_fields.append('fresh_install_pkcs11_config_path')
    else:
        _persist_local_dev_pkcs11_config_if_available(
            form,
            update_fields,
            current_staged_config=current_staged_config,
            current_config_path=current_config_path,
            current_config_exists=current_config_exists,
        )

    if (
        form.instance.fresh_install_pkcs11_token_label != previous_token_label
        or form.instance.fresh_install_pkcs11_slot_id != previous_slot_id
    ):
        form.instance.fresh_install_pkcs11_token_serial = ''
        update_fields.append('fresh_install_pkcs11_token_serial')
    form.instance.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
    form.instance.save(update_fields=update_fields)

    form.refresh_pkcs11_state()


def persist_valid_pkcs11_fields_from_invalid_form(
    form: FreshInstallBackendConfigModelForm,
) -> None:
    """Preserve valid PKCS#11 inputs even when the submitted form has other errors."""
    if form.instance.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
        return

    update_fields: list[str] = []

    uploaded_module = form.files.get('pkcs11_module_upload')
    if uploaded_module is not None and 'pkcs11_module_upload' not in form.errors:
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_module_path)
        form.instance.fresh_install_pkcs11_module_path = stage_uploaded_pkcs11_module(uploaded_module)
        form.staged_pkcs11_module_name = Path(form.instance.fresh_install_pkcs11_module_path).name
        update_fields.append('fresh_install_pkcs11_module_path')

    uploaded_config = form.files.get('pkcs11_config_upload')
    if uploaded_config is not None and 'pkcs11_config_upload' not in form.errors:
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_config_path)
        form.instance.fresh_install_pkcs11_config_path = stage_uploaded_pkcs11_config(uploaded_config)
        form.staged_pkcs11_config_name = Path(form.instance.fresh_install_pkcs11_config_path).name
        update_fields.append('fresh_install_pkcs11_config_path')

    config_env_var = form.data.get('pkcs11_config_env_var', '').strip()
    if config_env_var and 'pkcs11_config_env_var' not in form.errors:
        form.instance.fresh_install_pkcs11_config_env_var = config_env_var
        update_fields.append('fresh_install_pkcs11_config_env_var')
    user_pin = form.data.get('pkcs11_user_pin', '')
    if user_pin and 'pkcs11_user_pin' not in form.errors:
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_auth_source_ref)
        form.instance.fresh_install_pkcs11_auth_source_ref = stage_pkcs11_user_pin(str(user_pin))
        form.instance.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        form.has_staged_pkcs11_pin = True
        update_fields.extend(
            [
                'fresh_install_pkcs11_auth_source_ref',
                'fresh_install_pkcs11_auth_source',
            ]
        )

    token_label = form.data.get('fresh_install_pkcs11_token_label', '').strip()
    if token_label and 'fresh_install_pkcs11_token_label' not in form.errors:
        form.instance.fresh_install_pkcs11_token_label = token_label
        update_fields.append('fresh_install_pkcs11_token_label')
    raw_slot_id = form.data.get('fresh_install_pkcs11_slot_id', '').strip()
    if raw_slot_id and 'fresh_install_pkcs11_slot_id' not in form.errors:
        form.instance.fresh_install_pkcs11_slot_id = int(raw_slot_id)
        update_fields.append('fresh_install_pkcs11_slot_id')
    if 'fresh_install_pkcs11_enforce_app_secret_protection' not in form.errors:
        form.instance.fresh_install_pkcs11_enforce_app_secret_protection = (
            form.data.get('fresh_install_pkcs11_enforce_app_secret_protection') in {'on', 'true', 'True', '1'}
        )
        update_fields.append('fresh_install_pkcs11_enforce_app_secret_protection')

    if update_fields:
        form.instance.save(update_fields=update_fields)


def _stage_and_probe_pkcs11_connection(
    form: FreshInstallBackendConfigModelForm,
    *,
    profile_name: str,
) -> Pkcs11Capabilities:
    """Install staged PKCS#11 assets and run the isolated token probe."""
    FreshInstallSummaryView.install_staged_pkcs11_assets(form.instance)
    form.refresh_pkcs11_state()
    return probe_staged_pkcs11_config_isolated(form.instance, profile_name=profile_name)


def _pkcs11_connection_test_error_response(
    view: Any,
    form: FreshInstallBackendConfigModelForm,
    exception: Exception,
) -> HttpResponse:
    """Render a PKCS#11 connection-test failure on the current step."""
    view.logger.exception('PKCS#11 setup-wizard connection test failed.')
    if isinstance(exception, DjangoValidationError):
        error_detail = '; '.join(exception.messages)
    else:
        error_detail = str(exception).strip() or type(exception).__name__
    form.add_error(None, f'Could not connect to the configured PKCS#11 backend: {error_detail}')
    return cast('HttpResponse', view.render_to_response(view.get_context_data(form=form)))


def _pkcs11_connection_test_success_response(
    view: Any,
    form: FreshInstallBackendConfigModelForm,
    *,
    capabilities: Pkcs11Capabilities,
    success_redirect_name: str,
) -> HttpResponse:
    """Persist successful probe details and redirect back to the PKCS#11 step."""
    update_fields: list[str] = []
    if form.instance.fresh_install_pkcs11_module_path == str(FINAL_WIZARD_PKCS11_MODULE_PATH):
        update_fields.append('fresh_install_pkcs11_module_path')
    if form.instance.fresh_install_pkcs11_auth_source_ref == str(FINAL_WIZARD_PKCS11_PIN_PATH):
        update_fields.extend(['fresh_install_pkcs11_auth_source', 'fresh_install_pkcs11_auth_source_ref'])
    if form.instance.fresh_install_pkcs11_config_path == str(FINAL_WIZARD_PKCS11_CONFIG_PATH):
        update_fields.append('fresh_install_pkcs11_config_path')
    token_label = capabilities.token.label or form.instance.fresh_install_pkcs11_token_label
    if capabilities.token.label and capabilities.token.label != form.instance.fresh_install_pkcs11_token_label:
        form.instance.fresh_install_pkcs11_token_label = capabilities.token.label
        update_fields.append('fresh_install_pkcs11_token_label')
    if capabilities.token.serial and capabilities.token.serial != form.instance.fresh_install_pkcs11_token_serial:
        form.instance.fresh_install_pkcs11_token_serial = capabilities.token.serial
        update_fields.append('fresh_install_pkcs11_token_serial')
    if capabilities.token.slot_id != form.instance.fresh_install_pkcs11_slot_id:
        form.instance.fresh_install_pkcs11_slot_id = capabilities.token.slot_id
        update_fields.append('fresh_install_pkcs11_slot_id')
    if update_fields:
        form.instance.save(update_fields=update_fields)
    token_serial = capabilities.token.serial or 'unknown serial'
    messages.success(
        view.request,
        f'PKCS#11 connection successful. Reached token {token_label!r} ({token_serial}) in slot '
        f'{capabilities.token.slot_id}.',
    )
    return redirect(success_redirect_name)


def run_staged_pkcs11_connection_test(
    view: Any,
    form: FreshInstallBackendConfigModelForm,
    *,
    success_redirect_name: str,
) -> HttpResponse:
    """Probe staged PKCS#11 token connectivity and keep the user on this step."""
    try:
        capabilities = _stage_and_probe_pkcs11_connection(
            form,
            profile_name='setup-wizard-pkcs11-test',
        )
    except DjangoValidationError as exception:
        return _pkcs11_connection_test_error_response(view, form, exception)

    return _pkcs11_connection_test_success_response(
        view,
        form,
        capabilities=capabilities,
        success_redirect_name=success_redirect_name,
    )


def run_fresh_install_staged_pkcs11_connection_test(
    view: Any,
    form: FreshInstallBackendConfigModelForm,
    *,
    success_redirect_name: str,
) -> HttpResponse:
    """Probe staged PKCS#11 connectivity and fresh-install app-secret policy support."""
    try:
        capabilities = _stage_and_probe_pkcs11_connection(
            form,
            profile_name='setup-wizard-pkcs11-test',
        )
        validate_staged_pkcs11_app_secret_protection_if_required(
            form.instance,
            profile_name='setup-wizard-pkcs11-app-secret-test',
        )
    except DjangoValidationError as exception:
        return _pkcs11_connection_test_error_response(view, form, exception)

    return _pkcs11_connection_test_success_response(
        view,
        form,
        capabilities=capabilities,
        success_redirect_name=success_redirect_name,
    )


def apply_pkcs11_probe_fallbacks(config_model: SetupWizardConfigModel) -> tuple[str, str, list[str]]:
    """Apply runtime fallback PKCS#11 paths before probing a staged backend."""
    module_path = (config_model.fresh_install_pkcs11_module_path or '').strip()
    pin_file = (config_model.fresh_install_pkcs11_auth_source_ref or '').strip()
    config_file = (config_model.fresh_install_pkcs11_config_path or '').strip()
    config_env_var = (config_model.fresh_install_pkcs11_config_env_var or '').strip()
    fallback_update_fields: list[str] = []

    if (not module_path or not _path_exists(Path(module_path))) and _path_exists(FINAL_WIZARD_PKCS11_MODULE_PATH):
        module_path = str(FINAL_WIZARD_PKCS11_MODULE_PATH)
        config_model.fresh_install_pkcs11_module_path = module_path
        fallback_update_fields.append('fresh_install_pkcs11_module_path')

    if (not pin_file or not _path_exists(Path(pin_file))) and _path_exists(FINAL_WIZARD_PKCS11_PIN_PATH):
        pin_file = str(FINAL_WIZARD_PKCS11_PIN_PATH)
        config_model.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        config_model.fresh_install_pkcs11_auth_source_ref = pin_file
        fallback_update_fields.extend(['fresh_install_pkcs11_auth_source', 'fresh_install_pkcs11_auth_source_ref'])

    if (not config_file or not _path_exists(Path(config_file))) and _path_exists(FINAL_WIZARD_PKCS11_CONFIG_PATH):
        config_file = str(FINAL_WIZARD_PKCS11_CONFIG_PATH)
        config_model.fresh_install_pkcs11_config_path = config_file
        fallback_update_fields.append('fresh_install_pkcs11_config_path')
    elif (not config_file or not _path_exists(Path(config_file))) and local_dev_pkcs11_config_available():
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
        part.strip()
        for part in (completed_process.stdout, completed_process.stderr)
        if part and part.strip()
    )
    if len(output) > MAX_PKCS11_PROBE_OUTPUT_LENGTH:
        return output[-MAX_PKCS11_PROBE_OUTPUT_LENGTH:]
    return output


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

    completed_process = subprocess.run(  # noqa: S603
        command,
        cwd=str(settings.REPO_ROOT),
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
    )
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
    completed_process = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(settings.BASE_DIR / 'manage.py'),
            'test_setup_wizard_pkcs11_app_secret',
            '--profile-name',
            profile_name,
        ],
        cwd=str(settings.REPO_ROOT),
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
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


def _path_exists(path: Path) -> bool:
    """Return whether a setup-wizard path exists without leaking permission errors."""
    try:
        return path.exists()
    except OSError:
        return False


def _save_untyped_model(instance: Any) -> None:
    """Save a Django model whose save method is not typed for mypy."""
    instance.save()


class TrustpointWizardError(Exception):
    """Custom exception for Trustpoint wizard-related issues."""


class TrustpointTlsServerCredentialError(Exception):
    """Custom exception for errors related to Trustpoint TLS Server Credentials.

    This exception is raised when specific issues with the TLS Server Credentials
    occur, such as missing credentials.
    """

    def __init__(self, message: str = 'Trustpoint TLS Server Credential error occurred.') -> None:
        """Initialize the exception with a custom error message.

        Args:
            message (str): A custom error message describing the exception. Defaults
                           to 'Trustpoint TLS Server Credential error occurred.'.
        """
        super().__init__(message)


def execute_shell_script(script: Path, *args: str) -> None:
    """Execute a shell script with optional arguments.

    Args:
        script (Path): The path to the shell script to execute.
        *args (str): Additional arguments to pass to the script.

    Raises:
        FileNotFoundError: If the script does not exist.
        ValueError: If the script path is not a valid file.
        subprocess.CalledProcessError: If the script fails to execute.
    """
    script_path = Path(script).resolve()

    if not script_path.exists():
        err_msg = f'Script not found: {script_path}'
        raise FileNotFoundError(err_msg)
    if not script_path.is_file():
        err_msg = f'The script path {script_path} is not a valid file.'
        raise ValueError(err_msg)

    command = ['sudo', str(script_path), *list(args)]

    # This method is executing all paths it gets.
    # The security is actually implemented using a sudoers file within the linux system -> noqa: S603.
    result = subprocess.run(command, capture_output=True, text=True, check=True)  # noqa: S603

    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, str(script_path))


# Index Views ---------------------------------------------------------------------------------------------------------


class SetupWizardIndexView(LoggerMixin, TemplateView):
    """Initial wizard: Fresh Install vs. Restore Backup."""

    http_method_names = ('get',)
    template_name = 'setup_wizard/index.html'

    @staticmethod
    def _continue_url(config_model: SetupWizardConfigModel) -> str | None:
        """Return a URL for the last recorded bootstrap step, if available."""
        active_flow = config_model.bootstrap_active_flow
        current_step = config_model.bootstrap_current_step
        if not active_flow or not current_step:
            return None

        fresh_install_steps = {
            'admin_user': 'fresh_install_admin_user',
            'database': 'fresh_install_database',
            'crypto_storage': 'fresh_install_crypto_storage',
            'backend_config': 'fresh_install_backend_config',
            'demo_data': 'fresh_install_demo_data',
            'tls_config': 'fresh_install_tls_config',
            'summary': 'fresh_install_summary',
        }
        attach_steps = {
            OperationalAttachMode.CONNECT_EXISTING: {
                'database': 'connect_existing_database',
                'crypto-storage': 'connect_existing_crypto_storage',
                'backend-config': 'connect_existing_backend_config',
                'summary': 'connect_existing_summary',
            },
            OperationalAttachMode.RESTORE_BACKUP: RESTORE_BACKUP_STEP_URL_NAMES,
        }
        url_name: str | None = None
        if active_flow == SetupWizardConfigModel.BootstrapFlow.FRESH_INSTALL.value:
            url_name = fresh_install_steps.get(current_step)
        else:
            with contextlib.suppress(ValueError):
                url_name = attach_steps.get(OperationalAttachMode(active_flow), {}).get(current_step)
        return reverse(f'setup_wizard:{url_name}') if url_name else None

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Render the setup mode chooser with an optional resume link."""
        context = super().get_context_data(**kwargs)
        config_model = SetupWizardConfigModel.get_singleton()
        context['continue_url'] = self._continue_url(config_model)
        context['continue_flow'] = config_model.get_bootstrap_active_flow_display()
        return context

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests for the setup mode wizard page.

        Bootstrap routing and authentication are enforced by the middleware; the
        index view itself only renders the available setup flows.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            HttpResponse: A redirect response to the appropriate setup wizard page
                          or the login page if the setup is not in a Docker container.
        """
        return super().get(*args, **kwargs)


# Config Wizard -------------------------------------------------------------------------------------------------------


class FreshInstallFormBaseView[FormT: BaseForm](LoginRequiredMixin, LoggerMixin, FormView[FormT]):
    """Shared base view for fresh-install wizard steps."""

    is_last: bool = False
    back_url: str | Promise | None = None
    body_heading: str = ''
    step_state: SetupWizardConfigModel.FreshInstallCurrentStep

    class StepState(enum.StrEnum):
        """Display state for a fresh-install wizard step in the progress UI."""

        ACTIVE = 'active'
        DONE = 'done'
        AVAILABLE = 'available'
        PENDING = 'pending'

    @staticmethod
    def _get_step_state(
        step: SetupWizardConfigModel.FreshInstallCurrentStep,
        viewed_step: SetupWizardConfigModel.FreshInstallCurrentStep,
        unlocked_step: SetupWizardConfigModel.FreshInstallCurrentStep,
        *,
        is_submitted: bool,
    ) -> FreshInstallFormBaseView.StepState:
        """Get the display state for a wizard step."""
        if step == viewed_step:
            return FreshInstallFormBaseView.StepState.ACTIVE
        if is_submitted:
            return FreshInstallFormBaseView.StepState.DONE
        if step <= unlocked_step:
            return FreshInstallFormBaseView.StepState.AVAILABLE
        return FreshInstallFormBaseView.StepState.PENDING

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build template context for the current fresh-install step."""
        context = super().get_context_data(**kwargs)
        context['is_last'] = self.is_last
        context['back_url'] = self.back_url
        context['body_heading'] = self.body_heading
        context['is_summary_step'] = self.step_state == SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY

        config_model = SetupWizardConfigModel.get_singleton()
        current_state = config_model.get_current_step()
        viewed_step = self.step_state
        admin_user_submitted = config_model.is_step_submitted(
            SetupWizardConfigModel.FreshInstallCurrentStep.ADMIN_USER
        )
        database_submitted = config_model.is_step_submitted(
            SetupWizardConfigModel.FreshInstallCurrentStep.DATABASE
        )
        crypto_storage_submitted = config_model.is_step_submitted(
            SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE
        )
        backend_config_submitted = config_model.is_step_submitted(
            SetupWizardConfigModel.FreshInstallCurrentStep.BACKEND_CONFIG
        )
        demo_data_submitted = config_model.is_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.DEMO_DATA)
        tls_config_submitted = config_model.is_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.TLS_CONFIG)
        summary_submitted = config_model.is_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY)
        admin_user_state = self._get_step_state(
            SetupWizardConfigModel.FreshInstallCurrentStep.ADMIN_USER,
            viewed_step,
            current_state,
            is_submitted=admin_user_submitted,
        )
        database_state = self._get_step_state(
            SetupWizardConfigModel.FreshInstallCurrentStep.DATABASE,
            viewed_step,
            current_state,
            is_submitted=database_submitted,
        )
        crypto_storage_state = self._get_step_state(
            SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE,
            viewed_step,
            current_state,
            is_submitted=crypto_storage_submitted,
        )
        backend_config_state = self._get_step_state(
            SetupWizardConfigModel.FreshInstallCurrentStep.BACKEND_CONFIG,
            viewed_step,
            current_state,
            is_submitted=backend_config_submitted,
        )
        demo_data_state = self._get_step_state(
            SetupWizardConfigModel.FreshInstallCurrentStep.DEMO_DATA,
            viewed_step,
            current_state,
            is_submitted=demo_data_submitted,
        )
        tls_config_state = self._get_step_state(
            SetupWizardConfigModel.FreshInstallCurrentStep.TLS_CONFIG,
            viewed_step,
            current_state,
            is_submitted=tls_config_submitted,
        )
        summary_state = self._get_step_state(
            SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY,
            viewed_step,
            current_state,
            is_submitted=summary_submitted,
        )

        context['steps'] = [
            {
                'label': 'Admin User',
                'url': reverse('setup_wizard:fresh_install_admin_user'),
                'state': str(admin_user_state),
                'submitted': admin_user_submitted,
            },
            {
                'label': 'Database',
                'url': reverse('setup_wizard:fresh_install_database'),
                'state': str(database_state),
                'submitted': database_submitted,
            },
            {
                'label': 'Crypto Backend',
                'url': reverse('setup_wizard:fresh_install_crypto_storage'),
                'state': str(crypto_storage_state),
                'submitted': crypto_storage_submitted,
            },
            {
                'label': 'Backend Config',
                'url': reverse('setup_wizard:fresh_install_backend_config'),
                'state': str(backend_config_state),
                'submitted': backend_config_submitted,
            },
            {
                'label': 'Demo Data',
                'url': reverse('setup_wizard:fresh_install_demo_data'),
                'state': str(demo_data_state),
                'submitted': demo_data_submitted,
            },
            {
                'label': 'TLS Config',
                'url': reverse('setup_wizard:fresh_install_tls_config'),
                'state': str(tls_config_state),
                'submitted': tls_config_submitted,
            },
            {
                'label': 'Summary',
                'url': reverse('setup_wizard:fresh_install_summary'),
                'state': str(summary_state),
                'submitted': summary_submitted,
            },
        ]
        context['wizard_notice'] = self._build_wizard_notice(config_model=config_model)
        return context

    def _build_wizard_notice(self, *, config_model: SetupWizardConfigModel) -> str | None:
        """Return optional user-facing guidance for the current wizard step."""
        _ = config_model
        return None

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests and update the unlocked wizard step."""
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.bootstrap_active_flow = SetupWizardConfigModel.BootstrapFlow.FRESH_INSTALL
        config_model.bootstrap_current_step = self.step_state.name.lower()
        if config_model.fresh_install_current_step < self.step_state:
            config_model.fresh_install_current_step = self.step_state
            config_model.save()
        else:
            config_model.save(update_fields=['bootstrap_active_flow', 'bootstrap_current_step'])
        return super().get(request, *args, **kwargs)


class FreshInstallModelFormBaseView[FormT: FreshInstallModelBaseForm](FreshInstallFormBaseView[FormT]):
    """Base view for fresh-install steps backed by the singleton config row.

    This view binds each step form to the singleton
    ``SetupWizardConfigModel`` instance and exposes wizard metadata for the
    template.
    """

    def get_form_kwargs(self) -> dict[str, Any]:
        """Build constructor kwargs for the bound model form.

        Returns:
            dict[str, Any]: Form kwargs containing the singleton model
            instance.
        """
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = SetupWizardConfigModel.get_singleton()
        return kwargs

    def form_valid(self, form: FormT) -> HttpResponse:
        """Persist the current step and continue the wizard flow.

        Args:
            form: The validated model-backed form for this wizard step.

        Returns:
            HttpResponse: The redirect or response returned by the parent
            implementation.
        """
        form.save()
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.mark_step_submitted(self.step_state)
        config_model.bootstrap_active_flow = SetupWizardConfigModel.BootstrapFlow.FRESH_INSTALL
        config_model.bootstrap_current_step = self.step_state.name.lower()
        config_model.save()
        return super().form_valid(form)


class FreshInstallAdminUserView(FreshInstallModelFormBaseView[FreshInstallAdminUserModelForm]):
    """Render the fresh-install step for staging the operational administrator."""

    form_class = FreshInstallAdminUserModelForm
    template_name = 'setup_wizard/fresh_install.html'
    success_url = reverse_lazy('setup_wizard:fresh_install_database')

    step_state = SetupWizardConfigModel.FreshInstallCurrentStep.ADMIN_USER
    body_heading = 'Create Operational Admin'


class FreshInstallDatabaseView(FreshInstallModelFormBaseView[FreshInstallDatabaseModelForm]):
    """Render the fresh-install step for staging the operational PostgreSQL database."""

    form_class = FreshInstallDatabaseModelForm
    template_name = 'setup_wizard/fresh_install.html'
    success_url = reverse_lazy('setup_wizard:fresh_install_crypto_storage')

    step_state = SetupWizardConfigModel.FreshInstallCurrentStep.DATABASE
    back_url = reverse_lazy('setup_wizard:fresh_install_admin_user')
    body_heading = 'Configure Operational Database'

    @staticmethod
    def _is_test_connection_submission(request: HttpRequest) -> bool:
        """Return whether the current POST requests a database connection test."""
        return request.POST.get('wizard_action') == 'test_database'

    @staticmethod
    def _test_database_connection(form: FreshInstallDatabaseModelForm) -> None:
        """Open a PostgreSQL connection using staged database settings."""
        with psycopg.connect(
            dbname=form.cleaned_data['operational_db_name'],
            user=form.cleaned_data['operational_db_user'],
            password=form.cleaned_data['operational_db_password'],
            host=form.cleaned_data['operational_db_host'],
            port=form.cleaned_data['operational_db_port'],
            connect_timeout=5,
        ):
            return

    def form_valid(self, form: FreshInstallDatabaseModelForm) -> HttpResponse:
        """Persist or test the staged database configuration."""
        if self._is_test_connection_submission(self.request):
            form.save()
            try:
                self._test_database_connection(form)
            except Exception as exception:
                self.logger.exception('Operational PostgreSQL connection test failed.')
                error_detail = str(exception).strip() or type(exception).__name__
                form.add_error(None, f'Could not connect to PostgreSQL: {error_detail}')
                return self.render_to_response(self.get_context_data(form=form))
            messages.success(self.request, 'PostgreSQL connection successful.')
            return redirect('setup_wizard:fresh_install_database')

        return super().form_valid(form)


class FreshInstallCryptoStorageView(FreshInstallModelFormBaseView[FreshInstallCryptoStorageModelForm]):
    """Render the fresh-install step for choosing cryptographic storage."""

    form_class = FreshInstallCryptoStorageModelForm
    template_name = 'setup_wizard/fresh_install.html'
    success_url = reverse_lazy('setup_wizard:fresh_install_backend_config')

    step_state = SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE
    back_url = reverse_lazy('setup_wizard:fresh_install_database')
    body_heading = 'Select Crypto Backend'

    @staticmethod
    def _reset_staged_pkcs11_backend(form: FreshInstallCryptoStorageModelForm) -> None:
        """Drop PKCS#11 wizard assets when switching away from the PKCS#11 backend."""
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_module_path)
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_auth_source_ref)
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_config_path)
        execute_shell_script(INSTALL_PKCS11_ASSETS, '--clear-module')
        execute_shell_script(INSTALL_PKCS11_ASSETS, '--clear-pin')
        execute_shell_script(INSTALL_PKCS11_ASSETS, '--clear-config')
        form.instance.fresh_install_pkcs11_module_path = ''
        form.instance.fresh_install_pkcs11_token_label = ''
        form.instance.fresh_install_pkcs11_token_serial = ''
        form.instance.fresh_install_pkcs11_slot_id = None
        form.instance.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        form.instance.fresh_install_pkcs11_auth_source_ref = ''
        form.instance.fresh_install_pkcs11_config_path = ''
        form.instance.fresh_install_pkcs11_config_env_var = ''
        form.instance.fresh_install_pkcs11_enforce_app_secret_protection = False

    def form_valid(self, form: FreshInstallCryptoStorageModelForm) -> HttpResponse:
        """Persist the chosen backend and clear stale PKCS#11 wizard staging when not needed."""
        selected_storage = form.cleaned_data['crypto_storage']
        if selected_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            self._reset_staged_pkcs11_backend(form)
        else:
            previous_storage = (
                SetupWizardConfigModel.objects.filter(pk=form.instance.pk)
                .values_list('crypto_storage', flat=True)
                .first()
            )
            if previous_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
                form.instance.fresh_install_pkcs11_enforce_app_secret_protection = True
        return super().form_valid(form)


class FreshInstallBackendConfigView(FreshInstallModelFormBaseView[FreshInstallBackendConfigModelForm]):
    """Render the fresh-install step for configuring the selected backend."""

    form_class = FreshInstallBackendConfigModelForm
    template_name = 'setup_wizard/fresh_install.html'
    success_url = reverse_lazy('setup_wizard:fresh_install_demo_data')

    step_state = SetupWizardConfigModel.FreshInstallCurrentStep.BACKEND_CONFIG
    back_url = reverse_lazy('setup_wizard:fresh_install_crypto_storage')
    body_heading = 'Configure Backend'

    @staticmethod
    def _is_test_connection_submission(request: HttpRequest) -> bool:
        """Return whether the current POST requests a PKCS#11 connection test."""
        return is_pkcs11_test_connection_submission(request)

    @staticmethod
    def _is_clear_module_submission(request: HttpRequest) -> bool:
        """Return whether the current POST requests staged library removal."""
        return is_clear_pkcs11_module_submission(request)

    @staticmethod
    def _is_clear_pin_submission(request: HttpRequest) -> bool:
        """Return whether the current POST requests staged PIN removal."""
        return is_clear_pkcs11_pin_submission(request)

    @staticmethod
    def _is_clear_config_submission(request: HttpRequest) -> bool:
        """Return whether the current POST requests staged provider config removal."""
        return is_clear_pkcs11_config_submission(request)

    @staticmethod
    def _clear_staged_pkcs11_module(config_model: SetupWizardConfigModel) -> None:
        """Remove the currently staged PKCS#11 library for this wizard session."""
        clear_staged_pkcs11_module(config_model)

    @staticmethod
    def _clear_staged_pkcs11_pin(config_model: SetupWizardConfigModel) -> None:
        """Remove the currently staged PKCS#11 user PIN for this wizard session."""
        clear_staged_pkcs11_pin(config_model)

    @staticmethod
    def _clear_staged_pkcs11_config(config_model: SetupWizardConfigModel) -> None:
        """Remove the currently staged PKCS#11 provider config for this wizard session."""
        clear_staged_pkcs11_config(config_model)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle staged PKCS#11 asset removal before running normal form validation."""
        config_model = SetupWizardConfigModel.get_singleton()
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            if self._is_clear_module_submission(request):
                self._clear_staged_pkcs11_module(config_model)
                messages.success(request, 'The PKCS#11 library was removed for this wizard session.')
                return redirect('setup_wizard:fresh_install_backend_config')
            if self._is_clear_pin_submission(request):
                self._clear_staged_pkcs11_pin(config_model)
                messages.success(request, 'The PKCS#11 user PIN was removed for this wizard session.')
                return redirect('setup_wizard:fresh_install_backend_config')
            if self._is_clear_config_submission(request):
                self._clear_staged_pkcs11_config(config_model)
                messages.success(request, 'The PKCS#11 provider config was removed for this wizard session.')
                return redirect('setup_wizard:fresh_install_backend_config')
        return super().post(request, *args, **kwargs)

    @staticmethod
    def _stage_uploaded_pkcs11_module(uploaded_module: Any) -> str:
        """Write an uploaded PKCS#11 library to private one-time wizard staging."""
        return stage_uploaded_pkcs11_module(uploaded_module)

    @staticmethod
    def _stage_pkcs11_user_pin(user_pin: str) -> str:
        """Write the entered PKCS#11 user PIN to private one-time wizard staging."""
        return stage_pkcs11_user_pin(user_pin)

    @staticmethod
    def _stage_uploaded_pkcs11_config(uploaded_config: Any) -> str:
        """Write an optional provider PKCS#11 config to private one-time wizard staging."""
        return stage_uploaded_pkcs11_config(uploaded_config)

    def _persist_pkcs11_backend_config(self, form: FreshInstallBackendConfigModelForm) -> None:
        """Persist staged PKCS#11 wizard inputs without advancing the wizard."""
        persist_staged_pkcs11_backend_config(form)

    def _test_pkcs11_connection(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Probe the staged PKCS#11 configuration and keep the user on this step."""
        return run_fresh_install_staged_pkcs11_connection_test(
            self,
            form,
            success_redirect_name='setup_wizard:fresh_install_backend_config',
        )

    def persist_pkcs11_backend_config(self, form: FreshInstallBackendConfigModelForm) -> None:
        """Persist staged PKCS#11 wizard inputs."""
        self._persist_pkcs11_backend_config(form)

    def test_pkcs11_connection(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Probe the staged PKCS#11 configuration."""
        return run_fresh_install_staged_pkcs11_connection_test(
            self,
            form,
            success_redirect_name='setup_wizard:fresh_install_backend_config',
        )

    def form_valid(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Persist wizard backend configuration using one-time PKCS#11 staging files."""
        if form.instance.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            self._persist_pkcs11_backend_config(form)
            if self._is_test_connection_submission(self.request):
                return self._test_pkcs11_connection(form)

        return super().form_valid(form)

    def form_invalid(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Persist already supplied PKCS#11 assets for this wizard session even when other validation fails."""
        persist_valid_pkcs11_fields_from_invalid_form(form)
        return super().form_invalid(form)


class FreshInstallDemoDataView(FreshInstallModelFormBaseView[FreshInstallDemoDataModelForm]):
    """Render the fresh-install step for choosing demo data injection."""

    form_class = FreshInstallDemoDataModelForm
    template_name = 'setup_wizard/fresh_install.html'
    success_url = reverse_lazy('setup_wizard:fresh_install_tls_config')

    step_state = SetupWizardConfigModel.FreshInstallCurrentStep.DEMO_DATA
    back_url = reverse_lazy('setup_wizard:fresh_install_backend_config')
    body_heading = 'Inject Demo Data?'


class FreshInstallTlsConfigView(FreshInstallFormBaseView[FreshInstallTlsConfigForm]):
    """Render the fresh-install step for choosing tls config injection."""

    form_class = FreshInstallTlsConfigForm
    template_name = 'setup_wizard/fresh_install.html'
    success_url = reverse_lazy('setup_wizard:fresh_install_summary')

    step_state = SetupWizardConfigModel.FreshInstallCurrentStep.TLS_CONFIG
    back_url = reverse_lazy('setup_wizard:fresh_install_demo_data')
    body_heading = 'Configure TLS'

    @staticmethod
    def _format_csv_initial(values: list[str]) -> str:
        """Format stored SAN values for the comma-separated input fields."""
        if not values:
            return ''
        return f'{", ".join(values)}, '

    def get_initial(self) -> dict[str, Any]:
        """Populate the form from the persisted TLS wizard configuration."""
        initial = super().get_initial()
        config_model = SetupWizardConfigModel.get_singleton()
        initial['tls_mode'] = config_model.fresh_install_tls_mode

        ipv4_addresses, ipv6_addresses, dns_names = extract_staged_tls_sans()
        if not (ipv4_addresses or ipv6_addresses or dns_names):
            return initial

        initial.update(
            {
                'ipv4_addresses': self._format_csv_initial(ipv4_addresses),
                'ipv6_addresses': self._format_csv_initial(ipv6_addresses),
                'domain_names': self._format_csv_initial(dns_names),
            }
        )
        return initial

    @staticmethod
    def _add_tls_config_error(
        form: FreshInstallTlsConfigForm,
        tls_mode: str,
        error_message: str,
    ) -> None:
        """Attach TLS configuration errors to the most relevant field."""
        if tls_mode == SetupWizardConfigModel.FreshInstallTlsConfigType.PKCS12:
            form.add_error('pkcs12_file', error_message)
            return

        if tls_mode == SetupWizardConfigModel.FreshInstallTlsConfigType.SEPARATE_FILES:
            normalized_error = error_message.lower()
            if 'full chain' in normalized_error or 'root ca' in normalized_error:
                form.add_error('further_certificates', error_message)
                return
            if 'private key' in normalized_error or 'key password' in normalized_error:
                form.add_error('key_file', error_message)
                return
            if (
                'certificate file' in normalized_error
                or 'end-entity certificate' in normalized_error
                or 'tls server certificate' in normalized_error
            ):
                form.add_error('tls_server_certificate', error_message)
                return

        form.add_error(None, error_message)

    def form_valid(self, form: FreshInstallTlsConfigForm) -> HttpResponse:
        """Persist the current step and continue the wizard flow.

        Args:
            form: The validated TLS configuration form for this wizard step.

        Returns:
            HttpResponse: The redirect or response returned by the parent
            implementation.
        """
        tls_mode = form.cleaned_data['tls_mode']
        try:
            config_model = SetupWizardConfigModel.get_singleton()
            config_model.fresh_install_tls_mode = tls_mode

            if tls_mode == SetupWizardConfigModel.FreshInstallTlsConfigType.GENERATE:
                generator = TlsServerCredentialGenerator(
                    ipv4_addresses=[
                        ipaddress.IPv4Address(address) for address in form.cleaned_data.get('ipv4_addresses', [])
                    ],
                    ipv6_addresses=[
                        ipaddress.IPv6Address(address) for address in form.cleaned_data.get('ipv6_addresses', [])
                    ],
                    domain_names=form.cleaned_data.get('domain_names', []),
                )
                tls_credential_serializer = generator.generate_tls_server_credential()
            elif tls_mode == SetupWizardConfigModel.FreshInstallTlsConfigType.PKCS12:
                pkcs12_file = form.cleaned_data['pkcs12_file']
                tls_credential_serializer = TlsServerCredentialFileParser.build_from_pkcs12_bytes(
                    pkcs12_raw=pkcs12_file.read(),
                    pkcs12_password=form.cleaned_data.get('pkcs12_password'),
                )
            else:
                tls_server_certificate = form.cleaned_data['tls_server_certificate']
                further_certificates = form.cleaned_data.get('further_certificates', [])
                key_file = form.cleaned_data['key_file']
                tls_credential_serializer = TlsServerCredentialFileParser.build_from_separate_files(
                    tls_server_certificate_raw=tls_server_certificate.read(),
                    further_certificates_raw=[certificate.read() for certificate in further_certificates],
                    key_file_raw=key_file.read(),
                    key_password=form.cleaned_data.get('key_password'),
                )

            with transaction.atomic():
                stage_tls_credential(tls_credential_serializer)
                config_model.mark_step_submitted(self.step_state)
                config_model.save(
                    update_fields=[
                        'fresh_install_tls_mode',
                        'fresh_install_tls_config_submitted',
                        'fresh_install_current_step',
                    ]
                )

            return super().form_valid(form)
        except DjangoValidationError as exception:
            for error_message in exception.messages:
                self._add_tls_config_error(form, tls_mode, error_message)
            self.logger.exception('Error configuring TLS server credential.')
            return self.form_invalid(form)
        except (ProtectedError, TypeError, ValueError) as exception:
            error_message = str(exception) or 'Error configuring TLS server credential.'
            self._add_tls_config_error(form, tls_mode, error_message)
            self.logger.exception('Error configuring TLS server credential.')
            return self.form_invalid(form)


class FreshInstallSummaryView(FreshInstallModelFormBaseView[FreshInstallSummaryModelForm]):
    """Render the fresh-install step for the summary."""

    form_class = FreshInstallSummaryModelForm
    template_name = 'setup_wizard/fresh_install.html'
    success_url = reverse_lazy('home:index')

    step_state = SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY
    back_url = reverse_lazy('setup_wizard:fresh_install_tls_config')
    body_heading = 'Summary'

    def _build_wizard_notice(self, *, config_model: SetupWizardConfigModel) -> str | None:
        """Return guidance after bootstrap configuration has been applied."""
        if getattr(settings, 'TRUSTPOINT_IS_BOOTSTRAP', False) and config_model.operational_config_applied:
            return (
                'Operational configuration has been applied, but this bootstrap process is still serving the '
                'wizard. Submit this step to retry the runtime switch.'
            )
        return None

    @staticmethod
    def _map_tls_apply_exit_code_to_message(return_code: int) -> str:
        """Map TLS apply script exit codes to user-facing error messages."""
        error_messages = {
            1: 'The TLS apply script was called without the required storage mode parameter.',
            2: "The TLS apply script received an invalid storage mode. Expected 'hsm' or 'no_hsm'.",
            3: 'Failed to move the staged TLS files into the Nginx TLS directory.',
            4: 'Nginx rejected the updated TLS configuration.',
        }
        return error_messages.get(return_code, 'An unknown error occurred.')

    @staticmethod
    def _write_pem_files(credential_model: CredentialModel) -> None:
        """Writes the private key, certificate, and trust store PEM files to disk.

        Args:
            credential_model (CredentialModel): The credential model instance containing
            the keys and certificates.
        """
        private_key_pem = credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
        certificate_pem = credential_model.get_certificate_serializer().as_pem().decode()
        trust_store_pem = credential_model.get_certificate_chain_serializer().as_pem().decode()

        NGINX_KEY_PATH.write_text(private_key_pem)
        NGINX_CERT_PATH.write_text(certificate_pem)

        # Only write chain file if there's actually a chain (not empty)
        if trust_store_pem.strip():
            NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)
        elif NGINX_CERT_CHAIN_PATH.exists():
            # Remove chain file if it exists but chain is empty
            NGINX_CERT_CHAIN_PATH.unlink()

    def _apply_staged_tls_credential(self) -> None:
        """Promote the staged TLS credential to active and apply it for nginx."""
        staged_tls_serializer = load_staged_tls_credential()
        if staged_tls_serializer is None:
            err_msg = 'No staged TLS Server Credential found.'
            raise ValueError(err_msg)

        staged_tls_credential = CredentialModel.save_credential_serializer(
            credential_serializer=staged_tls_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
        )

        active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
        active_tls.credential = staged_tls_credential
        active_tls.save()

        self._write_pem_files(staged_tls_credential)
        execute_shell_script(UPDATE_TLS_NGINX, 'no_hsm')
        sha256_fingerprint = staged_tls_credential.get_certificate().fingerprint(hashes.SHA256())
        formatted_fingerprint = ':'.join(f'{byte:02X}' for byte in sha256_fingerprint)
        self.logger.info('TLS SHA256 fingerprint: %s', formatted_fingerprint)
        clear_staged_tls_credential()

    @staticmethod
    def _load_existing_backend_profile(backend_kind: BackendKind) -> CryptoProviderProfileModel | None:
        """Return an existing profile for the given backend kind when one already exists."""
        return (
            CryptoProviderProfileModel.objects.filter(backend_kind=backend_kind)
            .order_by('-active', 'id')
            .first()
        )

    @classmethod
    def _ensure_backend_kind_matches_instance(cls, backend_kind: BackendKind) -> None:
        """Reject mixing backend kinds within one Trustpoint instance."""
        existing_kinds = set(CryptoProviderProfileModel.objects.values_list('backend_kind', flat=True))
        if existing_kinds and backend_kind.value not in existing_kinds:
            configured_backend_kind = sorted(existing_kinds)[0]
            err_msg = (
                'This Trustpoint instance already contains crypto backend '
                f'configuration for {configured_backend_kind!r}.'
            )
            raise DjangoValidationError(err_msg)

    @classmethod
    def _activate_profile(
        cls,
        *,
        backend_kind: BackendKind,
        default_name: str,
    ) -> CryptoProviderProfileModel:
        """Activate or create the singleton profile for the chosen backend kind."""
        cls._ensure_backend_kind_matches_instance(backend_kind)
        existing_profile = cls._load_existing_backend_profile(backend_kind)
        if existing_profile is not None:
            CryptoProviderProfileModel.objects.filter(active=True).exclude(pk=existing_profile.pk).update(active=False)
            existing_profile.active = True
            _save_untyped_model(existing_profile)
            return existing_profile

        CryptoProviderProfileModel.objects.filter(active=True).update(active=False)
        profile = CryptoProviderProfileModel(
            name=default_name,
            backend_kind=backend_kind,
            active=True,
        )
        _save_untyped_model(profile)
        return profile

    @classmethod
    def _configure_software_backend(cls) -> None:
        """Configure the software backend for the instance."""
        profile = cls._activate_profile(
            backend_kind=BackendKind.SOFTWARE,
            default_name='trustpoint-software-demo-testing-backend',
        )
        defaults = {
            'encryption_source': SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
            'encryption_source_ref': '',
            'allow_exportable_private_keys': False,
        }
        config, created = CryptoProviderSoftwareConfigModel.objects.get_or_create(
            profile=profile,
            defaults=defaults,
        )
        if not created:
            for field_name, value in defaults.items():
                setattr(config, field_name, value)
        config.full_clean()
        _save_untyped_model(config)

    @staticmethod
    def _configure_software_app_secret_backend() -> None:
        """Configure the software app-secret backend."""
        backend = AppSecretBackendModel.get_singleton()
        backend.backend_kind = AppSecretBackendKind.SOFTWARE
        _save_untyped_model(backend)

        AppSecretPkcs11ConfigModel.objects.filter(backend=backend).delete()
        software_config, _ = AppSecretSoftwareConfigModel.objects.get_or_create(backend=backend)
        software_config.full_clean()
        _save_untyped_model(software_config)

        clear_app_secret_cache()
        get_app_secret_service().ensure_backend_ready()

    @staticmethod
    def _configure_pkcs11_app_secret_backend() -> None:
        """Configure the PKCS#11-backed app-secret subsystem from the active crypto profile."""
        crypto_profile = CryptoProviderProfileModel.objects.get(active=True, backend_kind=BackendKind.PKCS11)
        crypto_config = crypto_profile.pkcs11_config

        backend = AppSecretBackendModel.get_singleton()
        backend.backend_kind = AppSecretBackendKind.PKCS11
        _save_untyped_model(backend)

        AppSecretSoftwareConfigModel.objects.filter(backend=backend).delete()
        secret_config, created = AppSecretPkcs11ConfigModel.objects.get_or_create(
            backend=backend,
            defaults={
                'module_path': crypto_config.module_path,
                'token_label': crypto_config.token_label,
                'token_serial': crypto_config.token_serial,
                'slot_id': crypto_config.slot_id,
                'auth_source': AppSecretPkcs11AuthSource(crypto_config.auth_source),
                'auth_source_ref': crypto_config.auth_source_ref,
            },
        )

        changed_runtime = False
        desired_values = {
            'module_path': crypto_config.module_path,
            'token_label': crypto_config.token_label,
            'token_serial': crypto_config.token_serial,
            'slot_id': crypto_config.slot_id,
            'auth_source': AppSecretPkcs11AuthSource(crypto_config.auth_source),
            'auth_source_ref': crypto_config.auth_source_ref,
        }
        if not created:
            for field_name, value in desired_values.items():
                if getattr(secret_config, field_name) != value:
                    changed_runtime = True
                setattr(secret_config, field_name, value)
            if changed_runtime:
                secret_config.wrapped_dek = None
                secret_config.backup_encrypted_dek = None

        secret_config.full_clean()
        _save_untyped_model(secret_config)

        clear_app_secret_cache()
        get_app_secret_service().ensure_backend_ready()

    @staticmethod
    def _map_pkcs11_install_exit_code_to_message(return_code: int) -> str:
        """Map PKCS#11 asset-install script exit codes to user-facing error messages."""
        error_messages = {
            1: 'The PKCS#11 install script did not receive the required staged setup values.',
            2: 'The staged PKCS#11 library is missing or no longer belongs to this wizard session.',
            3: 'The staged PKCS#11 user PIN file is missing or no longer belongs to this wizard session.',
            4: 'Failed to install the PKCS#11 library into the protected HSM area.',
            5: 'Failed to create the protected PKCS#11 user PIN file.',
            6: 'Failed to persist the installed PKCS#11 module path for the instance.',
            7: 'The staged PKCS#11 provider config is missing or no longer belongs to this wizard session.',
            8: 'Failed to install the PKCS#11 provider config into the protected HSM area.',
        }
        return error_messages.get(return_code, 'An unknown error occurred while installing PKCS#11 assets.')

    @staticmethod
    def _ensure_local_dev_pkcs11_module(config_model: SetupWizardConfigModel) -> Path:
        """Use the local development PKCS#11 handoff module when available and needed."""
        local_dev_module = local_dev_pkcs11_module_path()
        configured_module_value = (config_model.fresh_install_pkcs11_module_path or '').strip()
        configured_module_exists = bool(configured_module_value and Path(configured_module_value).is_file())

        if (not configured_module_value or not configured_module_exists) and local_dev_pkcs11_handoff_available():
            config_model.fresh_install_pkcs11_module_path = str(local_dev_module)

        return local_dev_module

    @staticmethod
    def _uses_builtin_local_pkcs11_handoff(
        *,
        staged_pin: Path | None,
        local_dev_module: Path,
        configured_module_path: Path,
    ) -> bool:
        """Return whether the built-in local PKCS#11 handoff can be used."""
        del staged_pin
        return (
            local_dev_pkcs11_handoff_available()
            and local_dev_module.is_file()
            and configured_module_path == local_dev_module
            and configured_module_path.is_file()
        )

    @staticmethod
    def _uses_existing_installed_pkcs11_module(
        *,
        staged_module: Path | None,
        staged_pin: Path | None,
        configured_module_path: Path,
    ) -> bool:
        """Return whether the wizard should keep an already installed module in place."""
        del staged_pin
        return staged_module is None and configured_module_path.is_file()

    @staticmethod
    def _discard_redundant_local_handoff_module(
        staged_module: Path | None,
        *,
        uses_builtin_local_handoff: bool,
    ) -> Path | None:
        """Discard an uploaded module when the local development module is already available."""
        if uses_builtin_local_handoff and staged_module is not None:
            cleanup_wizard_pkcs11_staged_path(staged_module)
            return None
        return staged_module

    @staticmethod
    def _validate_staged_pkcs11_assets(
        *,
        staged_module: Path | None,
        staged_pin: Path | None,
        uses_existing_installed_module: bool,
        uses_existing_installed_pin: bool,
    ) -> None:
        """Validate the staged PKCS#11 assets before installing them."""
        if staged_pin is None and not uses_existing_installed_pin:
            err_msg = 'The staged PKCS#11 setup files are incomplete. Enter the PIN again.'
            raise DjangoValidationError(err_msg)

        if staged_module is None and not uses_existing_installed_module:
            err_msg = 'The staged PKCS#11 setup files are incomplete. Upload the library and enter the PIN again.'
            raise DjangoValidationError(err_msg)

    @staticmethod
    def _build_pkcs11_install_args(
        *,
        staged_module: Path | None,
        staged_pin: Path | None,
        staged_config: Path | None,
        uses_existing_installed_module: bool,
        uses_existing_installed_pin: bool,
    ) -> tuple[str, ...]:
        """Build arguments for the PKCS#11 asset install helper."""
        if uses_existing_installed_module:
            if staged_config is not None:
                err_msg = 'The staged PKCS#11 setup files are incomplete. Upload the library and enter the PIN again.'
                raise DjangoValidationError(err_msg)
            if staged_pin is None:
                return ()
            return (str(staged_pin),)

        if staged_module is None:
            err_msg = 'The staged PKCS#11 setup files are incomplete. Upload the library and enter the PIN again.'
            raise DjangoValidationError(err_msg)

        if uses_existing_installed_pin:
            if staged_config is not None:
                return ('--use-installed-pin', str(staged_module), str(staged_config))
            return ('--use-installed-pin', str(staged_module))

        if staged_pin is None:
            err_msg = 'The staged PKCS#11 setup files are incomplete. Enter the PIN again.'
            raise DjangoValidationError(err_msg)

        if staged_config is not None:
            return (str(staged_module), str(staged_pin), str(staged_config))

        return (str(staged_module), str(staged_pin))

    @classmethod
    def _raise_pkcs11_install_script_error(
        cls,
        exc: subprocess.CalledProcessError,
        *,
        uses_existing_installed_module: bool,
    ) -> None:
        """Raise a user-facing validation error for a failed PKCS#11 install helper run."""
        script_error_detail = (exc.stderr or exc.stdout or '').strip()
        err_msg = cls._map_pkcs11_install_exit_code_to_message(exc.returncode)

        if uses_existing_installed_module and exc.returncode == 1:
            err_msg = (
                'The running Trustpoint container still appears to use the older PKCS#11 install helper. '
                'Rebuild and recreate the Trustpoint container, then try the setup wizard again.'
            )

        if script_error_detail:
            logger.exception('PKCS#11 install script failed: %s', script_error_detail)

        raise DjangoValidationError(err_msg) from exc

    @classmethod
    def _run_pkcs11_asset_install_script(
        cls,
        *,
        staged_module: Path | None,
        staged_pin: Path | None,
        staged_config: Path | None,
        uses_existing_installed_module: bool,
        uses_existing_installed_pin: bool,
    ) -> None:
        """Run the PKCS#11 asset install helper script."""
        install_args = cls._build_pkcs11_install_args(
            staged_module=staged_module,
            staged_pin=staged_pin,
            staged_config=staged_config,
            uses_existing_installed_module=uses_existing_installed_module,
            uses_existing_installed_pin=uses_existing_installed_pin,
        )
        if not install_args:
            return

        try:
            execute_shell_script(INSTALL_PKCS11_ASSETS, *install_args)
        except subprocess.CalledProcessError as exc:
            cls._raise_pkcs11_install_script_error(
                exc,
                uses_existing_installed_module=uses_existing_installed_module,
            )

    @staticmethod
    def _persist_installed_pkcs11_assets(
        *,
        config_model: SetupWizardConfigModel,
        staged_module: Path | None,
        staged_pin: Path | None,
        staged_config: Path | None,
    ) -> None:
        """Persist final PKCS#11 asset locations after successful installation."""
        if staged_pin is not None:
            cleanup_wizard_pkcs11_staged_path(staged_pin)

        if staged_module is not None:
            cleanup_wizard_pkcs11_staged_path(staged_module)
            config_model.fresh_install_pkcs11_module_path = str(FINAL_WIZARD_PKCS11_MODULE_PATH)

        if staged_config is not None:
            cleanup_wizard_pkcs11_staged_path(staged_config)
            config_model.fresh_install_pkcs11_config_path = str(FINAL_WIZARD_PKCS11_CONFIG_PATH)

        config_model.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        config_model.fresh_install_pkcs11_auth_source_ref = str(FINAL_WIZARD_PKCS11_PIN_PATH)
        config_model.save(
            update_fields=[
                'fresh_install_pkcs11_module_path',
                'fresh_install_pkcs11_auth_source',
                'fresh_install_pkcs11_auth_source_ref',
                'fresh_install_pkcs11_config_path',
            ]
        )

    @classmethod
    def _install_staged_pkcs11_assets(cls, config_model: SetupWizardConfigModel) -> None:
        """Install staged PKCS#11 assets into the protected HSM area through the wizard helper script."""
        staged_module = existing_wizard_pkcs11_staged_file(config_model.fresh_install_pkcs11_module_path)
        staged_pin = existing_wizard_pkcs11_staged_file(config_model.fresh_install_pkcs11_auth_source_ref)
        staged_config = existing_wizard_pkcs11_staged_file(config_model.fresh_install_pkcs11_config_path)

        if staged_module is None and staged_pin is None and staged_config is None:
            return

        local_dev_module = cls._ensure_local_dev_pkcs11_module(config_model)
        configured_module_path = Path((config_model.fresh_install_pkcs11_module_path or '').strip())
        uses_builtin_local_handoff = cls._uses_builtin_local_pkcs11_handoff(
            staged_pin=staged_pin,
            local_dev_module=local_dev_module,
            configured_module_path=configured_module_path,
        )
        staged_module = cls._discard_redundant_local_handoff_module(
            staged_module,
            uses_builtin_local_handoff=uses_builtin_local_handoff,
        )
        uses_existing_installed_module = uses_builtin_local_handoff or cls._uses_existing_installed_pkcs11_module(
            staged_module=staged_module,
            staged_pin=staged_pin,
            configured_module_path=configured_module_path,
        )
        uses_existing_installed_pin = staged_pin is None and _path_exists(FINAL_WIZARD_PKCS11_PIN_PATH)

        cls._validate_staged_pkcs11_assets(
            staged_module=staged_module,
            staged_pin=staged_pin,
            uses_existing_installed_module=uses_existing_installed_module,
            uses_existing_installed_pin=uses_existing_installed_pin,
        )
        if staged_pin is None and not uses_existing_installed_pin:
            return

        cls._run_pkcs11_asset_install_script(
            staged_module=staged_module,
            staged_pin=staged_pin,
            staged_config=staged_config,
            uses_existing_installed_module=uses_existing_installed_module,
            uses_existing_installed_pin=uses_existing_installed_pin,
        )
        cls._persist_installed_pkcs11_assets(
            config_model=config_model,
            staged_module=staged_module,
            staged_pin=staged_pin,
            staged_config=staged_config,
        )

    @classmethod
    def install_staged_pkcs11_assets(cls, config_model: SetupWizardConfigModel) -> None:
        """Install staged PKCS#11 assets into the protected HSM area."""
        cls._install_staged_pkcs11_assets(config_model)

    @classmethod
    def _configure_pkcs11_backend(cls, config_model: SetupWizardConfigModel) -> None:  # noqa: C901
        """Configure the PKCS#11 backend for the instance from wizard-staged values."""
        cls._install_staged_pkcs11_assets(config_model)

        module_path = Path(
            (config_model.fresh_install_pkcs11_module_path or '').strip() or str(FINAL_WIZARD_PKCS11_MODULE_PATH)
        )
        fallback_module_path = Path(settings.HSM_DEFAULT_PKCS11_MODULE_PATH)
        if not _path_exists(module_path) and _path_exists(fallback_module_path):
            module_path = fallback_module_path

        token_label = (config_model.fresh_install_pkcs11_token_label or '').strip() or None
        slot_id = config_model.fresh_install_pkcs11_slot_id
        auth_source_ref = (
            (config_model.fresh_install_pkcs11_auth_source_ref or '').strip() or str(FINAL_WIZARD_PKCS11_PIN_PATH)
        )
        fallback_pin_path = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
        if auth_source_ref and not _path_exists(Path(auth_source_ref)) and _path_exists(fallback_pin_path):
            auth_source_ref = str(fallback_pin_path)

        if not _path_exists(module_path):
            err_msg = f'The PKCS#11 module path does not exist: {module_path}'
            raise DjangoValidationError(err_msg)
        if token_label is None and slot_id is None:
            err_msg = 'No PKCS#11 token selector is configured for the setup wizard.'
            raise DjangoValidationError(err_msg)
        if not auth_source_ref:
            err_msg = 'No PKCS#11 user PIN source reference is configured for the setup wizard.'
            raise DjangoValidationError(err_msg)
        if not Path(auth_source_ref).exists():
            err_msg = f'The PKCS#11 user PIN file does not exist: {auth_source_ref}'
            raise DjangoValidationError(err_msg)
        config_env_var = (config_model.fresh_install_pkcs11_config_env_var or '').strip()
        config_path = (config_model.fresh_install_pkcs11_config_path or '').strip()
        if config_path and not config_env_var:
            err_msg = (
                'A PKCS#11 provider config file is configured, but no provider config environment variable is set.'
            )
            raise DjangoValidationError(err_msg)
        if config_env_var and config_path and _path_exists(Path(config_path)):
            os.environ[config_env_var] = config_path

        profile = cls._activate_profile(
            backend_kind=BackendKind.PKCS11,
            default_name='trustpoint-pkcs11-backend',
        )
        defaults = {
            'module_path': str(module_path),
            'token_label': token_label or '',
            'token_serial': (config_model.fresh_install_pkcs11_token_serial or '').strip(),
            'slot_id': slot_id,
            'auth_source': Pkcs11AuthSource.FILE,
            'auth_source_ref': auth_source_ref,
            'max_sessions': 8,
            'borrow_timeout_seconds': 5.0,
            'rw_sessions': True,
        }
        config, created = CryptoProviderPkcs11ConfigModel.objects.get_or_create(
            profile=profile,
            defaults=defaults,
        )
        if not created:
            for field_name, value in defaults.items():
                setattr(config, field_name, value)
        config.full_clean()
        config.save()

    @classmethod
    def _configure_instance_crypto_backend(cls, config_model: SetupWizardConfigModel) -> None:
        """Configure the redesigned crypto backend from the wizard selection."""
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage:
            cls._configure_software_backend()
            return
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            cls._configure_pkcs11_backend(config_model)
            return
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.RestBackend:
            err_msg = 'The REST crypto backend is not implemented yet.'
            raise DjangoValidationError(err_msg)

        err_msg = f'Unsupported crypto storage selection {config_model.crypto_storage!r}.'
        raise DjangoValidationError(err_msg)

    @classmethod
    def _configure_app_secret_backend(cls, config_model: SetupWizardConfigModel) -> None:
        """Configure the separate application-secret subsystem."""
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage:
            cls._configure_software_app_secret_backend()
            return
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            if config_model.fresh_install_pkcs11_enforce_app_secret_protection:
                cls._configure_pkcs11_app_secret_backend()
                return
            cls._configure_software_app_secret_backend()
            return
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.RestBackend:
            err_msg = 'The REST backend does not yet support application-secret encryption.'
            raise DjangoValidationError(err_msg)

        err_msg = f'Unsupported crypto storage selection {config_model.crypto_storage!r}.'
        raise DjangoValidationError(err_msg)

    @staticmethod
    def _add_form_validation_errors(
        form: FreshInstallSummaryModelForm,
        exception: DjangoValidationError,
    ) -> None:
        """Attach validation error messages to the summary form."""
        for error_message in exception.messages:
            form.add_error(None, error_message)

    def _handle_summary_validation_error(
        self,
        form: FreshInstallSummaryModelForm,
        exception: DjangoValidationError,
        *,
        log_message: str,
    ) -> HttpResponse:
        """Handle validation errors raised while applying the summary step."""
        self._add_form_validation_errors(form, exception)
        self.logger.exception(log_message)
        return self.form_invalid(form)

    def _handle_summary_exception(
        self,
        form: FreshInstallSummaryModelForm,
        exception: Exception,
    ) -> HttpResponse:
        """Handle non-validation errors raised while applying the summary step."""
        error_message = str(exception) or 'Error applying fresh-install summary configuration.'
        form.add_error(None, error_message)
        self.logger.exception('Error applying fresh-install summary configuration.')
        return self.form_invalid(form)

    def _handle_tls_apply_error(
        self,
        form: FreshInstallSummaryModelForm,
        exception: subprocess.CalledProcessError,
    ) -> HttpResponse:
        """Handle TLS apply script failures."""
        error_message = self._map_tls_apply_exit_code_to_message(exception.returncode)
        form.add_error(None, f'Error applying TLS Server Credential: {error_message}')
        self.logger.exception('Error applying fresh-install TLS server credential.')
        return self.form_invalid(form)

    def _apply_bootstrap_summary_configuration(self) -> tuple[Any | None, Any]:
        """Apply bootstrap configuration and attempt the runtime switch."""
        config_model = SetupWizardConfigModel.get_singleton()

        if config_model.operational_config_applied:
            result = refresh_pending_operational_env(config_model)
            switch_result = run_operational_runtime_switch(result.pending_env_file)
            return result, switch_result

        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            probe_staged_pkcs11_config_isolated(config_model, profile_name='setup-wizard-pkcs11-pre-apply')
            validate_staged_pkcs11_app_secret_protection_if_required(
                config_model,
                profile_name='setup-wizard-pkcs11-pre-apply-app-secret',
            )

        result = run_operational_handoff(config_model)
        config_model.mark_step_submitted(self.step_state)
        config_model.operational_config_applied = True
        config_model.save(update_fields=['fresh_install_summary_submitted', 'operational_config_applied'])
        switch_result = run_operational_runtime_switch(result.pending_env_file)
        return result, switch_result

    def _handle_bootstrap_switch_result(self, result: Any | None, switch_result: Any) -> HttpResponse:
        """Return the response for a completed bootstrap runtime switch attempt."""
        if switch_result.switched:
            return redirect('/users/login/', permanent=False)

        handoff_marker_message = ''
        if result is not None:
            handoff_marker_message = f'The handoff marker was written to {result.env_file}. '

        messages.success(
            self.request,
            (
                'Operational configuration was applied successfully. '
                f'{handoff_marker_message}{switch_result.detail}'
            ),
        )
        return redirect('setup_wizard:fresh_install_summary')

    def _handle_bootstrap_summary_submission(self, form: FreshInstallSummaryModelForm) -> HttpResponse:
        """Apply the summary step while running in bootstrap mode."""
        try:
            result, switch_result = self._apply_bootstrap_summary_configuration()
        except DjangoValidationError as exception:
            return self._handle_summary_validation_error(
                form,
                exception,
                log_message='Error applying bootstrap configuration to operational runtime.',
            )

        return self._handle_bootstrap_switch_result(result, switch_result)

    def _apply_direct_summary_configuration(self, form: FreshInstallSummaryModelForm) -> HttpResponse:
        """Apply the summary step directly in the current runtime."""
        with transaction.atomic():
            config_model = SetupWizardConfigModel.get_singleton()
            if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
                probe_staged_pkcs11_config_isolated(config_model, profile_name='setup-wizard-pkcs11-pre-apply')
                validate_staged_pkcs11_app_secret_protection_if_required(
                    config_model,
                    profile_name='setup-wizard-pkcs11-pre-apply-app-secret',
                )
            self._configure_instance_crypto_backend(config_model)
            self._configure_app_secret_backend(config_model)
            call_command('create_default_cert_profiles')
            if config_model.inject_demo_data:
                call_command('add_domains_and_devices')
            call_command('execute_all_notifications')
            self._apply_staged_tls_credential()
            SetupWizardCompletedModel.mark_setup_complete_once()
            return super().form_valid(form)

    def _handle_direct_summary_submission(self, form: FreshInstallSummaryModelForm) -> HttpResponse:
        """Apply the summary step while running in the current runtime."""
        try:
            return self._apply_direct_summary_configuration(form)
        except subprocess.CalledProcessError as exception:
            return self._handle_tls_apply_error(form, exception)
        except DjangoValidationError as exception:
            return self._handle_summary_validation_error(
                form,
                exception,
                log_message='Error applying fresh-install summary configuration.',
            )
        except (
            CommandError,
            DatabaseError,
            FileNotFoundError,
            OSError,
            ProtectedError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exception:
            return self._handle_summary_exception(form, exception)

    def form_valid(self, form: FreshInstallSummaryModelForm) -> HttpResponse:
        """Apply the first summary step actions before continuing the setup flow."""
        if getattr(settings, 'TRUSTPOINT_IS_BOOTSTRAP', False):
            return self._handle_bootstrap_summary_submission(form)

        return self._handle_direct_summary_submission(form)


class FreshInstallSummaryTruststoreDownloadView(LoginRequiredMixin, LoggerMixin, View):
    """Download the staged root CA certificate from the summary page."""

    http_method_names = ('get',)

    @staticmethod
    def _get_root_ca_certificate_and_content_type(
        root_ca_certificate_serializer: CertificateSerializer,
        file_format: str,
    ) -> tuple[bytes, str]:
        """Return the staged root CA certificate in the requested format."""
        if file_format == 'pem':
            return root_ca_certificate_serializer.as_pem(), 'application/x-pem-file'
        if file_format == 'der':
            return root_ca_certificate_serializer.as_der(), 'application/pkix-cert'

        err_msg = f'Invalid file format requested: {file_format}.'
        raise ValueError(err_msg)

    def get(self, request: HttpRequest, *_args: Any, **kwargs: Any) -> HttpResponse:
        """Handle the summary truststore download."""
        file_format = kwargs['file_format']
        if file_format not in {'pem', 'der'}:
            messages.add_message(request, messages.ERROR, 'Only PEM and DER downloads are supported.')
            return redirect('setup_wizard:fresh_install_summary', permanent=False)

        root_ca_certificate_serializer = get_staged_root_ca_certificate_serializer()
        if root_ca_certificate_serializer is None:
            messages.add_message(request, messages.ERROR, 'No truststore available for download.')
            return redirect('setup_wizard:fresh_install_summary', permanent=False)

        try:
            trust_store, content_type = self._get_root_ca_certificate_and_content_type(
                root_ca_certificate_serializer,
                file_format,
            )
        except ValueError as exception:
            messages.add_message(request, messages.ERROR, str(exception))
            return redirect('setup_wizard:fresh_install_summary', permanent=False)

        response = HttpResponse(content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="trust_store_root_ca.{file_format}"'
        response.write(trust_store)
        return response


class FreshInstallCancelView(LoginRequiredMixin, LoggerMixin, View):
    """Discard the unfinished fresh-install wizard state and return to the setup index."""

    http_method_names = ('post',)

    @staticmethod
    def _cleanup_partial_runtime_artifacts() -> None:
        """Remove runtime files and crypto records created by an unfinished setup attempt."""
        for path in (
            FINAL_WIZARD_PKCS11_MODULE_PATH,
            FINAL_WIZARD_PKCS11_PIN_PATH,
            Path(settings.HSM_DEFAULT_PKCS11_MODULE_PATH_FILE),
            NGINX_KEY_PATH,
            NGINX_CERT_PATH,
            NGINX_CERT_CHAIN_PATH,
        ):
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                continue

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Delete staged wizard data and log the bootstrap user out."""
        del args
        del kwargs

        if SetupWizardCompletedModel.setup_wizard_completed():
            self.logger.warning('Ignoring fresh-install cancel request because setup is already completed.')
            return redirect('setup_wizard:index', permanent=False)

        config_model = SetupWizardConfigModel.get_singleton()
        cleanup_wizard_pkcs11_staged_path(config_model.fresh_install_pkcs11_module_path)
        cleanup_wizard_pkcs11_staged_path(config_model.fresh_install_pkcs11_auth_source_ref)
        clear_staged_tls_credential()
        self._cleanup_partial_runtime_artifacts()

        with transaction.atomic():
            SetupWizardConfigModel.objects.filter(pk=SetupWizardConfigModel.SINGLETON_ID).delete()

        clear_app_secret_cache()
        logout(request)
        return redirect('setup_wizard:index', permanent=False)


# Operational Attach Flows -------------------------------------------------------------------------------------------


class ConnectExistingWizardMixin[FormT: BaseForm](LoginRequiredMixin, LoggerMixin, FormView[FormT]):
    """Small-step wizard shell for connecting to existing operational state."""

    template_name = 'setup_wizard/operational_attach_wizard.html'
    attach_mode = OperationalAttachMode.CONNECT_EXISTING
    page_title = 'Connect Existing Instance'
    step_name: str
    body_heading: str = ''
    back_url: str | Promise | None = None
    step_url_names: ClassVar[dict[str, str]] = {
        'database': 'connect_existing_database',
        'crypto-storage': 'connect_existing_crypto_storage',
        'backend-config': 'connect_existing_backend_config',
        'summary': 'connect_existing_summary',
    }
    step_labels: ClassVar[dict[str, str]] = {
        'database': 'Database',
        'crypto-storage': 'Crypto Backend',
        'backend-config': 'Backend Config',
        'summary': 'Inspect & Apply',
    }

    class StepState(enum.StrEnum):
        """Display state for connect-existing progress."""

        ACTIVE = 'active'
        DONE = 'done'
        AVAILABLE = 'available'

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind connect-existing step forms to the bootstrap singleton."""
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = SetupWizardConfigModel.get_singleton()
        return kwargs

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Remember the current attach step before rendering it."""
        config_model = SetupWizardConfigModel.get_singleton()
        record_bootstrap_progress(config_model, flow=self.attach_mode, step_name=self.step_name)
        return super().get(request, *args, **kwargs)

    def _step_state(self, step_name: str) -> StepState:
        """Return the UI state for a connect-existing step."""
        if step_name == self.step_name:
            return self.StepState.ACTIVE
        config_model = SetupWizardConfigModel.get_singleton()
        submitted_by_step = {
            'database': config_model.fresh_install_database_submitted,
            'crypto-storage': config_model.fresh_install_crypto_storage_submitted,
            'backend-config': config_model.fresh_install_backend_config_submitted,
            'backup-import': config_model.restore_backup_import_submitted,
            'summary': config_model.fresh_install_summary_submitted,
        }
        return self.StepState.DONE if submitted_by_step.get(step_name, False) else self.StepState.AVAILABLE

    def _step_redirect(self, step_name: str) -> HttpResponse:
        """Redirect to a named step in this attach wizard."""
        return redirect(f'setup_wizard:{self.step_url_names[step_name]}')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Render shared connect-existing wizard metadata."""
        context = super().get_context_data(**kwargs)
        context['page_title'] = self.page_title
        context['body_heading'] = self.body_heading
        context['back_url'] = self.back_url
        context['steps'] = []
        for step_name, url_name in self.step_url_names.items():
            step_state = self._step_state(step_name)
            context['steps'].append(
                {
                    'label': self.step_labels[step_name],
                    'url': reverse(f'setup_wizard:{url_name}'),
                    'state': str(step_state),
                    'submitted': step_state == self.StepState.DONE,
                }
            )
        return context


class ConnectExistingDatabaseView(ConnectExistingWizardMixin[FreshInstallDatabaseModelForm]):
    """Connect-existing step for staging the operational database."""

    form_class = FreshInstallDatabaseModelForm
    success_url = reverse_lazy('setup_wizard:connect_existing_crypto_storage')
    step_name = 'database'
    back_url = reverse_lazy('setup_wizard:index')
    body_heading = 'Configure Operational Database'

    def form_valid(self, form: FreshInstallDatabaseModelForm) -> HttpResponse:
        """Persist or test the operational database settings."""
        form.save()
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.mark_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.DATABASE)
        config_model.save()

        if self.request.POST.get('wizard_action') == 'test_database':
            try:
                FreshInstallDatabaseView._test_database_connection(form)  # noqa: SLF001 - shared wizard helper.
            except Exception as exception:
                self.logger.exception('Connect-existing PostgreSQL connection test failed.')
                error_detail = str(exception).strip() or type(exception).__name__
                form.add_error(None, f'Could not connect to PostgreSQL: {error_detail}')
                return self.render_to_response(self.get_context_data(form=form))
            messages.success(self.request, 'PostgreSQL connection successful.')
            return self._step_redirect('database')

        return super().form_valid(form)


class ConnectExistingCryptoStorageView(ConnectExistingWizardMixin[FreshInstallCryptoStorageModelForm]):
    """Connect-existing step for selecting the backend kind."""

    form_class = FreshInstallCryptoStorageModelForm
    success_url = reverse_lazy('setup_wizard:connect_existing_backend_config')
    step_name = 'crypto-storage'
    back_url = reverse_lazy('setup_wizard:connect_existing_database')
    body_heading = 'Select Crypto Backend'

    def form_valid(self, form: FreshInstallCryptoStorageModelForm) -> HttpResponse:
        """Persist the backend kind and clear stale PKCS#11 staging when needed."""
        if form.cleaned_data['crypto_storage'] != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            FreshInstallCryptoStorageView._reset_staged_pkcs11_backend(form)  # noqa: SLF001 - shared wizard helper.
        form.save()
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.mark_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE)
        config_model.save()
        return super().form_valid(form)


class ConnectExistingBackendConfigView(ConnectExistingWizardMixin[FreshInstallBackendConfigModelForm]):
    """Connect-existing step for backend-specific connection details."""

    form_class = FreshInstallBackendConfigModelForm
    success_url = reverse_lazy('setup_wizard:connect_existing_summary')
    step_name = 'backend-config'
    back_url = reverse_lazy('setup_wizard:connect_existing_crypto_storage')
    body_heading = 'Configure Backend'

    @staticmethod
    def _stage_uploaded_pkcs11_module(uploaded_module: Any) -> str:
        """Write an uploaded PKCS#11 library to private one-time wizard staging."""
        return stage_uploaded_pkcs11_module(uploaded_module)

    @staticmethod
    def _stage_pkcs11_user_pin(user_pin: str) -> str:
        """Write the entered PKCS#11 user PIN to private one-time wizard staging."""
        return stage_pkcs11_user_pin(user_pin)

    @staticmethod
    def _stage_uploaded_pkcs11_config(uploaded_config: Any) -> str:
        """Write an optional provider PKCS#11 config to private one-time wizard staging."""
        return stage_uploaded_pkcs11_config(uploaded_config)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle staged PKCS#11 asset removal before normal form validation."""
        config_model = SetupWizardConfigModel.get_singleton()
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            if is_clear_pkcs11_module_submission(request):
                clear_staged_pkcs11_module(config_model)
                messages.success(request, 'The PKCS#11 library was removed for this wizard session.')
                return self._step_redirect('backend-config')
            if is_clear_pkcs11_pin_submission(request):
                clear_staged_pkcs11_pin(config_model)
                messages.success(request, 'The PKCS#11 user PIN was removed for this wizard session.')
                return self._step_redirect('backend-config')
            if is_clear_pkcs11_config_submission(request):
                clear_staged_pkcs11_config(config_model)
                messages.success(request, 'The PKCS#11 provider config was removed for this wizard session.')
                return self._step_redirect('backend-config')
        return super().post(request, *args, **kwargs)

    def _persist_pkcs11_backend_config(self, form: FreshInstallBackendConfigModelForm) -> None:
        """Persist PKCS#11 attach details using the fresh-install staging helper."""
        persist_staged_pkcs11_backend_config(form)

    def _test_pkcs11_connection(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Test PKCS#11 connectivity without advancing."""
        response = run_staged_pkcs11_connection_test(
            self,
            form,
            success_redirect_name=f"setup_wizard:{self.step_url_names['backend-config']}",
        )
        if response.status_code in {301, 302}:
            return self._step_redirect('backend-config')
        return response

    def form_valid(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Persist backend configuration or keep the user on this step for tests."""
        if form.instance.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            self._persist_pkcs11_backend_config(form)
            if is_pkcs11_test_connection_submission(self.request):
                return self._test_pkcs11_connection(form)

        config_model = SetupWizardConfigModel.get_singleton()
        config_model.mark_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.BACKEND_CONFIG)
        config_model.save()
        return super().form_valid(form)

    def form_invalid(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Use the fresh-install invalid handler so uploaded PKCS#11 files are preserved."""
        persist_valid_pkcs11_fields_from_invalid_form(form)
        return super().form_invalid(form)


def backend_kind_for_config(config_model: SetupWizardConfigModel) -> str:
    """Map the staged wizard backend selection to the normalized backend kind."""
    if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage:
        return BackendKind.SOFTWARE.value
    if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
        return BackendKind.PKCS11.value
    if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.RestBackend:
        return BackendKind.REST.value
    return str(config_model.crypto_storage)


def database_error_report(
    *,
    mode: OperationalAttachMode,
    target: OperationalTargetConfig,
    exception: Exception,
) -> OperationalCompatibilityReport:
    """Build a blocking report for a failed target database inspection."""
    error_detail = str(exception).strip() or type(exception).__name__
    return OperationalCompatibilityReport(
        mode=mode,
        target=target,
        snapshot=None,
        checks=(
            CompatibilityCheck(
                code='database.unreachable',
                label='Operational Database',
                severity=CompatibilitySeverity.ERROR,
                message=f'Could not inspect the operational database: {error_detail}',
            ),
        ),
    )


def attach_backend_readiness_checks(config_model: SetupWizardConfigModel) -> tuple[CompatibilityCheck, ...]:
    """Validate that the staged backend can be reached by this bootstrap container."""
    backend_kind = backend_kind_for_config(config_model)
    if backend_kind == BackendKind.SOFTWARE.value:
        return (
            CompatibilityCheck(
                code='backend.runtime_software',
                label='Backend Runtime',
                severity=CompatibilitySeverity.INFO,
                message='The software crypto backend is selected for this container.',
            ),
        )

    if backend_kind == BackendKind.REST.value:
        return (
            CompatibilityCheck(
                code='backend.runtime_rest_unavailable',
                label='Backend Runtime',
                severity=CompatibilitySeverity.ERROR,
                message='The REST crypto backend is scaffolded but is not implemented for attach/restore yet.',
            ),
        )

    if backend_kind != BackendKind.PKCS11.value:
        return (
            CompatibilityCheck(
                code='backend.runtime_unknown',
                label='Backend Runtime',
                severity=CompatibilitySeverity.ERROR,
                message=f'Unsupported staged backend kind {backend_kind!r}.',
            ),
        )

    try:
        capabilities = probe_staged_pkcs11_config_isolated(
            config_model,
            profile_name='setup-wizard-pkcs11-attach-readiness',
        )
    except DjangoValidationError as exception:
        error_detail = '; '.join(exception.messages) if hasattr(exception, 'messages') else str(exception)
        return (
            CompatibilityCheck(
                code='backend.runtime_pkcs11_unavailable',
                label='Backend Runtime',
                severity=CompatibilitySeverity.ERROR,
                message=f'Could not authenticate to the staged PKCS#11 backend: {error_detail}',
            ),
        )

    token_label = capabilities.token.label or 'unlabeled token'
    token_serial = capabilities.token.serial or 'unknown serial'
    return (
        CompatibilityCheck(
            code='backend.runtime_pkcs11_ok',
            label='Backend Runtime',
            severity=CompatibilitySeverity.INFO,
            message=(
                f'This container can authenticate to PKCS#11 token {token_label!r} '
                f'({token_serial}) in slot {capabilities.token.slot_id}.'
            ),
        ),
    )


def _build_staged_pkcs11_app_secret_config(
    config_model: SetupWizardConfigModel,
    *,
    wrapped_dek: bytes,
    kek_label: str,
) -> AppSecretPkcs11ConfigModel:
    """Build an unsaved app-secret PKCS#11 config for attach validation."""
    module_path, pin_file, _update_fields = apply_pkcs11_probe_fallbacks(config_model)
    token_label = (config_model.fresh_install_pkcs11_token_label or '').strip() or None
    token_serial = (config_model.fresh_install_pkcs11_token_serial or '').strip() or None
    slot_id = config_model.fresh_install_pkcs11_slot_id

    validate_pkcs11_probe_inputs(
        module_path=module_path,
        pin_file=pin_file,
        token_label=token_label,
        slot_id=slot_id,
    )

    backend = AppSecretBackendModel(
        singleton_id=AppSecretBackendModel.SINGLETON_ID,
        backend_kind=AppSecretBackendKind.PKCS11,
    )
    return AppSecretPkcs11ConfigModel(
        backend=backend,
        module_path=module_path,
        token_label=token_label or '',
        token_serial=token_serial or '',
        slot_id=slot_id,
        auth_source=AppSecretPkcs11AuthSource.FILE,
        auth_source_ref=pin_file,
        kek_label=kek_label,
        wrapped_dek=wrapped_dek,
    )


def app_secret_decryptability_checks(  # noqa: PLR0911
    *,
    config_model: SetupWizardConfigModel,
    target: OperationalTargetConfig,
    snapshot: OperationalStateSnapshot,
) -> tuple[CompatibilityCheck, ...]:
    """Validate that the staged backend can recover the target app-secret DEK."""
    if not snapshot.app_secret_backend_kind:
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_skipped',
                label='Application Secrets',
                severity=CompatibilitySeverity.WARNING,
                message='App-secret decryptability could not be checked because the target backend kind is unknown.',
            ),
        )

    if target.app_secret_backend.backend_kind != snapshot.app_secret_backend_kind:
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_skipped',
                label='Application Secrets',
                severity=CompatibilitySeverity.WARNING,
                message='App-secret decryptability was skipped because the staged backend kind does not match.',
            ),
        )

    try:
        material = OperationalTargetInspector().inspect_app_secret_material(target.database)
    except (OSError, RuntimeError, TypeError, ValueError, psycopg.Error) as exception:
        error_detail = str(exception).strip() or type(exception).__name__
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_inspection_failed',
                label='Application Secrets',
                severity=CompatibilitySeverity.ERROR,
                message=f'Could not read target app-secret material for validation: {error_detail}',
            ),
        )

    if material.backend_kind == BackendKind.SOFTWARE.value:
        if len(material.raw_dek) == DEK_LENGTH_BYTES:
            return (
                CompatibilityCheck(
                    code='appsecret.decryptability_ok',
                    label='Application Secrets',
                    severity=CompatibilitySeverity.INFO,
                    message='The target software app-secret DEK is present and has the expected length.',
                ),
            )
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_failed',
                label='Application Secrets',
                severity=CompatibilitySeverity.ERROR,
                message='The target software app-secret DEK is missing or has an invalid length.',
            ),
        )

    if material.backend_kind != BackendKind.PKCS11.value:
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_skipped',
                label='Application Secrets',
                severity=CompatibilitySeverity.WARNING,
                message=f'No app-secret decryptability check is implemented for {material.backend_kind!r}.',
            ),
        )

    if not material.wrapped_dek:
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_failed',
                label='Application Secrets',
                severity=CompatibilitySeverity.ERROR,
                message='The target database has no protected app-secret DEK to validate.',
            ),
        )

    if config_model.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_failed',
                label='Application Secrets',
                severity=CompatibilitySeverity.ERROR,
                message='The target app-secret backend is PKCS#11, but the staged backend is not an HSM backend.',
            ),
        )

    try:
        secret_config = _build_staged_pkcs11_app_secret_config(
            config_model,
            wrapped_dek=material.wrapped_dek,
            kek_label=material.kek_label,
        )
        Pkcs11AppSecretService(secret_config).recover_existing_dek()
    except (AppSecretConfigurationError, DjangoValidationError, OSError, RuntimeError, ValueError) as exception:
        error_detail = str(exception).strip() or type(exception).__name__
        return (
            CompatibilityCheck(
                code='appsecret.decryptability_failed',
                label='Application Secrets',
                severity=CompatibilitySeverity.ERROR,
                message=f'The staged PKCS#11 backend could not recover the target app-secret DEK: {error_detail}',
            ),
        )

    return (
        CompatibilityCheck(
            code='appsecret.decryptability_ok',
            label='Application Secrets',
            severity=CompatibilitySeverity.INFO,
            message='The staged PKCS#11 backend can recover the target app-secret DEK.',
        ),
    )


def _build_staged_pkcs11_managed_key_backend(config_model: SetupWizardConfigModel) -> Pkcs11Backend:
    """Build a PKCS#11 backend from the staged wizard config for read-only key verification."""
    module_path, pin_file, _update_fields = apply_pkcs11_probe_fallbacks(config_model)
    token_label = (config_model.fresh_install_pkcs11_token_label or '').strip() or None
    token_serial = (config_model.fresh_install_pkcs11_token_serial or '').strip() or None
    slot_id = config_model.fresh_install_pkcs11_slot_id

    validate_pkcs11_probe_inputs(
        module_path=module_path,
        pin_file=pin_file,
        token_label=token_label,
        slot_id=slot_id,
    )
    profile = build_pkcs11_probe_profile(
        profile_name='setup-wizard-pkcs11-managed-key-reconciliation',
        module_path=module_path,
        pin_file=pin_file,
        token_selector=Pkcs11TokenSelector(token_label=token_label, token_serial=token_serial, slot_id=slot_id),
    )
    return Pkcs11Backend(profile=profile)


def _managed_key_binding_from_material(material: Any) -> object:
    """Build an adapter binding from target DB material."""
    algorithm = KeyAlgorithm(material.algorithm)
    signing_execution_mode = SigningExecutionMode(material.signing_execution_mode)
    provider_label = material.provider_label or None

    if material.backend_kind == BackendKind.PKCS11.value:
        return Pkcs11ManagedKeyBinding(
            key_id=bytes.fromhex(str(material.binding['key_id_hex'])),
            algorithm=algorithm,
            public_key_fingerprint_sha256=material.public_key_fingerprint_sha256,
            signing_execution_mode=signing_execution_mode,
            provider_label=provider_label,
        )

    if material.backend_kind == BackendKind.SOFTWARE.value:
        return SoftwareManagedKeyBinding(
            key_handle=str(material.binding['key_handle']),
            algorithm=algorithm,
            encrypted_private_key_pkcs8_der=bytes(material.binding['encrypted_private_key_pkcs8_der']),
            encryption_metadata=dict(material.binding.get('encryption_metadata') or {}),
            public_key_fingerprint_sha256=material.public_key_fingerprint_sha256,
            signing_execution_mode=signing_execution_mode,
            provider_label=provider_label,
        )

    err_msg = f'No live managed-key binding adapter exists for backend {material.backend_kind!r}.'
    raise DjangoValidationError(err_msg)


def _software_backend_for_target(target: OperationalTargetConfig) -> SoftwareBackend:
    """Build a software backend from target DB configuration for key verification."""
    software_material = OperationalTargetInspector().inspect_software_backend_material(target.database)
    if software_material is None:
        err_msg = 'The target database does not contain active software backend configuration.'
        raise DjangoValidationError(err_msg)
    return SoftwareBackend(
        profile=SoftwareProviderProfile(
            name='setup-wizard-software-managed-key-reconciliation',
            encryption_source=software_material.encryption_source,
            encryption_source_ref=software_material.encryption_source_ref or None,
            allow_exportable_private_keys=software_material.allow_exportable_private_keys,
        )
    )


def _managed_key_reconciliation_backend(
    *,
    config_model: SetupWizardConfigModel,
    target: OperationalTargetConfig,
    backend_kind: str,
) -> Pkcs11Backend | SoftwareBackend:
    """Build the staged backend used for live managed-key reconciliation."""
    if backend_kind == BackendKind.PKCS11.value:
        if config_model.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            err_msg = 'The target managed keys are PKCS#11-backed, but the staged backend is not HSM storage.'
            raise DjangoValidationError(err_msg)
        return _build_staged_pkcs11_managed_key_backend(config_model)

    if backend_kind == BackendKind.SOFTWARE.value:
        return _software_backend_for_target(target)

    err_msg = f'Live managed-key reconciliation is not implemented for backend {backend_kind!r}.'
    raise DjangoValidationError(err_msg)


def managed_key_backend_reconciliation_checks(  # noqa: C901, PLR0911, PLR0912
    *,
    config_model: SetupWizardConfigModel,
    target: OperationalTargetConfig,
    snapshot: OperationalStateSnapshot,
) -> tuple[CompatibilityCheck, ...]:
    """Validate that DB managed-key bindings resolve to matching live backend objects."""
    if snapshot.managed_key_count == 0:
        return (
            CompatibilityCheck(
                code='managed_keys.backend_reconciliation_skipped',
                label='Managed Keys',
                severity=CompatibilitySeverity.INFO,
                message='No managed keys exist in the target database, so live backend reconciliation was skipped.',
            ),
        )

    if not snapshot.crypto_backend_kind:
        return (
            CompatibilityCheck(
                code='managed_keys.backend_reconciliation_skipped',
                label='Managed Keys',
                severity=CompatibilitySeverity.WARNING,
                message='Managed-key reconciliation could not run because the target backend kind is unknown.',
            ),
        )

    if target.crypto_backend.backend_kind != snapshot.crypto_backend_kind:
        return (
            CompatibilityCheck(
                code='managed_keys.backend_reconciliation_skipped',
                label='Managed Keys',
                severity=CompatibilitySeverity.WARNING,
                message='Managed-key reconciliation was skipped because the staged backend kind does not match.',
            ),
        )

    try:
        materials = OperationalTargetInspector().inspect_managed_key_material(target.database)
    except (OSError, RuntimeError, TypeError, ValueError, psycopg.Error) as exception:
        error_detail = str(exception).strip() or type(exception).__name__
        return (
            CompatibilityCheck(
                code='managed_keys.backend_reconciliation_failed',
                label='Managed Keys',
                severity=CompatibilitySeverity.ERROR,
                message=f'Could not read managed-key binding material from the target database: {error_detail}',
            ),
        )

    if not materials:
        return (
            CompatibilityCheck(
                code='managed_keys.backend_reconciliation_failed',
                label='Managed Keys',
                severity=CompatibilitySeverity.ERROR,
                message='The target database has managed keys, but no backend binding material could be read.',
            ),
        )

    try:
        backend = _managed_key_reconciliation_backend(
            config_model=config_model,
            target=target,
            backend_kind=snapshot.crypto_backend_kind,
        )
    except DjangoValidationError as exception:
        error_detail = '; '.join(exception.messages) if hasattr(exception, 'messages') else str(exception)
        return (
            CompatibilityCheck(
                code='managed_keys.backend_reconciliation_failed',
                label='Managed Keys',
                severity=CompatibilitySeverity.ERROR,
                message=f'Could not initialize live backend reconciliation: {error_detail}',
            ),
        )

    missing_count = 0
    mismatch_count = 0
    error_count = 0
    verification_backend = cast('ManagedKeyBackendAdapter', backend)
    try:
        for material in materials:
            try:
                binding = _managed_key_binding_from_material(material)
                verification = verification_backend.verify_managed_key(binding)
            except (CryptoError, DjangoValidationError, KeyError, TypeError, ValueError):
                error_count += 1
                continue

            if verification.status == ManagedKeyVerificationStatus.MISSING:
                missing_count += 1
            elif verification.status == ManagedKeyVerificationStatus.MISMATCH:
                mismatch_count += 1
            elif verification.status != ManagedKeyVerificationStatus.PRESENT:
                error_count += 1
    finally:
        backend.close()

    if missing_count or mismatch_count or error_count:
        return (
            CompatibilityCheck(
                code='managed_keys.backend_reconciliation_failed',
                label='Managed Keys',
                severity=CompatibilitySeverity.ERROR,
                message=(
                    f'Live backend reconciliation failed for {missing_count} missing, '
                    f'{mismatch_count} mismatched, and {error_count} unreadable managed keys.'
                ),
            ),
        )

    return (
        CompatibilityCheck(
            code='managed_keys.backend_reconciliation_ok',
            label='Managed Keys',
            severity=CompatibilitySeverity.INFO,
            message=f'All {len(materials)} managed-key bindings resolve to matching live backend public keys.',
        ),
    )


class ConnectExistingSummaryView(ConnectExistingWizardMixin[EmptyForm]):
    """Connect-existing summary step for inspection and explicit attach."""

    form_class = EmptyForm
    step_name = 'summary'
    back_url = reverse_lazy('setup_wizard:connect_existing_backend_config')
    body_heading = 'Inspect and Attach'

    def get_form_kwargs(self) -> dict[str, Any]:
        """The summary uses a plain confirmation form, not the setup singleton model form."""
        return FormView.get_form_kwargs(self)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Inspect the target on the summary page."""
        context = super().get_context_data(**kwargs)
        context['compatibility_report'] = kwargs.get('compatibility_report') or self._build_report()
        context['is_attach_summary'] = True
        context['summary_submit_label'] = (
            'Apply Restore' if self.attach_mode == OperationalAttachMode.RESTORE_BACKUP else 'Apply Attach'
        )
        return context

    def _build_target(self, config_model: SetupWizardConfigModel) -> OperationalTargetConfig:
        """Build the immutable attach target from staged bootstrap state."""
        backend_kind = backend_kind_for_config(config_model)
        return OperationalTargetConfig(
            mode=self.attach_mode,
            database=OperationalDatabaseConfig(
                host=config_model.operational_db_host,
                port=config_model.operational_db_port,
                name=config_model.operational_db_name,
                user=config_model.operational_db_user,
                password=config_model.operational_db_password,
            ),
            crypto_backend=OperationalBackendBinding(backend_kind=backend_kind),
            app_secret_backend=OperationalBackendBinding(backend_kind=backend_kind),
            backup_file_name=config_model.restore_backup_archive_original_name or None,
        )

    def _build_report(self) -> OperationalCompatibilityReport:
        """Build the current compatibility report for the staged target."""
        config_model = SetupWizardConfigModel.get_singleton()
        target = self._build_target(config_model)
        try:
            snapshot = OperationalTargetInspector().inspect_database(target.database)
        except Exception as exception:
            self.logger.exception('Connect-existing database inspection failed.')
            report = database_error_report(
                mode=self.attach_mode,
                target=target,
                exception=exception,
            )
            return report.with_checks(attach_backend_readiness_checks(config_model))
        report = OperationalAttachmentValidator(current_version=settings.APP_VERSION).build_report(
            mode=self.attach_mode,
            target=target,
            snapshot=snapshot,
        )
        return report.with_checks(
            (
                *attach_backend_readiness_checks(config_model),
                *app_secret_decryptability_checks(
                    config_model=config_model,
                    target=target,
                    snapshot=snapshot,
                ),
                *managed_key_backend_reconciliation_checks(
                    config_model=config_model,
                    target=target,
                    snapshot=snapshot,
                ),
            )
        )

    def form_valid(self, form: EmptyForm) -> HttpResponse:
        """Explicitly attach this container to the inspected operational target."""
        _ = form
        config_model = SetupWizardConfigModel.get_singleton()
        report = self._build_report()
        if not report.can_apply:
            return self.render_to_response(self.get_context_data(compatibility_report=report))

        try:
            if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
                FreshInstallSummaryView.install_staged_pkcs11_assets(config_model)
            handoff_result = run_operational_attach_handoff(config_model)
            runtime_result = run_operational_runtime_switch(handoff_result.pending_env_file)
        except DjangoValidationError as exception:
            form.add_error(None, str(exception))
            return self.render_to_response(self.get_context_data(form=form, compatibility_report=report))

        config_model.operational_config_applied = True
        config_model.mark_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY)
        config_model.save()
        SetupWizardCompletedModel.mark_setup_complete_once()
        if runtime_result.switched:
            success_message = (
                'Operational runtime restored and attached successfully.'
                if self.attach_mode == OperationalAttachMode.RESTORE_BACKUP
                else 'Operational runtime attached successfully.'
            )
            messages.success(self.request, success_message)
        else:
            pending_message = (
                'Operational restore configuration saved. Restart the runtime to attach.'
                if self.attach_mode == OperationalAttachMode.RESTORE_BACKUP
                else 'Operational configuration saved. Restart the runtime to attach.'
            )
            messages.success(self.request, pending_message)
        return redirect('/users/login/', permanent=False)


RESTORE_BACKUP_STEP_URL_NAMES = {
    'database': 'restore_backup_database',
    'crypto-storage': 'restore_backup_crypto_storage',
    'backend-config': 'restore_backup_backend_config',
    'backup-import': 'restore_backup_import',
    'summary': 'restore_backup_summary',
}
RESTORE_BACKUP_STEP_LABELS = {
    'database': 'Database',
    'crypto-storage': 'Crypto Backend',
    'backend-config': 'Backend Config',
    'backup-import': 'Backup Import',
    'summary': 'Inspect & Apply',
}


class RestoreBackupDatabaseView(ConnectExistingDatabaseView):
    """Restore step for staging the operational database."""

    attach_mode = OperationalAttachMode.RESTORE_BACKUP
    page_title = 'Restore from Backup'
    step_url_names = RESTORE_BACKUP_STEP_URL_NAMES
    step_labels = RESTORE_BACKUP_STEP_LABELS
    success_url = reverse_lazy('setup_wizard:restore_backup_crypto_storage')
    back_url = reverse_lazy('setup_wizard:index')


class RestoreBackupCryptoStorageView(ConnectExistingCryptoStorageView):
    """Restore step for selecting the backend kind."""

    attach_mode = OperationalAttachMode.RESTORE_BACKUP
    page_title = 'Restore from Backup'
    step_url_names = RESTORE_BACKUP_STEP_URL_NAMES
    step_labels = RESTORE_BACKUP_STEP_LABELS
    success_url = reverse_lazy('setup_wizard:restore_backup_backend_config')
    back_url = reverse_lazy('setup_wizard:restore_backup_database')


class RestoreBackupBackendConfigView(ConnectExistingBackendConfigView):
    """Restore step for backend-specific connection details."""

    attach_mode = OperationalAttachMode.RESTORE_BACKUP
    page_title = 'Restore from Backup'
    step_url_names = RESTORE_BACKUP_STEP_URL_NAMES
    step_labels = RESTORE_BACKUP_STEP_LABELS
    success_url = reverse_lazy('setup_wizard:restore_backup_import')
    back_url = reverse_lazy('setup_wizard:restore_backup_crypto_storage')


class RestoreBackupImportView(ConnectExistingWizardMixin[RestoreBackupImportForm]):
    """Restore step for selecting the backup archive."""

    form_class = RestoreBackupImportForm
    attach_mode = OperationalAttachMode.RESTORE_BACKUP
    page_title = 'Restore from Backup'
    step_url_names = RESTORE_BACKUP_STEP_URL_NAMES
    step_labels = RESTORE_BACKUP_STEP_LABELS
    success_url = reverse_lazy('setup_wizard:restore_backup_summary')
    step_name = 'backup-import'
    back_url = reverse_lazy('setup_wizard:restore_backup_backend_config')
    body_heading = 'Select Backup Archive'

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle staged backup archive removal before normal validation."""
        if is_clear_restore_backup_submission(request):
            config_model = SetupWizardConfigModel.get_singleton()
            cleanup_staged_restore_archive(config_model)
            config_model.restore_backup_archive_path = ''
            config_model.restore_backup_archive_original_name = ''
            config_model.restore_backup_import_submitted = False
            config_model.restore_backup_restored_at = None
            config_model.restore_backup_restore_error = ''
            config_model.save(update_fields=[
                'restore_backup_archive_path',
                'restore_backup_archive_original_name',
                'restore_backup_import_submitted',
                'restore_backup_restored_at',
                'restore_backup_restore_error',
            ])
            messages.success(request, 'The staged backup archive was removed for this wizard session.')
            return self._step_redirect('backup-import')
        return super().post(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind the backup import form to the bootstrap singleton state."""
        kwargs = FormView.get_form_kwargs(self)
        kwargs['config_model'] = SetupWizardConfigModel.get_singleton()
        return kwargs

    def form_valid(self, form: RestoreBackupImportForm) -> HttpResponse:
        """Stage the backup archive and restore it before target inspection."""
        config_model = SetupWizardConfigModel.get_singleton()
        uploaded_archive = form.cleaned_data.get('backup_archive')
        if uploaded_archive is not None:
            cleanup_staged_restore_archive(config_model)
            config_model.restore_backup_archive_path = stage_restore_backup_archive(uploaded_archive)
            config_model.restore_backup_archive_original_name = str(getattr(uploaded_archive, 'name', 'backup.dump'))
            config_model.restore_backup_restored_at = None
            config_model.restore_backup_restore_error = ''
            config_model.restore_backup_import_submitted = True
            config_model.save()

        try:
            restore_operational_database_from_backup(
                config_model,
                backup_password=form.cleaned_data.get('backup_archive_password') or '',
            )
        except DjangoValidationError as exception:
            logger.warning('Database restore from uploaded setup-wizard backup failed: %s', exception)
            config_model.restore_backup_restore_error = str(exception)
            config_model.restore_backup_restored_at = None
            config_model.restore_backup_import_submitted = True
            config_model.save(update_fields=[
                'restore_backup_restore_error',
                'restore_backup_restored_at',
                'restore_backup_import_submitted',
            ])
            form.add_error('backup_archive', exception)
            return self.render_to_response(self.get_context_data(form=form))

        config_model.restore_backup_restored_at = timezone.now()
        config_model.restore_backup_restore_error = ''
        config_model.restore_backup_import_submitted = True
        config_model.save(update_fields=[
            'restore_backup_restored_at',
            'restore_backup_restore_error',
            'restore_backup_import_submitted',
        ])
        messages.success(self.request, 'Backup restored into the configured PostgreSQL database.')
        return super().form_valid(form)


class RestoreBackupSummaryView(ConnectExistingSummaryView):
    """Restore summary step for inspection and explicit attach."""

    attach_mode = OperationalAttachMode.RESTORE_BACKUP
    page_title = 'Restore from Backup'
    step_url_names = RESTORE_BACKUP_STEP_URL_NAMES
    step_labels = RESTORE_BACKUP_STEP_LABELS
    back_url = reverse_lazy('setup_wizard:restore_backup_import')
    body_heading = 'Inspect and Restore'


class SetupWizardRestoreBackupView(LoginRequiredMixin, View):
    """Bootstrap entry for restoring a database backup, then attaching explicitly."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Start restore at the first lightweight wizard step."""
        _ = request, args, kwargs
        return redirect('setup_wizard:restore_backup_database')


class SetupWizardConnectExistingView(LoginRequiredMixin, View):
    """Bootstrap entry for connecting this container to an existing instance."""

    def get(self, _request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Start connect-existing at the first lightweight wizard step."""
        _ = args, kwargs
        return redirect('setup_wizard:connect_existing_database')
