"""Apply bootstrap-staged configuration to the operational Trustpoint database."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand, CommandParser
from django.db import DatabaseError, transaction
from django.db.models import ProtectedError

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11AuthSource,
    AppSecretPkcs11ConfigModel,
    AppSecretSoftwareConfigModel,
)
from appsecrets.service import clear_app_secret_cache, get_app_secret_service
from crypto.application.capabilities import BackendCapabilityService
from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    Pkcs11AuthSource,
    SoftwareKeyEncryptionSource,
)
from management.nginx_paths import NGINX_CERT_CHAIN_PATH, NGINX_CERT_PATH, NGINX_KEY_PATH
from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.pkcs11_local_dev import local_dev_pkcs11_handoff_available, local_dev_pkcs11_module_path
from setup_wizard.pkcs11_staging import cleanup_wizard_pkcs11_staged_path, existing_wizard_pkcs11_staged_file
from setup_wizard.tls_credential import clear_staged_tls_credential, load_staged_tls_credential

logger = logging.getLogger(__name__)

STATE_FILE_DIR = Path('/etc/trustpoint/wizard/')
UPDATE_TLS_NGINX = STATE_FILE_DIR / 'update_tls_nginx.sh'
INSTALL_PKCS11_ASSETS = STATE_FILE_DIR / 'install_pkcs11_assets.sh'
FINAL_WIZARD_PKCS11_MODULE_PATH = Path(settings.HSM_LIB_DIR) / 'uploaded-pkcs11-module.so'
FINAL_WIZARD_PKCS11_PIN_PATH = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
FINAL_WIZARD_PKCS11_CONFIG_PATH = Path(settings.HSM_CONFIG_DIR) / 'uploaded-pkcs11-provider.cfg'


class OperationalBootstrapApplier:
    """Apply the serialized bootstrap choices to the operational database."""

    def __init__(self, payload: dict[str, Any]) -> None:
        """Store the serialized bootstrap payload."""
        self.payload = payload
        self.fresh_install = payload['fresh_install']

    @staticmethod
    def execute_shell_script(script: Path, *args: str) -> None:
        """Execute a privileged wizard helper script."""
        script_path = Path(script).resolve()
        if not script_path.exists():
            err_msg = f'Script not found: {script_path}'
            raise FileNotFoundError(err_msg)
        if not script_path.is_file():
            err_msg = f'The script path {script_path} is not a valid file.'
            raise ValueError(err_msg)

        completed_process = subprocess.run(
            ['sudo', str(script_path), *list(args)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed_process.returncode != 0:
            error = subprocess.CalledProcessError(completed_process.returncode, str(script_path))
            error.stdout = completed_process.stdout
            error.stderr = completed_process.stderr
            raise error

    @staticmethod
    def _load_existing_backend_profile(backend_kind: BackendKind) -> CryptoProviderProfileModel | None:
        """Return an existing profile for the given backend kind when one already exists."""
        return CryptoProviderProfileModel.objects.filter(backend_kind=backend_kind).order_by('-active', 'id').first()

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
    def _activate_profile(cls, *, backend_kind: BackendKind, default_name: str) -> CryptoProviderProfileModel:
        """Activate or create the singleton profile for the chosen backend kind."""
        cls._ensure_backend_kind_matches_instance(backend_kind)
        existing_profile = cls._load_existing_backend_profile(backend_kind)
        if existing_profile is not None:
            CryptoProviderProfileModel.objects.filter(active=True).exclude(pk=existing_profile.pk).update(active=False)
            existing_profile.active = True
            existing_profile.save()
            return existing_profile

        CryptoProviderProfileModel.objects.filter(active=True).update(active=False)
        profile = CryptoProviderProfileModel(name=default_name, backend_kind=backend_kind, active=True)
        profile.save()
        return profile

    @classmethod
    def _configure_software_backend(cls) -> None:
        """Configure the software backend for the operational instance."""
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
        config.save()

    @staticmethod
    def _configure_software_app_secret_backend() -> None:
        """Configure the software app-secret backend."""
        backend = AppSecretBackendModel.get_singleton()
        backend.backend_kind = AppSecretBackendKind.SOFTWARE
        backend.save()

        AppSecretPkcs11ConfigModel.objects.filter(backend=backend).delete()
        software_config, _ = AppSecretSoftwareConfigModel.objects.get_or_create(backend=backend)
        software_config.full_clean()
        software_config.save()

        clear_app_secret_cache()
        get_app_secret_service().ensure_backend_ready()

    @staticmethod
    def _configure_pkcs11_app_secret_backend() -> None:
        """Configure the PKCS#11-backed app-secret subsystem from the active crypto profile."""
        crypto_profile = CryptoProviderProfileModel.objects.get(active=True, backend_kind=BackendKind.PKCS11)
        crypto_config = crypto_profile.pkcs11_config

        backend = AppSecretBackendModel.get_singleton()
        backend.backend_kind = AppSecretBackendKind.PKCS11
        backend.save()

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
        secret_config.save()

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

    def _install_staged_pkcs11_assets(self) -> tuple[str, str, str]:
        """Install staged PKCS#11 assets and return final module, PIN-file, and provider-config paths."""
        staged_module = existing_wizard_pkcs11_staged_file(self.fresh_install['pkcs11_module_path'])
        staged_pin = existing_wizard_pkcs11_staged_file(self.fresh_install['pkcs11_auth_source_ref'])
        staged_config = existing_wizard_pkcs11_staged_file(self.fresh_install.get('pkcs11_config_path'))
        configured_module_value = (self.fresh_install['pkcs11_module_path'] or '').strip()
        configured_config_value = (self.fresh_install.get('pkcs11_config_path') or '').strip()
        configured_module_path = Path(configured_module_value) if configured_module_value else Path()
        configured_module_exists = bool(configured_module_value and configured_module_path.is_file())

        local_dev_module = local_dev_pkcs11_module_path()
        if (not configured_module_value or not configured_module_exists) and local_dev_pkcs11_handoff_available():
            configured_module_value = str(local_dev_module)
            configured_module_path = local_dev_module
            configured_module_exists = configured_module_path.is_file()

        if staged_module is None and staged_pin is None and staged_config is None:
            return (
                configured_module_value,
                (self.fresh_install['pkcs11_auth_source_ref'] or '').strip(),
                configured_config_value,
            )

        uses_builtin_local_proxy = (
            local_dev_pkcs11_handoff_available()
            and local_dev_module.is_file()
            and configured_module_path == local_dev_module
            and configured_module_exists
        )

        if uses_builtin_local_proxy and staged_module is not None:
            cleanup_wizard_pkcs11_staged_path(staged_module)
            staged_module = None

        uses_existing_installed_module = staged_module is None and configured_module_exists
        uses_existing_installed_pin = staged_pin is None and FINAL_WIZARD_PKCS11_PIN_PATH.exists()

        if staged_pin is None and not uses_existing_installed_pin:
            err_msg = 'The staged PKCS#11 setup files are incomplete. Enter the PIN again.'
            raise DjangoValidationError(err_msg)
        if staged_module is None and not uses_builtin_local_proxy and not uses_existing_installed_module:
            err_msg = (
                'The staged PKCS#11 setup files are incomplete. Upload the library and enter the PIN again.'
            )
            raise DjangoValidationError(err_msg)
        if staged_config is not None and staged_pin is None and staged_module is None:
            err_msg = (
                'The staged PKCS#11 setup files are incomplete. Upload the library and enter the PIN again.'
            )
            raise DjangoValidationError(err_msg)

        try:
            if staged_module is None and staged_pin is None:
                pass
            elif staged_pin is None:
                if staged_config is not None:
                    self.execute_shell_script(
                        INSTALL_PKCS11_ASSETS,
                        '--use-installed-pin',
                        str(staged_module),
                        str(staged_config),
                    )
                else:
                    self.execute_shell_script(INSTALL_PKCS11_ASSETS, '--use-installed-pin', str(staged_module))
            elif uses_builtin_local_proxy:
                self.execute_shell_script(INSTALL_PKCS11_ASSETS, str(staged_pin))
            elif staged_config is not None:
                self.execute_shell_script(
                    INSTALL_PKCS11_ASSETS, str(staged_module), str(staged_pin), str(staged_config)
                )
            else:
                self.execute_shell_script(INSTALL_PKCS11_ASSETS, str(staged_module), str(staged_pin))
        except subprocess.CalledProcessError as exc:
            script_error_detail = (exc.stderr or exc.stdout or '').strip()
            err_msg = self._map_pkcs11_install_exit_code_to_message(exc.returncode)
            if uses_builtin_local_proxy and exc.returncode == 1:
                err_msg = (
                    'The running Trustpoint container still appears to use the older PKCS#11 install helper. '
                    'Rebuild and recreate the Trustpoint container, then try the setup wizard again.'
                )
            if script_error_detail:
                logger.exception('PKCS#11 install script failed: %s', script_error_detail)
            raise DjangoValidationError(err_msg) from exc

        if staged_pin is not None:
            cleanup_wizard_pkcs11_staged_path(staged_pin)
        if staged_module is not None:
            cleanup_wizard_pkcs11_staged_path(staged_module)
            configured_module_value = str(FINAL_WIZARD_PKCS11_MODULE_PATH)
        if staged_config is not None:
            cleanup_wizard_pkcs11_staged_path(staged_config)
            configured_config_value = str(FINAL_WIZARD_PKCS11_CONFIG_PATH)

        return configured_module_value, str(FINAL_WIZARD_PKCS11_PIN_PATH), configured_config_value

    def _configure_pkcs11_backend(self) -> None:
        """Configure the PKCS#11 backend from bootstrap-staged values."""
        module_path_value, auth_source_ref, config_path_value = self._install_staged_pkcs11_assets()
        module_path = Path(module_path_value or str(FINAL_WIZARD_PKCS11_MODULE_PATH))
        fallback_module_path = Path(settings.HSM_DEFAULT_PKCS11_MODULE_PATH)
        if not module_path.exists() and fallback_module_path.exists():
            module_path = fallback_module_path

        slot_id = self.fresh_install.get('pkcs11_slot_id')
        token_label = (self.fresh_install['pkcs11_token_label'] or '').strip() or None
        if token_label is None and slot_id is None:
            token_label = getattr(settings, 'HSM_DEFAULT_TOKEN_LABEL', '').strip() or None
        fallback_pin_path = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
        if auth_source_ref and not Path(auth_source_ref).exists() and fallback_pin_path.exists():
            auth_source_ref = str(fallback_pin_path)

        if not module_path.exists():
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

        config_env_var = (self.fresh_install.get('pkcs11_config_env_var') or '').strip()
        config_path_value = (config_path_value or '').strip()
        if config_path_value and not config_env_var:
            err_msg = (
                'A PKCS#11 provider config file is configured, but no provider config environment variable is set.'
            )
            raise DjangoValidationError(err_msg)
        if config_env_var and config_path_value:
            config_path = Path(config_path_value)
            if config_path.exists():
                os.environ[config_env_var] = str(config_path)

        profile = self._activate_profile(
            backend_kind=BackendKind.PKCS11,
            default_name='trustpoint-pkcs11-backend',
        )
        defaults = {
            'module_path': str(module_path),
            'token_label': token_label,
            'token_serial': self.fresh_install.get('pkcs11_token_serial') or None,
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

    def _configure_instance_crypto_backend(self) -> None:
        """Configure the operational crypto backend."""
        crypto_storage = SetupWizardConfigModel.CryptoStorageType(self.fresh_install['crypto_storage'])
        if crypto_storage == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage:
            self._configure_software_backend()
            return
        if crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            self._configure_pkcs11_backend()
            return
        err_msg = f'Unsupported crypto storage selection {crypto_storage!r}.'
        raise DjangoValidationError(err_msg)

    @staticmethod
    def _probe_and_record_crypto_capabilities() -> None:
        """Persist the operational backend capability snapshot after explicit setup apply."""
        report = BackendCapabilityService().refresh_and_record_active_report()
        if not report.available:
            diagnostics = '; '.join(report.diagnostics) or 'no usable capabilities reported'
            err_msg = f'The configured crypto backend is not usable: {diagnostics}'
            raise DjangoValidationError(err_msg)

    def _configure_app_secret_backend(self) -> None:
        """Configure the operational app-secret backend."""
        crypto_storage = SetupWizardConfigModel.CryptoStorageType(self.fresh_install['crypto_storage'])
        if crypto_storage == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage:
            self._configure_software_app_secret_backend()
            return
        if crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            if bool(self.fresh_install.get('pkcs11_enforce_app_secret_protection')):
                self._configure_pkcs11_app_secret_backend()
                return
            self._configure_software_app_secret_backend()
            return
        err_msg = f'Unsupported crypto storage selection {crypto_storage!r}.'
        raise DjangoValidationError(err_msg)

    @staticmethod
    def _write_pem_files(credential_model: CredentialModel) -> None:
        """Write TLS private key, certificate, and optional chain files to disk."""
        private_key_pem = credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
        certificate_pem = credential_model.get_certificate_serializer().as_pem().decode()
        trust_store_pem = credential_model.get_certificate_chain_serializer().as_pem().decode()

        NGINX_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        NGINX_KEY_PATH.write_text(private_key_pem)
        NGINX_CERT_PATH.write_text(certificate_pem)

        if trust_store_pem.strip():
            NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)
        elif NGINX_CERT_CHAIN_PATH.exists():
            NGINX_CERT_CHAIN_PATH.unlink()

    def _apply_staged_tls_credential(self) -> None:
        """Promote the staged TLS credential to active operational state."""
        staged_tls_serializer = load_staged_tls_credential()
        if staged_tls_serializer is None:
            err_msg = 'No staged TLS Server Credential found.'
            raise DjangoValidationError(err_msg)

        staged_tls_credential = CredentialModel.save_credential_serializer(
            credential_serializer=staged_tls_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
        )
        active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
        active_tls.credential = staged_tls_credential
        active_tls.save()

        self._write_pem_files(staged_tls_credential)
        self.execute_shell_script(UPDATE_TLS_NGINX, 'no_hsm')
        sha256_fingerprint = staged_tls_credential.get_certificate().fingerprint(hashes.SHA256())
        formatted_fingerprint = ':'.join(f'{byte:02X}' for byte in sha256_fingerprint)
        logger.info('TLS SHA256 fingerprint: %s', formatted_fingerprint)
        clear_staged_tls_credential()

    def _create_operational_admin(self) -> None:
        """Create or update the first operational administrator."""
        admin_payload = self.payload['admin']
        username = (admin_payload['username'] or '').strip()
        password_hash = (admin_payload['password_hash'] or '').strip()
        if not username:
            err_msg = 'The operational admin username is missing.'
            raise DjangoValidationError(err_msg)
        if not password_hash:
            err_msg = 'The operational admin password hash is missing.'
            raise DjangoValidationError(err_msg)

        user_model = get_user_model()
        user, _ = user_model.objects.get_or_create(username=username)
        user.email = admin_payload.get('email') or ''
        user.password = password_hash
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save()

    def apply(self) -> None:
        """Apply the full bootstrap payload to the operational runtime."""
        self._configure_instance_crypto_backend()
        self._probe_and_record_crypto_capabilities()
        self._configure_app_secret_backend()
        call_command('create_default_cert_profiles')
        call_command('create_management_ca')
        if self.fresh_install['inject_demo_data']:
            call_command('add_domains_and_devices')
        call_command('execute_all_notifications')
        self._apply_staged_tls_credential()
        self._create_operational_admin()


class Command(BaseCommand):
    """Apply bootstrap-staged configuration to the operational database."""

    help = 'Apply a bootstrap setup payload to the operational Trustpoint runtime.'

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command arguments."""
        parser.add_argument('--config', required=True, help='Path to the bootstrap apply payload JSON file.')

    def handle(self, *args: object, **options: object) -> None:
        """Entrypoint for the command."""
        del args
        if getattr(settings, 'TRUSTPOINT_IS_BOOTSTRAP', False):
            err_msg = 'apply_bootstrap_config must run with TRUSTPOINT_PHASE=operational.'
            raise CommandError(err_msg)

        config_path = Path(str(options['config']))
        try:
            payload = json.loads(config_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            err_msg = f'Could not read bootstrap apply payload: {exc}'
            raise CommandError(err_msg) from exc

        try:
            with transaction.atomic():
                OperationalBootstrapApplier(payload).apply()
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or '').strip()
            err_msg = detail or f'Wizard helper script failed with exit code {exc.returncode}.'
            raise CommandError(err_msg) from exc
        except DjangoValidationError as exc:
            err_msg = '; '.join(exc.messages)
            raise CommandError(err_msg) from exc
        except (
            DatabaseError,
            FileNotFoundError,
            OSError,
            ProtectedError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            err_msg = str(exc) or 'Error applying bootstrap configuration.'
            raise CommandError(err_msg) from exc

        self.stdout.write(self.style.SUCCESS('Bootstrap configuration applied to operational runtime.'))
