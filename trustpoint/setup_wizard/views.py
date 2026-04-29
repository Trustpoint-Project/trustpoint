"""Views for the users application."""

from __future__ import annotations

import enum
import ipaddress
import logging
import subprocess
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

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
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy
from django.views.generic import FormView, TemplateView, View

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11AuthSource,
    AppSecretPkcs11ConfigModel,
    AppSecretSoftwareConfigModel,
)
from appsecrets.service import clear_app_secret_cache, get_app_secret_service
from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector
from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    Pkcs11AuthSource,
    SoftwareKeyEncryptionSource,
)
from management.models import PKCS11Token
from management.nginx_paths import (
    NGINX_CERT_CHAIN_PATH,
    NGINX_CERT_PATH,
    NGINX_KEY_PATH,
)
from pki.models import CaModel, CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard import SetupWizardState
from setup_wizard.operational_handoff import (
    refresh_pending_operational_env,
    run_operational_handoff,
    run_operational_runtime_switch,
)
from setup_wizard.pkcs11_local_dev import local_dev_pkcs11_handoff_available, local_dev_pkcs11_module_path
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
    BackupPasswordForm,
    BackupRestoreForm,
    FreshInstallAdminUserModelForm,
    FreshInstallBackendConfigModelForm,
    FreshInstallCryptoStorageModelForm,
    FreshInstallDatabaseModelForm,
    FreshInstallDemoDataModelForm,
    FreshInstallModelBaseForm,
    FreshInstallSummaryModelForm,
    FreshInstallTlsConfigForm,
    PasswordAutoRestoreForm,
)
from .models import SetupWizardCompletedModel, SetupWizardConfigModel

if TYPE_CHECKING:
    from django.utils.functional import Promise
    from trustpoint_core.serializer import CertificateSerializer

logger = logging.getLogger(__name__)


STATE_FILE_DIR = Path('/etc/trustpoint/wizard/')
UPDATE_TLS_NGINX = STATE_FILE_DIR / Path('update_tls_nginx.sh')
INSTALL_PKCS11_ASSETS = STATE_FILE_DIR / Path('install_pkcs11_assets.sh')
FINAL_WIZARD_PKCS11_MODULE_PATH = Path(settings.HSM_LIB_DIR) / 'uploaded-pkcs11-module.so'
FINAL_WIZARD_PKCS11_PIN_PATH = Path(settings.HSM_DEFAULT_USER_PIN_FILE)


def _path_exists(path: Path) -> bool:
    """Return whether a setup-wizard path exists without leaking permission errors."""
    try:
        return path.exists()
    except OSError:
        return False


# TODO(AlexHx8472): no transitions anymore  # noqa: FIX002
SCRIPT_WIZARD_BACKUP_PASSWORD = STATE_FILE_DIR / Path('transition/wizard_backup_password.sh')
SCRIPT_WIZARD_AUTO_RESTORE_SUCCESS = STATE_FILE_DIR / Path('transition/wizard_auto_restore_success.sh')


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
        if config_model.fresh_install_current_step < self.step_state:
            config_model.fresh_install_current_step = self.step_state
            config_model.save()
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
        """Drop staged PKCS#11 wizard assets when switching away from the PKCS#11 backend."""
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_module_path)
        cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_auth_source_ref)
        form.instance.fresh_install_pkcs11_module_path = ''
        form.instance.fresh_install_pkcs11_token_label = ''
        form.instance.fresh_install_pkcs11_token_serial = ''
        form.instance.fresh_install_pkcs11_slot_id = None
        form.instance.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        form.instance.fresh_install_pkcs11_auth_source_ref = ''

    def form_valid(self, form: FreshInstallCryptoStorageModelForm) -> HttpResponse:
        """Persist the chosen backend and clear stale PKCS#11 wizard staging when not needed."""
        if form.cleaned_data['crypto_storage'] != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            self._reset_staged_pkcs11_backend(form)
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
        return request.POST.get('wizard_action') == 'test_connection'

    @staticmethod
    def _is_clear_module_submission(request: HttpRequest) -> bool:
        """Return whether the current POST requests staged library removal."""
        return request.POST.get('wizard_action') == 'clear_module'

    @staticmethod
    def _is_clear_pin_submission(request: HttpRequest) -> bool:
        """Return whether the current POST requests staged PIN removal."""
        return request.POST.get('wizard_action') == 'clear_pin'

    @staticmethod
    def _clear_staged_pkcs11_module(config_model: SetupWizardConfigModel) -> None:
        """Remove the currently staged PKCS#11 library for this wizard session."""
        cleanup_wizard_pkcs11_staged_path(config_model.fresh_install_pkcs11_module_path)
        config_model.fresh_install_pkcs11_module_path = ''
        config_model.save(update_fields=['fresh_install_pkcs11_module_path'])

    @staticmethod
    def _clear_staged_pkcs11_pin(config_model: SetupWizardConfigModel) -> None:
        """Remove the currently staged PKCS#11 user PIN for this wizard session."""
        cleanup_wizard_pkcs11_staged_path(config_model.fresh_install_pkcs11_auth_source_ref)
        config_model.fresh_install_pkcs11_auth_source_ref = ''
        config_model.save(update_fields=['fresh_install_pkcs11_auth_source_ref'])

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle staged PKCS#11 asset removal before running normal form validation."""
        config_model = SetupWizardConfigModel.get_singleton()
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            if self._is_clear_module_submission(request):
                self._clear_staged_pkcs11_module(config_model)
                messages.success(request, 'The staged PKCS#11 library was removed for this wizard session.')
                return redirect('setup_wizard:fresh_install_backend_config')
            if self._is_clear_pin_submission(request):
                self._clear_staged_pkcs11_pin(config_model)
                messages.success(request, 'The staged PKCS#11 user PIN was removed for this wizard session.')
                return redirect('setup_wizard:fresh_install_backend_config')
        return super().post(request, *args, **kwargs)

    @staticmethod
    def _stage_uploaded_pkcs11_module(uploaded_module: Any) -> str:
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

    @staticmethod
    def _stage_pkcs11_user_pin(user_pin: str) -> str:
        """Write the entered PKCS#11 user PIN to private one-time wizard staging."""
        staging_root = wizard_pkcs11_staging_root()
        staging_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        staging_root.chmod(0o700)
        staged_path = staging_root / f'pkcs11-user-pin-{uuid.uuid4().hex}.txt'
        staged_path.write_text(user_pin, encoding='utf-8')
        staged_path.chmod(0o600)
        return str(staged_path)

    def _persist_pkcs11_backend_config(self, form: FreshInstallBackendConfigModelForm) -> None:
        """Persist staged PKCS#11 wizard inputs without advancing the wizard."""
        if form.instance.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            return

        update_fields = [
            'fresh_install_pkcs11_token_label',
            'fresh_install_pkcs11_token_serial',
            'fresh_install_pkcs11_slot_id',
            'fresh_install_pkcs11_auth_source',
        ]

        form.instance.fresh_install_pkcs11_token_label = form.cleaned_data['fresh_install_pkcs11_token_label']

        uploaded_module = form.cleaned_data.get('pkcs11_module_upload')
        current_staged_module = existing_wizard_pkcs11_staged_file(form.instance.fresh_install_pkcs11_module_path)
        current_module_path = (form.instance.fresh_install_pkcs11_module_path or '').strip()
        current_module_exists = bool(current_module_path and Path(current_module_path).is_file())
        if uploaded_module is not None:
            cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_module_path)
            form.instance.fresh_install_pkcs11_module_path = self._stage_uploaded_pkcs11_module(uploaded_module)
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
            form.instance.fresh_install_pkcs11_auth_source_ref = self._stage_pkcs11_user_pin(user_pin)
            update_fields.append('fresh_install_pkcs11_auth_source_ref')

        form.instance.fresh_install_pkcs11_token_serial = ''
        form.instance.fresh_install_pkcs11_slot_id = None
        form.instance.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        form.instance.save(update_fields=update_fields)
        form._apply_pkcs11_defaults()

    @staticmethod
    def _build_pkcs11_test_profile(form: FreshInstallBackendConfigModelForm) -> Pkcs11ProviderProfile:
        """Build a temporary PKCS#11 provider profile from staged wizard inputs."""
        module_path = (form.instance.fresh_install_pkcs11_module_path or '').strip()
        pin_file = (form.instance.fresh_install_pkcs11_auth_source_ref or '').strip()
        token_label = (form.instance.fresh_install_pkcs11_token_label or '').strip()

        return Pkcs11ProviderProfile(
            name='setup-wizard-pkcs11-test',
            module_path=module_path,
            token=Pkcs11TokenSelector(token_label=token_label),
            user_pin_file=pin_file,
            max_sessions=2,
            borrow_timeout_seconds=5.0,
            rw_sessions=True,
        )

    def _test_pkcs11_connection(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Probe the staged PKCS#11 configuration and keep the user on this step."""
        try:
            backend = Pkcs11Backend(profile=self._build_pkcs11_test_profile(form))
            backend.verify_authentication()
            capabilities = backend.probe_capabilities()
        except Exception as exception:
            self.logger.exception('PKCS#11 setup-wizard connection test failed.')
            error_detail = str(exception).strip() or type(exception).__name__
            form.add_error(None, f'Could not connect to the configured PKCS#11 backend: {error_detail}')
            return self.render_to_response(self.get_context_data(form=form))
        finally:
            if 'backend' in locals():
                backend.close()

        token_label = capabilities.token.label or form.instance.fresh_install_pkcs11_token_label
        token_serial = capabilities.token.serial or 'unknown serial'
        messages.success(
            self.request,
            f'PKCS#11 connection successful. Reached token {token_label!r} ({token_serial}) in slot '
            f'{capabilities.token.slot_id}.',
        )
        return redirect('setup_wizard:fresh_install_backend_config')

    def form_valid(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Persist wizard backend configuration using one-time PKCS#11 staging files."""
        if form.instance.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            self._persist_pkcs11_backend_config(form)
            if self._is_test_connection_submission(self.request):
                return self._test_pkcs11_connection(form)

        return super().form_valid(form)

    def form_invalid(self, form: FreshInstallBackendConfigModelForm) -> HttpResponse:
        """Persist already supplied PKCS#11 assets for this wizard session even when other validation fails."""
        if form.instance.crypto_storage == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            update_fields: list[str] = []

            uploaded_module = form.files.get('pkcs11_module_upload')
            if uploaded_module is not None and 'pkcs11_module_upload' not in form.errors:
                cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_module_path)
                form.instance.fresh_install_pkcs11_module_path = self._stage_uploaded_pkcs11_module(uploaded_module)
                form.staged_pkcs11_module_name = Path(form.instance.fresh_install_pkcs11_module_path).name
                update_fields.append('fresh_install_pkcs11_module_path')

            user_pin = form.data.get('pkcs11_user_pin', '')
            if user_pin and 'pkcs11_user_pin' not in form.errors:
                cleanup_wizard_pkcs11_staged_path(form.instance.fresh_install_pkcs11_auth_source_ref)
                form.instance.fresh_install_pkcs11_auth_source_ref = self._stage_pkcs11_user_pin(str(user_pin))
                form.instance.fresh_install_pkcs11_auth_source = (
                    SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
                )
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

            if update_fields:
                form.instance.save(update_fields=update_fields)

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

    def _apply_staged_tls_credential(self, config_model: SetupWizardConfigModel) -> None:
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
            existing_profile.save()
            return existing_profile

        CryptoProviderProfileModel.objects.filter(active=True).update(active=False)
        profile = CryptoProviderProfileModel(
            name=default_name,
            backend_kind=backend_kind,
            active=True,
        )
        profile.save()
        return profile

    @classmethod
    def _configure_software_backend(cls) -> None:
        """Configure the dev/testing software backend for the instance."""
        if not (getattr(settings, 'DEVELOPMENT_ENV', False) or getattr(settings, 'DOCKER_CONTAINER', False)):
            err_msg = (
                'The dev/testing crypto backend can only be configured for development or demo-style container setups.'
            )
            raise DjangoValidationError(err_msg)

        profile = cls._activate_profile(
            backend_kind=BackendKind.SOFTWARE,
            default_name='trustpoint-software-backend',
        )
        defaults = {
            'encryption_source': SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
            'encryption_source_ref': None,
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
        """Configure the development-only software app-secret backend."""
        if not (getattr(settings, 'DEVELOPMENT_ENV', False) or getattr(settings, 'DOCKER_CONTAINER', False)):
            err_msg = 'The software app-secret backend is only allowed for development or demo-style container setups.'
            raise DjangoValidationError(err_msg)

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
        }
        return error_messages.get(return_code, 'An unknown error occurred while installing PKCS#11 assets.')

    @classmethod
    def _install_staged_pkcs11_assets(cls, config_model: SetupWizardConfigModel) -> None:
        """Install staged PKCS#11 assets into the protected HSM area through the wizard helper script."""
        staged_module = existing_wizard_pkcs11_staged_file(config_model.fresh_install_pkcs11_module_path)
        staged_pin = existing_wizard_pkcs11_staged_file(config_model.fresh_install_pkcs11_auth_source_ref)
        local_dev_module = local_dev_pkcs11_module_path()
        configured_module_value = (config_model.fresh_install_pkcs11_module_path or '').strip()
        configured_module_exists = bool(configured_module_value and Path(configured_module_value).is_file())
        if (not configured_module_value or not configured_module_exists) and local_dev_pkcs11_handoff_available():
            config_model.fresh_install_pkcs11_module_path = str(local_dev_module)
        configured_module_path = Path((config_model.fresh_install_pkcs11_module_path or '').strip())

        if staged_module is None and staged_pin is None:
            return

        uses_builtin_local_proxy = (
            staged_pin is not None
            and local_dev_pkcs11_handoff_available()
            and local_dev_module.is_file()
            and configured_module_path == local_dev_module
            and configured_module_path.is_file()
        )

        if uses_builtin_local_proxy and staged_module is not None:
            cleanup_wizard_pkcs11_staged_path(staged_module)
            staged_module = None

        if staged_pin is None:
            err_msg = 'The staged PKCS#11 setup files are incomplete. Enter the PIN again.'
            raise DjangoValidationError(err_msg)
        if staged_module is None and not uses_builtin_local_proxy:
            err_msg = 'The staged PKCS#11 setup files are incomplete. Upload the library and enter the PIN again.'
            raise DjangoValidationError(err_msg)

        try:
            if uses_builtin_local_proxy:
                execute_shell_script(INSTALL_PKCS11_ASSETS, str(staged_pin))
            else:
                execute_shell_script(INSTALL_PKCS11_ASSETS, str(staged_module), str(staged_pin))
        except subprocess.CalledProcessError as exc:
            script_error_detail = (exc.stderr or exc.stdout or '').strip()
            err_msg = cls._map_pkcs11_install_exit_code_to_message(exc.returncode)
            if uses_builtin_local_proxy and exc.returncode == 1:
                err_msg = (
                    'The running Trustpoint container still appears to use the older PKCS#11 install helper. '
                    'Rebuild and recreate the Trustpoint container, then try the setup wizard again.'
                )
            if script_error_detail:
                logger.exception('PKCS#11 install script failed: %s', script_error_detail)
            raise DjangoValidationError(err_msg) from exc

        cleanup_wizard_pkcs11_staged_path(staged_pin)
        if staged_module is not None:
            cleanup_wizard_pkcs11_staged_path(staged_module)
            config_model.fresh_install_pkcs11_module_path = str(FINAL_WIZARD_PKCS11_MODULE_PATH)
        config_model.fresh_install_pkcs11_auth_source = SetupWizardConfigModel.FreshInstallPkcs11AuthSource.FILE
        config_model.fresh_install_pkcs11_auth_source_ref = str(FINAL_WIZARD_PKCS11_PIN_PATH)
        config_model.save(
            update_fields=[
                'fresh_install_pkcs11_module_path',
                'fresh_install_pkcs11_auth_source',
                'fresh_install_pkcs11_auth_source_ref',
            ]
        )

    @classmethod
    def _configure_pkcs11_backend(cls, config_model: SetupWizardConfigModel) -> None:
        """Configure the PKCS#11 backend for the instance from wizard-staged values."""
        cls._install_staged_pkcs11_assets(config_model)

        module_path = Path(
            (config_model.fresh_install_pkcs11_module_path or '').strip() or str(FINAL_WIZARD_PKCS11_MODULE_PATH)
        )
        fallback_module_path = Path(settings.HSM_DEFAULT_PKCS11_MODULE_PATH)
        if not _path_exists(module_path) and _path_exists(fallback_module_path):
            module_path = fallback_module_path

        token_label = (config_model.fresh_install_pkcs11_token_label or '').strip() or getattr(
            settings, 'HSM_DEFAULT_TOKEN_LABEL', ''
        )
        auth_source_ref = (
            (config_model.fresh_install_pkcs11_auth_source_ref or '').strip() or str(FINAL_WIZARD_PKCS11_PIN_PATH)
        )
        fallback_pin_path = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
        if auth_source_ref and not _path_exists(Path(auth_source_ref)) and _path_exists(fallback_pin_path):
            auth_source_ref = str(fallback_pin_path)

        if not _path_exists(module_path):
            err_msg = f'The PKCS#11 module path does not exist: {module_path}'
            raise DjangoValidationError(err_msg)
        if not token_label:
            err_msg = 'No PKCS#11 token label is configured for the setup wizard.'
            raise DjangoValidationError(err_msg)
        if not auth_source_ref:
            err_msg = 'No PKCS#11 user PIN source reference is configured for the setup wizard.'
            raise DjangoValidationError(err_msg)
        if not Path(auth_source_ref).exists():
            err_msg = f'The PKCS#11 user PIN file does not exist: {auth_source_ref}'
            raise DjangoValidationError(err_msg)

        profile = cls._activate_profile(
            backend_kind=BackendKind.PKCS11,
            default_name='trustpoint-pkcs11-backend',
        )
        defaults = {
            'module_path': str(module_path),
            'token_label': token_label,
            'token_serial': None,
            'slot_id': None,
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
            cls._configure_pkcs11_app_secret_backend()
            return
        if config_model.crypto_storage == SetupWizardConfigModel.CryptoStorageType.RestBackend:
            err_msg = 'The REST backend does not yet support application-secret encryption.'
            raise DjangoValidationError(err_msg)

        err_msg = f'Unsupported crypto storage selection {config_model.crypto_storage!r}.'
        raise DjangoValidationError(err_msg)

    def form_valid(self, form: FreshInstallSummaryModelForm) -> HttpResponse:
        """Apply the first summary step actions before continuing the setup flow."""
        if getattr(settings, 'TRUSTPOINT_IS_BOOTSTRAP', False):
            try:
                config_model = SetupWizardConfigModel.get_singleton()
                result = None
                if config_model.operational_config_applied:
                    result = refresh_pending_operational_env(config_model)
                    switch_result = run_operational_runtime_switch(result.pending_env_file)
                else:
                    result = run_operational_handoff(config_model)
                    config_model.mark_step_submitted(self.step_state)
                    config_model.operational_config_applied = True
                    config_model.save(update_fields=['fresh_install_summary_submitted', 'operational_config_applied'])
                    switch_result = run_operational_runtime_switch(result.pending_env_file)
            except DjangoValidationError as exception:
                for error_message in exception.messages:
                    form.add_error(None, error_message)
                self.logger.exception('Error applying bootstrap configuration to operational runtime.')
                return self.form_invalid(form)

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

        try:
            with transaction.atomic():
                config_model = SetupWizardConfigModel.get_singleton()
                self._configure_instance_crypto_backend(config_model)
                self._configure_app_secret_backend(config_model)
                call_command('create_default_cert_profiles')
                if config_model.inject_demo_data:
                    call_command('add_domains_and_devices')
                call_command('execute_all_notifications')
                self._apply_staged_tls_credential(config_model)
                SetupWizardCompletedModel.mark_setup_complete_once()
                return super().form_valid(form)
        except subprocess.CalledProcessError as exception:
            error_message = self._map_tls_apply_exit_code_to_message(exception.returncode)
            form.add_error(None, f'Error applying TLS Server Credential: {error_message}')
            self.logger.exception('Error applying fresh-install TLS server credential.')
            return self.form_invalid(form)
        except DjangoValidationError as exception:
            for error_message in exception.messages:
                form.add_error(None, error_message)
            self.logger.exception('Error applying fresh-install summary configuration.')
            return self.form_invalid(form)
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
            error_message = str(exception) or 'Error applying fresh-install summary configuration.'
            form.add_error(None, error_message)
            self.logger.exception('Error applying fresh-install summary configuration.')
            return self.form_invalid(form)


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


# Backup Stuff ---------------------------------------------------------------------------------------------------------


class SetupWizardRestoreBackupView(TemplateView):
    """View for the restore option during initialization.

    Attributes:
        http_method_names (ClassVar[list[str]]): List of HTTP methods allowed for this view.
        template_name (str): Path to the template used for rendering the initial page.
    """

    http_method_names = ('get',)
    template_name = 'setup_wizard/restore_backup.html'


class SetupWizardBackupPasswordView(LoggerMixin, FormView[BackupPasswordForm]):
    """View for setting up backup password for PKCS#11 token during the setup wizard.

    This view allows users to set a backup password that can be used to recover
    the DEK (Data Encryption Key) in case the HSM becomes unavailable. The password
    is used to derive a BEK (Backup Encryption Key) using Argon2.
    """

    http_method_names = ('get', 'post')
    template_name = 'setup_wizard/backup_password.html'
    success_url = reverse_lazy('setup_wizard:demo_data')
    form_class = BackupPasswordForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_BACKUP_PASSWORD:
            self.logger.warning(
                "Unexpected wizard state '%s', expected '%s'. Redirecting to appropriate state.",
                wizard_state,
                SetupWizardState.WIZARD_BACKUP_PASSWORD,
            )

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add password requirements to the context."""
        context = super().get_context_data(**kwargs)
        context['password_requirements'] = [
            gettext_lazy('Your password can’t be too similar to your other personal information.'),  # noqa: RUF001
            gettext_lazy('Your password must contain at least 8 characters.'),
            gettext_lazy('Your password can’t be a commonly used password.'),  # noqa: RUF001
            gettext_lazy('Your password can’t be entirely numeric.'),  # noqa: RUF001
        ]
        return context

    def form_valid(
        self,
        form: BackupPasswordForm,
    ) -> HttpResponse:
        """Handle valid form submission."""
        password = form.cleaned_data.get('password')

        try:
            token = PKCS11Token.objects.first()
            if not token:
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    'No PKCS#11 token found. This should not happen in the backup password step.',
                )
                self.logger.error('No PKCS11Token found in backup password step')
                return redirect('setup_wizard:demo_data', permanent=False)

            if not isinstance(password, str):
                messages.add_message(self.request, messages.ERROR, 'Invalid password provided.')
                self.logger.error('Invalid password type provided in backup password step')
                return self.form_invalid(form)

            token.set_backup_password(password)
            execute_shell_script(SCRIPT_WIZARD_BACKUP_PASSWORD)

            messages.add_message(self.request, messages.SUCCESS, 'Backup password set successfully.')
            self.logger.info('Backup password set for token: %s', token.label)
            return super().form_valid(form)

        except subprocess.CalledProcessError as exc:
            err_msg = f'Backup password script failed: {self._map_exit_code_to_message(exc.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:backup_password', permanent=False)
        except FileNotFoundError:
            err_msg = 'Backup password script not found: '
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:backup_password', permanent=False)
        except PKCS11Token.DoesNotExist as exc:
            err_msg = str(exc)
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:backup_password', permanent=False)
        except ValueError as exc:
            err_msg = f'Invalid input: {exc!s}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return self.form_invalid(form)
        except RuntimeError as exc:
            err_msg = f'Failed to set backup password: {exc!s}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return self.form_invalid(form)
        except Exception as exc:
            # General exception handling with specific messages
            err_msg = f'An unexpected error occurred: {exc!s}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return self.form_invalid(form)

    def form_invalid(self, form: BackupPasswordForm) -> HttpResponse:
        """Handle invalid form submission."""
        messages.add_message(self.request, messages.ERROR, 'Please correct the errors below and try again.')
        return super().form_invalid(form)

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Invalid arguments provided to backup password script.',
            2: 'Trustpoint is not in the WIZARD_BACKUP_PASSWORD state.',
            3: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            4: 'Failed to remove the WIZARD_BACKUP_PASSWORD state file.',
            5: 'Failed to create the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred during backup password setup.')


class BackupPasswordRecoveryMixin(LoggerMixin):
    """Mixin that provides backup password recovery functionality."""

    request: HttpRequest

    def handle_backup_password_recovery(self, backup_password: str) -> bool:
        """Handle DEK recovery using backup password.

        This method handles two scenarios:
        1. Standard recovery: KEK exists, use it to wrap the recovered DEK
        2. New KEK scenario: No KEK or KEK doesn't match, generate new KEK first

        Args:
            backup_password: The backup password provided by user

        Returns:
            bool: True if recovery was successful, False otherwise
        """
        try:
            token = self._get_token_for_recovery()
            if not token:
                return False

            has_kek = self._ensure_kek_exists(token)
            if has_kek is None:
                return False

            dek_bytes = self._recover_dek_with_password(token, backup_password)
            if not dek_bytes:
                return False

            if not self._wrap_and_save_dek(token, dek_bytes, had_kek=has_kek):
                return False

            self._cache_dek(token)
            self._log_success(token, had_kek=has_kek)

        except Exception:
            self.logger.exception('Unexpected error during backup password recovery')
            messages.add_message(self.request, messages.ERROR, 'Unexpected error during backup password recovery')
            return False
        else:
            return True

    def _get_token_for_recovery(self) -> PKCS11Token | None:
        """Get the PKCS11Token for recovery."""
        token = PKCS11Token.objects.first()
        if not token:
            self.logger.warning('No PKCS11Token found after restore for backup password recovery')
            return None

        if not token.has_backup_encryption():
            self.logger.warning('No backup encryption found for token %s, skipping password recovery', token.label)
            return None

        return token

    def _ensure_kek_exists(self, token: PKCS11Token) -> bool | None:
        """Ensure KEK exists on the token, generate if needed.

        Returns:
            bool: True if KEK already existed, False if newly generated, None on error
        """
        has_kek = bool(token.kek)

        if not has_kek:
            self.logger.info('No KEK found on token %s - generating new KEK', token.label)
            try:
                token.generate_kek(key_length=256)
                self.logger.info('New KEK generated successfully for token %s', token.label)
            except (subprocess.CalledProcessError, ValueError, RuntimeError) as e:
                self.logger.exception('Failed to generate new KEK for token %s', token.label)
                messages.add_message(self.request, messages.ERROR, f'Failed to generate new KEK: {e}')
                return None

        return has_kek

    def _recover_dek_with_password(self, token: PKCS11Token, backup_password: str) -> bytes | None:
        """Recover DEK using backup password."""
        try:
            return token.get_dek_with_backup_password(backup_password)
        except (RuntimeError, ValueError):
            self.logger.exception('Invalid backup password provided for token %s', token.label)
            self.logger.exception('The restore process needs to be redone with the correct backup password.')
            messages.add_message(
                self.request, messages.ERROR, 'Invalid backup password provided. DEK recovery failed. '
            )
            messages.add_message(
                self.request, messages.ERROR, 'The restore process needs to be redone with the correct backup password.'
            )
            return None

    def _wrap_and_save_dek(self, token: PKCS11Token, dek_bytes: bytes, *, had_kek: bool) -> bool:
        """Wrap recovered DEK with KEK and save."""
        try:
            wrapped_dek = token.wrap_dek(dek_bytes)
            token.encrypted_dek = wrapped_dek
            token.save(update_fields=['encrypted_dek'])

            kek_status = 'newly generated' if not had_kek else 'existing'
            self.logger.info('Successfully wrapped recovered DEK with %s KEK for token %s', kek_status, token.label)
        except RuntimeError as e:
            self.logger.exception('Failed to wrap recovered DEK for token %s', token.label)
            messages.add_message(self.request, messages.ERROR, f'Failed to wrap recovered DEK with KEK: {e}')
            return False
        else:
            return True

    def _cache_dek(self, token: PKCS11Token) -> None:
        """Cache the DEK for immediate use."""
        try:
            cached_dek = token.get_dek()
            if cached_dek:
                self.logger.info('DEK successfully cached for token %s after backup recovery', token.label)
            else:
                self.logger.warning('Failed to cache DEK for token %s after backup recovery', token.label)
        except Exception as e:  # noqa: BLE001
            self.logger.warning('Failed to cache DEK for token %s: %s', token.label, e)

    def _log_success(self, token: PKCS11Token, *, had_kek: bool) -> None:
        """Log successful recovery."""
        recovery_type = 'with new KEK generation' if not had_kek else 'with existing KEK'
        self.logger.info('Successfully completed backup password recovery for token %s %s', token.label, recovery_type)
        messages.add_message(
            self.request,
            messages.SUCCESS,
            'DEK successfully recovered using backup password and re-secured with HSM key.',
        )


class BackupRestoreView(BackupPasswordRecoveryMixin, LoggerMixin, View):
    """Upload a dump file and restore the database from it with optional backup password."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle POST requests to upload a backup file and restore the database."""
        form = BackupRestoreForm(request.POST, request.FILES)

        if not form.is_valid():
            return self._handle_invalid_form()

        backup_file = form.cleaned_data['backup_file']
        backup_password = form.cleaned_data.get('backup_password')

        try:
            return self._process_backup_file(backup_file, backup_password)
        except subprocess.CalledProcessError as exception:
            err_msg = f'Restore script failed: {self._map_exit_code_to_message(exception.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('users:login')
        except FileNotFoundError:
            err_msg = 'Restore script not found.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('users:login')
        except Exception:
            err_msg = 'An unexpected error occurred during the restore process.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('users:login')

    def _handle_invalid_form(self) -> HttpResponse:
        """Handle invalid form submission."""
        messages.add_message(self.request, messages.ERROR, 'Please correct the errors below and try again.')
        return redirect('users:login')

    def _process_backup_file(self, backup_file: Any, backup_password: str | None) -> HttpResponse:
        """Process the uploaded backup file."""
        temp_dir = settings.BACKUP_FILE_PATH
        temp_path = temp_dir / backup_file.name

        try:
            self._save_backup_file(backup_file, temp_path)
            self._restore_database(backup_file, backup_password)
        finally:
            self._cleanup_temp_file(temp_path)

        return redirect('users:login')

    def _save_backup_file(self, backup_file: Any, temp_path: Path) -> None:
        """Save the uploaded backup file to a temporary location."""
        with temp_path.open('wb+') as f:
            for chunk in backup_file.chunks():
                f.write(chunk)

        call_command('dbrestore', '-z', '--noinput', '-I', str(temp_path))

    def _restore_database(self, backup_file: Any, backup_password: str | None) -> None:
        """Restore the database from the backup file."""
        if backup_password:
            success = self.handle_backup_password_recovery(backup_password)
            if not success:
                messages.add_message(
                    self.request, messages.ERROR, 'Database restored successfully, but backup password recovery failed.'
                )
        else:
            self.logger.warning(
                'No backup password provided, skipping DEK recovery. Encrypted fields may not be accessible.'
            )
        call_command('trustpointrestore')

        messages.add_message(
            self.request, messages.SUCCESS, f'Trustpoint restored successfully from {backup_file.name}'
        )

    def _cleanup_temp_file(self, temp_path: Path) -> None:
        """Clean up the temporary backup file."""
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception as e:  # noqa: BLE001
            self.logger.warning('Failed to clean up temporary file %s: %s', temp_path, e)

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'State file WIZARD_SETUP_MODE not found.',
            3: 'Failed to remove the WIZARD_SETUP_MODE state file.',
            4: 'Failed to create the WIZARD_COMPLETED state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred during the restore process.')


class BackupAutoRestorePasswordView(BackupPasswordRecoveryMixin, LoggerMixin, FormView[PasswordAutoRestoreForm]):
    """View for handling backup password entry during auto restore process.

    This view allows users to enter the backup password needed to recover
    the DEK (Data Encryption Key) during the auto restore process. It validates
    the current wizard state and processes the password recovery.
    """

    http_method_names = ('get', 'post')
    template_name = 'setup_wizard/auto_restore_password.html'
    success_url = reverse_lazy('users:login')
    form_class = PasswordAutoRestoreForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['page_title'] = gettext_lazy('Auto Restore - Enter Backup Password')
        context['page_description'] = gettext_lazy('Enter the backup password to complete the auto restore process.')
        return context

    def form_valid(self, form: PasswordAutoRestoreForm) -> HttpResponse:
        """Handle valid form submission."""
        backup_password = form.cleaned_data.get('password')

        try:
            success = self.handle_backup_password_recovery(cast('str', backup_password))

            if not success:
                return self.form_invalid(form)

            self.logger.info('Extracting Trustpoint TLS certificates from database')
            try:
                self._extract_tls_certificates()
            except Exception as e:
                err_msg = f'Failed to extract TLS certificates: {e}'
                self.logger.exception(err_msg)
                messages.add_message(self.request, messages.ERROR, err_msg)
                return self.form_invalid(form)

            execute_shell_script(SCRIPT_WIZARD_AUTO_RESTORE_SUCCESS)

            self._deactivate_all_issuing_cas()

            messages.add_message(
                self.request, messages.SUCCESS, 'Auto restore completed successfully. You can now log in.'
            )
            messages.add_message(
                self.request,
                messages.WARNING,
                'All Certificate Authorities have been deactivated because their private keys are no longer '
                'available after HSM change.',
            )
            self.logger.info('Auto restore completed successfully with backup password recovery')
            return super().form_valid(form)

        except subprocess.CalledProcessError as exc:
            err_msg = f'Auto restore script failed: {self._map_exit_code_to_message(exc.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return self.form_invalid(form)

        except FileNotFoundError:
            err_msg = 'Auto restore script not found: '
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return self.form_invalid(form)

        except Exception:
            err_msg = 'An unexpected error occurred during auto restore password recovery.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception('Unexpected error during auto restore')
            return self.form_invalid(form)

    def form_invalid(self, form: PasswordAutoRestoreForm) -> HttpResponse:
        """Handle invalid form submission."""
        messages.add_message(self.request, messages.ERROR, 'Please correct the errors below and try again.')
        return super().form_invalid(form)

    def _raise_runtime_error(self, message: str) -> None:
        """Helper method to raise RuntimeError with logging."""
        self.logger.error(message)
        raise RuntimeError(message)

    def _deactivate_all_issuing_cas(self) -> None:
        """Deactivate all Issuing CAs after HSM change.

        When restoring to a new HSM, the private keys from the old HSM are no longer
        available. This method deactivates all CAs to prevent operations that would
        require the missing private keys.
        """
        try:
            active_cas = CaModel.objects.filter(is_active=True)
            count = active_cas.count()

            if count > 0:
                active_cas.update(is_active=False)
                self.logger.info(
                    'Deactivated %d Certificate Authority(ies) due to HSM change - private keys no longer available',
                    count,
                )
            else:
                self.logger.info('No active Certificate Authorities found to deactivate')

        except Exception:
            self.logger.exception('Failed to deactivate Certificate Authorities')
            # Don't raise - this is not critical enough to fail the restore process

    def _extract_tls_certificates(self) -> None:
        """Extract TLS certificates from database and write to files for Nginx configuration.

        This is called during auto restore to prepare TLS files before Nginx configuration.

        Raises:
            RuntimeError: If TLS credential extraction fails.
        """
        try:
            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
            tls_server_credential_model = active_tls.credential

            if not tls_server_credential_model:
                self._raise_runtime_error('TLS credential not found in database')

            tls_server_credential_model = cast('CredentialModel', tls_server_credential_model)

            private_key_pem = tls_server_credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = tls_server_credential_model.get_certificate_serializer().as_pem().decode()
            trust_store_pem = tls_server_credential_model.get_certificate_chain_serializer().as_pem().decode()

            NGINX_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
            NGINX_KEY_PATH.write_text(private_key_pem)
            NGINX_CERT_PATH.write_text(certificate_pem)

            if trust_store_pem.strip():
                NGINX_CERT_CHAIN_PATH.write_text(trust_store_pem)
            elif NGINX_CERT_CHAIN_PATH.exists():
                NGINX_CERT_CHAIN_PATH.unlink()

            self.logger.info('TLS certificates extracted successfully')

        except ActiveTrustpointTlsServerCredentialModel.DoesNotExist as e:
            error_msg = 'Active TLS credential not found in database'
            self.logger.exception(error_msg)
            raise RuntimeError(error_msg) from e
        except Exception as e:
            error_msg = f'Failed to extract TLS certificates: {e}'
            self.logger.exception(error_msg)
            raise RuntimeError(error_msg) from e

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_AUTO_RESTORE_PASSWORD state.',
            2: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            3: 'Failed to remove the WIZARD_AUTO_RESTORE_PASSWORD state file.',
            4: 'Failed to create the WIZARD_COMPLETED state file.',
            5: 'Failed to execute post-restore operations.',
        }
        return error_messages.get(return_code, 'An unknown error occurred during auto restore password processing.')
