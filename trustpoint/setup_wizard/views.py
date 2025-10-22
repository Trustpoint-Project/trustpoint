"""Views for the users application."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db.models import ProtectedError
from django.http import HttpRequest, HttpResponse, HttpResponseBase, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import FormView, TemplateView, View
from management.forms import KeyStorageConfigForm
from management.models import KeyStorageConfig, PKCS11Token
from pki.models import CertificateModel, CredentialModel, IssuingCaModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from trustpoint.logger import LoggerMixin

from setup_wizard import SetupWizardState
from setup_wizard.forms import (
    BackupPasswordForm,
    EmptyForm,
    HsmSetupForm,
    PasswordAutoRestoreForm,
    StartupWizardTlsCertificateForm,
)
from setup_wizard.tls_credential import TlsServerCredentialGenerator
from trustpoint.settings import DOCKER_CONTAINER

if TYPE_CHECKING:
    from trustpoint_core.serializer import CertificateSerializer


APACHE_PATH = Path(__file__).parent.parent.parent / 'docker/trustpoint/apache/tls'
APACHE_KEY_PATH = APACHE_PATH / Path('apache-tls-server-key.key')
APACHE_CERT_PATH = APACHE_PATH / Path('apache-tls-server-cert.pem')
APACHE_CERT_CHAIN_PATH = APACHE_PATH / Path('apache-tls-server-cert-chain.pem')

STATE_FILE_DIR = Path('/etc/trustpoint/wizard/transition/')
SCRIPT_WIZARD_SETUP_CRYPTO_STORAGE = STATE_FILE_DIR / Path('wizard_setup_crypto_storage.sh')
SCRIPT_WIZARD_SETUP_HSM = STATE_FILE_DIR / Path('wizard_setup_hsm.sh')
SCRIPT_WIZARD_SETUP_MODE = STATE_FILE_DIR / Path('wizard_setup_mode.sh')
SCRIPT_WIZARD_SELECT_TLS_SERVER_CREDENTIAL = STATE_FILE_DIR / Path('wizard_select_tls_server_credential.sh')
SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY = STATE_FILE_DIR / Path('wizard_tls_server_credential_apply.sh')
SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL = STATE_FILE_DIR / Path('wizard_tls_server_credential_apply_cancel.sh')
SCRIPT_WIZARD_BACKUP_PASSWORD = STATE_FILE_DIR / Path('wizard_backup_password.sh')
SCRIPT_WIZARD_DEMO_DATA = STATE_FILE_DIR / Path('wizard_demo_data.sh')
SCRIPT_WIZARD_CREATE_SUPER_USER = STATE_FILE_DIR / Path('wizard_create_super_user.sh')
SCRIPT_WIZARD_RESTORE = STATE_FILE_DIR / Path('wizard_restore.sh')
SCRIPT_WIZARD_AUTORESTORE_PASSWORD = STATE_FILE_DIR / Path('wizard_autorestorepassword.sh')


logger = logging.getLogger(__name__)



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
        err_msg = f'State bump script not found: {script_path}'
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


class StartupWizardRedirect:
    """Handles redirection logic based on the current state of the setup wizard.

    This class provides a static method for determining the appropriate redirection
    URL based on the wizard's state, ensuring users are guided through the setup process.
    """

    @staticmethod
    def redirect_by_state(wizard_state: SetupWizardState) -> HttpResponseRedirect:
        """Redirects the user to the appropriate setup wizard page based on the current state.

        Args:
            wizard_state (SetupWizardState): The current state of the setup wizard.

        Returns:
            HttpResponseRedirect: A redirection response to the appropriate page.

        Raises:
            ValueError: If the wizard state is unrecognized or invalid.
        """
        state_to_url = {
            SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE: 'setup_wizard:crypto_storage_setup',
            SetupWizardState.WIZARD_SETUP_HSM: 'setup_wizard:hsm_setup',
            SetupWizardState.WIZARD_SETUP_MODE: 'setup_wizard:setup_mode',
            SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY: 'setup_wizard:tls_server_credential_apply',
            SetupWizardState.WIZARD_BACKUP_PASSWORD: 'setup_wizard:backup_password',
            SetupWizardState.WIZARD_DEMO_DATA: 'setup_wizard:demo_data',
            SetupWizardState.WIZARD_CREATE_SUPER_USER: 'setup_wizard:create_super_user',
            SetupWizardState.WIZARD_COMPLETED: 'users:login',
            SetupWizardState.WIZARD_AUTO_RESTORE_HSM: 'setup_wizard:auto_restore_hsm',
            SetupWizardState.WIZARD_AUTO_RESTORE_PASSWORD: 'setup_wizard:auto_restore_password',
        }

        if wizard_state == 'WIZARD_SETUP_HSM':
            try:
                config = KeyStorageConfig.get_config()
                if config.storage_type == KeyStorageConfig.StorageType.SOFTHSM:
                    hsm_type = 'softhsm'
                elif config.storage_type == KeyStorageConfig.StorageType.PHYSICAL_HSM:
                    hsm_type = 'physical'
                else:
                    msg = 'Invalid storage type for HSM setup.'
                    raise ValueError(msg) from None

                return redirect(state_to_url[wizard_state], hsm_type=hsm_type, permanent=False)

            except KeyStorageConfig.DoesNotExist:
                msg = 'KeyStorageConfig is not configured.'
                raise ValueError(msg) from None

        if wizard_state in state_to_url:
            return redirect(state_to_url[wizard_state], permanent=False)

        err_msg = 'Unknown wizard state found. Failed to redirect by state.'
        raise ValueError(err_msg) from None


class HsmSetupMixin(LoggerMixin):
    """Mixin that provides common HSM setup functionality for both initial setup and auto restore."""
    form_class = HsmSetupForm
    template_name = 'setup_wizard/hsm_setup.html'
    http_method_names = ('get', 'post')

    def form_valid(self, form: HsmSetupForm) -> HttpResponse:
        """Handle form submission for HSM setup."""
        cleaned_data = form.cleaned_data
        hsm_type = cleaned_data['hsm_type']

        if hsm_type != 'softhsm':
            messages.add_message(self.request, messages.ERROR, 'Physical HSM is not yet supported.')
            return redirect(self.get_error_redirect_url(), permanent=False)

        module_path = cleaned_data['module_path']
        slot = str(cleaned_data['slot'])
        label = cleaned_data['label']

        if not self._validate_hsm_inputs(module_path, slot, label):
            return redirect(self.get_error_redirect_url(), permanent=False)

        try:
            result = self._run_hsm_setup_script(module_path, slot, label)
            if result.returncode != 0:
                self._raise_called_process_error(result.returncode)
            token, created = self._get_or_update_token(hsm_type, module_path, slot, label)
            self._generate_kek_and_dek(token)
            self._add_success_message(hsm_type, created=created, token=token)
        except Exception as exc:  # noqa: BLE001
            return self._handle_hsm_setup_exception(exc)

        return super().form_valid(form)

    def _validate_hsm_inputs(self, module_path: str, slot: str, label: str) -> bool:
        """Validate HSM input fields and add error messages if invalid."""
        if not re.match(r'^[\w\-/\.]+$', module_path):
            messages.add_message(self.request, messages.ERROR, 'Invalid module path.')
            return False
        if not slot.isdigit():
            messages.add_message(self.request, messages.ERROR, 'Invalid slot value.')
            return False
        if not re.match(r'^[\w\-]+$', label):
            messages.add_message(self.request, messages.ERROR, 'Invalid label.')
            return False
        for arg in [module_path, slot, label]:
            if not re.match(r'^[\w\-/\.]+$', arg):
                messages.add_message(self.request, messages.ERROR, 'Invalid argument detected in command.')
                return False
        return True

    def _run_hsm_setup_script(self, module_path: str, slot: str, label: str) -> subprocess.CompletedProcess[str]:
        """Run the HSM setup shell script."""
        setup_type = self.get_setup_type()
        command = ['sudo', str(SCRIPT_WIZARD_SETUP_HSM), module_path, slot, label, setup_type]
        return subprocess.run(command, capture_output=True, text=True, check=True)  # noqa: S603

    def _get_or_update_token(self, hsm_type: str, module_path: str, slot: str, label: str) -> tuple[PKCS11Token, bool]:
        """Get or update the PKCS11Token object."""
        token, created = PKCS11Token.objects.get_or_create(
            label=label,
            defaults={
                'slot': int(slot),
                'module_path': module_path,
            }
        )
        if not created:
            token.slot = int(slot)
            token.module_path = module_path
            token.save()

        self._assign_token_to_crypto_storage(token, hsm_type)

        return token, created

    def _assign_token_to_crypto_storage(self, token: PKCS11Token, hsm_type: str) -> None:
        """Assign the created token to the appropriate crypto storage configuration."""
        try:
            config = KeyStorageConfig.get_config()

            if hsm_type == 'softhsm' and config.storage_type == KeyStorageConfig.StorageType.SOFTHSM:
                config.hsm_config = token
                config.save(update_fields=['hsm_config'])
                self.logger.info('Assigned SoftHSM token %s to crypto storage configuration', token.label)

            elif hsm_type == 'physical' and config.storage_type == KeyStorageConfig.StorageType.PHYSICAL_HSM:
                config.hsm_config = token
                config.save(update_fields=['hsm_config'])
                self.logger.info('Assigned Physical HSM token %s to crypto storage configuration', token.label)

            else:
                self.logger.warning(
                    'Token HSM type %s does not match crypto storage type %s, not assigning',
                    hsm_type, config.storage_type
                )

        except (AttributeError, ValueError, RuntimeError) as e:
            self.logger.warning('Failed to assign token to crypto storage configuration: %s', e)

    def _generate_kek_and_dek(self, token: PKCS11Token) -> None:
        """Generate KEK and DEK for the token, log and warn on failure."""
        try:
            token.generate_kek(key_length=256)
            self.logger.info('key encryption key (KEK) generated for token: %s', token.label)
        except Exception as e:
            self.logger.exception('Failed to generate key encryption key (KEK)')
            messages.add_message(self.request, messages.WARNING,
                                 f'HSM setup completed, but key encryption key (KEK) generation failed: {e!s}')
        try:
            token.generate_and_wrap_dek()
            self.logger.info('DEK generated and wrap for token: %s', token.label)
        except Exception as e:
            self.logger.exception('Failed to generate and wrap DEK')
            messages.add_message(self.request, messages.WARNING,
                                 f'HSM setup completed, but DEK generation failed: {e!s}')

    def _raise_called_process_error(self, returncode: int) -> None:
        """Raise a subprocess.CalledProcessError with the given return code."""
        raise subprocess.CalledProcessError(returncode, str(SCRIPT_WIZARD_SETUP_HSM))

    def _add_success_message(self, hsm_type: str, *, created: bool, token: PKCS11Token) -> None:
        """Add a success message for HSM setup."""
        action = 'created' if created else 'updated'
        context = self.get_success_context()
        messages.add_message(self.request, messages.SUCCESS,
                             f'HSM setup completed successfully {context} with {hsm_type.upper()}. '
                             f'PKCS#11 token configuration {action}.')
        self.logger.info('PKCS11Token %s %s: %s', action, context, token)

    def _handle_hsm_setup_exception(self, exc: Exception) -> HttpResponse:
        """Handle exceptions during HSM setup and add appropriate error messages."""
        if isinstance(exc, subprocess.CalledProcessError):
            err_msg = f'HSM setup failed: {self._map_exit_code_to_message(exc.returncode)}'
        elif isinstance(exc, FileNotFoundError):
            err_msg = f'HSM setup script not found: {SCRIPT_WIZARD_SETUP_HSM}'
        else:
            err_msg = 'An unexpected error occurred during HSM setup.'
        messages.add_message(self.request, messages.ERROR, err_msg)
        self.logger.exception(err_msg)
        return redirect(self.get_error_redirect_url(), permanent=False)

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Invalid number of arguments provided to HSM setup script.',
            2: 'Trustpoint is not in the WIZARD_SETUP_HSM state.',
            3: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            4: 'HSM SO PIN file not found or not readable.',
            5: 'HSM PIN file not found or not readable.',
            6: 'HSM SO PIN is empty or could not be read from file.',
            7: 'HSM PIN is empty or could not be read from file.',
            8: 'PKCS#11 module not found.',
            9: 'Failed to initialize HSM token.',
            10: 'Failed to initialize user PIN for HSM.',
            11: 'Failed to access HSM with configured PIN.',
            12: 'Failed to remove the WIZARD_SETUP_HSM state file.',
            13: 'Failed to create the WIZARD_SETUP_MODE state file.',
            14: 'Failed to set ownership of SoftHSM tokens to www-data.',
            15: 'Failed to set permissions on SoftHSM tokens.',
            16: 'Failed to set permissions on SoftHSM config file.',
            17: 'Failed to set permissions on /var/lib/softhsm directory.',
            18: 'www-data still cannot access token directory after permission changes.',
            19: 'Failed to access HSM slot as www-data user.',
            20: 'Failed to create the WIZARD_AUTO_RESTORE state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred during HSM setup.')

    def get_setup_type(self) -> str:
        """Return the setup type for the HSM script."""
        msg = 'Subclasses must implement get_setup_type()'
        raise NotImplementedError(msg)

    def get_error_redirect_url(self) -> str:
        """Return the URL to redirect to on error."""
        msg = 'Subclasses must implement get_error_redirect_url()'
        raise NotImplementedError(msg)

    def get_success_context(self) -> str:
        """Return context string for success messages."""
        msg = 'Subclasses must implement get_success_context()'
        raise NotImplementedError(msg)

    def get_expected_wizard_state(self) -> SetupWizardState:
        """Return the expected wizard state for this view."""
        msg = 'Subclasses must implement get_expected_wizard_state()'
        raise NotImplementedError(msg)

class SetupWizardCryptoStorageView(LoggerMixin, FormView):
    """View for handling crypto storage setup during the setup wizard."""

    http_method_names = ('get', 'post')
    template_name = 'setup_wizard/crypto_storage_setup.html'
    form_class = KeyStorageConfigForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: KeyStorageConfigForm) -> HttpResponse:
        """Handle valid form submission and determine next step based on storage type."""
        try:
            config = form.save()
            storage_type = config.storage_type

            execute_shell_script(SCRIPT_WIZARD_SETUP_CRYPTO_STORAGE, storage_type)

            messages.add_message(
                self.request,
                messages.SUCCESS,
                f'Crypto storage configuration saved: {config.get_storage_type_display()}'
            )

            self.logger.info('Crypto storage configured with type: %s', storage_type)

            if storage_type == KeyStorageConfig.StorageType.SOFTWARE:
                return redirect('setup_wizard:setup_mode', permanent=False)
            if storage_type == KeyStorageConfig.StorageType.SOFTHSM:
                return redirect('setup_wizard:hsm_setup', hsm_type='softhsm', permanent=False)
            if storage_type == KeyStorageConfig.StorageType.PHYSICAL_HSM:
                    messages.add_message(
                                    self.request,
                                    messages.ERROR,
                                    'Physical HSM is coming soon.'
                                )
                # return redirect('setup_wizard:hsm_setup', hsm_type='physical', permanent=False)  # noqa: ERA001

            messages.add_message(
                self.request,
                messages.ERROR,
                'Unknown storage type selected.'
            )
            return redirect('setup_wizard:crypto_storage_setup', permanent=False)

        except subprocess.CalledProcessError as exception:
            err_msg = f'Crypto storage script failed: {self._map_exit_code_to_message(exception.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:crypto_storage_setup', permanent=False)

        except FileNotFoundError:
            err_msg = f'Crypto storage script not found: {SCRIPT_WIZARD_SETUP_CRYPTO_STORAGE}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:crypto_storage_setup', permanent=False)

        except Exception:
            err_msg = 'An unexpected error occurred during crypto storage setup.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception('Crypto storage setup error')
            return redirect('setup_wizard:crypto_storage_setup', permanent=False)

    def form_invalid(self, form: KeyStorageConfigForm) -> HttpResponse:
        """Handle invalid form submission."""
        messages.add_message(
            self.request,
            messages.ERROR,
            'Please correct the errors below and try again.'
        )
        return super().form_invalid(form)

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_SETUP_CRYPTO_STORAGE state.',
            2: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            3: 'Failed to remove the WIZARD_SETUP_CRYPTO_STORAGE state file.',
            4: 'Failed to create the next wizard state file.',
            5: 'Invalid crypto storage type provided.',
        }
        return error_messages.get(return_code, 'An unknown error occurred during crypto storage setup.')

class SetupWizardHsmSetupView(HsmSetupMixin, FormView):
    """View for handling HSM setup during the setup wizard."""

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != self.get_expected_wizard_state():
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        hsm_type = kwargs.get('hsm_type')
        if hsm_type not in ['softhsm', 'physical']:
            messages.add_message(
                self.request,
                messages.ERROR,
                'Invalid HSM type specified.'
            )
            return redirect('setup_wizard:crypto_storage_setup', permanent=False)

        try:
            config = KeyStorageConfig.get_config()

            expected_storage_type = (
                KeyStorageConfig.StorageType.SOFTHSM if hsm_type == 'softhsm'
                else KeyStorageConfig.StorageType.PHYSICAL_HSM
            )

            if config.storage_type != expected_storage_type:
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    f'{hsm_type.title()} HSM setup is only available when {hsm_type.title()} HSM storage is selected.'
                )
                return redirect('setup_wizard:crypto_storage_setup', permanent=False)
        except Exception:  # noqa: BLE001
            return redirect('setup_wizard:crypto_storage_setup', permanent=False)

        return super().dispatch(request, *args, **kwargs)

    def get_form(self, form_class: type[HsmSetupForm] | None = None) -> HsmSetupForm:
        """Return a form instance with appropriate defaults based on HSM type."""
        if form_class is None:
            form_class = self.get_form_class()

        hsm_type = self.kwargs.get('hsm_type')
        form_kwargs = self.get_form_kwargs()

        return form_class(hsm_type, **form_kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add HSM type to template context."""
        context = super().get_context_data(**kwargs)
        context['hsm_type'] = self.kwargs.get('hsm_type')
        context['hsm_type_display'] = self.kwargs.get('hsm_type').replace('_', ' ').title()
        return context

    def get_setup_type(self) -> str:
        """Return the setup type for the HSM script."""
        return 'init_setup'

    def get_success_url(self) -> str:
        """Return the success URL after HSM setup."""
        return reverse_lazy('setup_wizard:setup_mode')

    def get_error_redirect_url(self) -> str:
        """Return the URL to redirect to on error."""
        return 'setup_wizard:hsm_setup'

    def get_success_context(self) -> str:
        """Return context string for success messages."""
        return 'for initial setup'

    def get_expected_wizard_state(self) -> SetupWizardState:
        """Return the expected wizard state for this view."""
        return SetupWizardState.WIZARD_SETUP_HSM

class BackupAutoRestoreHsmView(HsmSetupMixin, FormView):
    """View for handling HSM setup during auto restore process."""

    success_url = reverse_lazy('setup_wizard:auto_restore_password')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != self.get_expected_wizard_state():
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def get_setup_type(self) -> str:
        """Return the setup type for the HSM script."""
        return 'auto_restore_setup'

    def get_error_redirect_url(self) -> str:
        """Return the URL to redirect to on error."""
        return 'setup_wizard:auto_restore_hsm'

    def get_success_context(self) -> str:
        """Return context string for success messages."""
        return 'for auto restore'

    def get_expected_wizard_state(self) -> SetupWizardState:
        """Return the expected wizard state for this view."""
        return SetupWizardState.WIZARD_AUTO_RESTORE_HSM

class SetupWizardSetupModeView(TemplateView):
    """View for the initial step of the setup wizard.

    This view is responsible for displaying the initial setup wizard page. It
    ensures that the application is running in a Docker container and that the
    setup wizard is in the initial state. If either condition is not met, the
    user is redirected to the appropriate page, such as the login page or the
    next setup step.

    Attributes:
        http_method_names (ClassVar[list[str]]): List of HTTP methods allowed for this view.
        template_name (str): Path to the template used for rendering the initial page.
    """

    http_method_names = ('get',)
    template_name = 'setup_wizard/setup_mode.html'

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests for the setup mode wizard page.

        This method validates the current state of the setup wizard and redirects
        the user to the appropriate page. If the application is not running in a
        Docker container, the user is redirected to the login page.

        Args:
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            HttpResponse: A redirect response to the appropriate setup wizard page
                          or the login page if the setup is not in a Docker container.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_SETUP_MODE:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().get(*args, **kwargs)

class SetupWizardSelectTlsServerCredentialView(LoggerMixin, FormView):
    """View for selecting the TLS server credential during setup."""

    http_method_names = ('get', 'post')
    template_name = 'setup_wizard/select_tls_server_credential.html'
    form_class = EmptyForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_SETUP_MODE:
            self.logger.warning(
                "Unexpected wizard state '%s' expected '%s'",
                wizard_state,
                SetupWizardState.WIZARD_SETUP_MODE,
            )
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests for the TLS server credential selection page."""
        return super().get(*args, **kwargs)

    def form_valid(self, form: EmptyForm) -> HttpResponse:
        """Handle form submission for TLS server credential selection."""
        try:
            if 'generate_credential' in self.request.POST:
                return redirect('setup_wizard:generate_tls_server_credential', permanent=False)
            if 'import_credential' in self.request.POST:
                return redirect('setup_wizard:import_tls_server_credential', permanent=False)
            messages.add_message(
                self.request,
                messages.ERROR,
                'Invalid option selected.'
            )
            return redirect('setup_wizard:select_tls_server_credential', permanent=False)

        except subprocess.CalledProcessError as exception:
            err_msg = f'Setup mode script failed: {self._map_exit_code_to_message(exception.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:select_tls_server_credential', permanent=False)
        except FileNotFoundError:
            err_msg = f'Setup mode script not found: {SCRIPT_WIZARD_SETUP_MODE}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:select_tls_server_credential', permanent=False)
        except Exception:
            err_msg = 'An unexpected error occurred during setup mode execution.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:select_tls_server_credential', permanent=False)

class SetupWizardRestoreOptionsView(TemplateView):
    """View for the restore option during initialization.

    Attributes:
        http_method_names (ClassVar[list[str]]): List of HTTP methods allowed for this view.
        template_name (str): Path to the template used for rendering the initial page.
    """

    http_method_names = ('get',)
    template_name = 'setup_wizard/restore_options.html'

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests for the initial setup wizard page.

        This method validates the current state of the setup wizard and redirects
        the user to the appropriate page. If the application is not running in a
        Docker container, the user is redirected to the login page.

        Args:
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            HttpResponse: A redirect response to the appropriate setup wizard page
                          or the login page if the setup is not in a Docker container.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_SETUP_MODE:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().get(*args, **kwargs)

class SetupWizardBackupPasswordView(LoggerMixin, FormView):
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
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_BACKUP_PASSWORD:
            self.logger.warning(
                "Unexpected wizard state '%s', expected '%s'. Redirecting to appropriate state.",
                wizard_state,
                SetupWizardState.WIZARD_BACKUP_PASSWORD,
            )
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict:
        """Add additional context data."""
        return super().get_context_data(**kwargs)

    def form_valid(self, form: BackupPasswordForm) -> HttpResponse:
        """Handle valid form submission."""
        password = form.cleaned_data.get('password')

        try:
            token = PKCS11Token.objects.first()
            if not token:
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    'No PKCS#11 token found. This should not happen in the backup password step.'
                )
                self.logger.error('No PKCS11Token found in backup password step')
                return redirect('setup_wizard:demo_data', permanent=False)

            token.set_backup_password(password)
            execute_shell_script(SCRIPT_WIZARD_BACKUP_PASSWORD)

            messages.add_message(
                self.request,
                messages.SUCCESS,
                'Backup password set successfully.'
            )
            self.logger.info('Backup password set for token: %s', token.label)
            return super().form_valid(form)

        except Exception as exc:
            error_mapping = {
                subprocess.CalledProcessError: lambda e: (
                    f'Backup password script failed: '
                    f'{self._map_exit_code_to_message(e.returncode)}'
                ),
                FileNotFoundError: lambda _: f'Backup password script not found: {SCRIPT_WIZARD_BACKUP_PASSWORD}',
                PKCS11Token.DoesNotExist: lambda e: str(e),
                ValueError: lambda e: f'Invalid input: {e!s}',
                RuntimeError: lambda e: f'Failed to set backup password: {e!s}',
            }
            err_msg = error_mapping.get(type(exc), lambda _:
                                        'An unexpected error occurred while setting up backup password.')(exc)
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)

            if isinstance(exc, (ValueError, RuntimeError)):
                return self.form_invalid(form)
            return redirect('setup_wizard:backup_password', permanent=False)

    def form_invalid(self, form: BackupPasswordForm) -> HttpResponse:
        """Handle invalid form submission."""
        messages.add_message(
            self.request,
            messages.ERROR,
            'Please correct the errors below and try again.'
        )
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


class BackupRestoreView(View, LoggerMixin):
    """Upload a dump file and restore the database from it."""
    def form_valid(self, form: BackupPasswordForm) -> HttpResponse:
        """Handle valid form submission."""
        password = form.cleaned_data.get('password')

        try:
            token = PKCS11Token.objects.first()
            if not token:
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    'No PKCS#11 token found. This should not happen in the backup password step.'
                )
                self.logger.error('No PKCS11Token found in backup password step')
                return redirect('setup_wizard:demo_data', permanent=False)

            token.set_backup_password(password)
            execute_shell_script(SCRIPT_WIZARD_BACKUP_PASSWORD)

            messages.add_message(
                self.request,
                messages.SUCCESS,
                'Backup password set successfully.'
            )
            self.logger.info('Backup password set for token: %s', token.label)
            return super().form_valid(form)

        except Exception as exc:
            error_mapping = {
                subprocess.CalledProcessError: lambda e: (
                    f'Backup password script failed: '
                    f'{self._map_exit_code_to_message(e.returncode)}'
                ),
                FileNotFoundError: lambda _: f'Backup password script not found: {SCRIPT_WIZARD_BACKUP_PASSWORD}',
                PKCS11Token.DoesNotExist: lambda e: str(e),
                ValueError: lambda e: f'Invalid input: {e!s}',
                RuntimeError: lambda e: f'Failed to set backup password: {e!s}',
            }
            err_msg = error_mapping.get(type(exc), lambda _:
                                        'An unexpected error occurred while setting up backup password.')(exc)
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)

            if isinstance(exc, (ValueError, RuntimeError)):
                return self.form_invalid(form)
            return redirect('setup_wizard:backup_password', permanent=False)

    def form_invalid(self, form: BackupPasswordForm) -> HttpResponse:
        """Handle invalid form submission."""
        messages.add_message(
            self.request,
            messages.ERROR,
            'Please correct the errors below and try again.'
        )
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

    def handle_backup_password_recovery(self, backup_password: str) -> bool:
        """Handle DEK recovery using backup password.

        Uses the existing KEK to wrap the recovered DEK and stores everything
        in the model for normal operation.

        Args:
            backup_password: The backup password provided by user

        Returns:
            bool: True if recovery was successful, False otherwise
        """
        try:
            # Get the PKCS11Token (should exist after database restore)
            token = PKCS11Token.objects.first()
            if not token:
                self.logger.warning('No PKCS11Token found after restore for backup password recovery')
                return False

            if not token.has_backup_encryption():
                self.logger.warning('No backup encryption found for token %s, skipping password recovery', token.label)
                return False

            # Verify the backup password and recover the DEK
            try:
                dek_bytes = token.get_dek_with_backup_password(backup_password)
            except (RuntimeError, ValueError):
                self.logger.exception('Invalid backup password provided for token %s', token.label)
                self.logger.exception('The restore process needs to be redone with the correct backup password.')
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    'Invalid backup password provided. DEK recovery failed. '
                )
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    'The restore process needs to be redone with the correct backup password.'
                )
                return False

            # Wrap the recovered DEK with the existing KEK (no new KEK generation)
            try:
                wrapped_dek = token.wrap_dek(dek_bytes)

                # Update the token with the newly wrapped DEK
                token.encrypted_dek = wrapped_dek
                token.save(update_fields=['encrypted_dek'])

                self.logger.info('Successfully wrapped recovered DEK with existing KEK for token %s', token.label)

            except RuntimeError as e:
                self.logger.exception('Failed to wrap recovered DEK for token %s', token.label)
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    f'Failed to wrap recovered DEK with existing KEK: {e}'
                )
                return False

            try:
                cached_dek = token.get_dek()
                if cached_dek:
                    self.logger.info('DEK successfully cached for token %s after backup recovery', token.label)
                else:
                    self.logger.warning('Failed to cache DEK for token %s after backup recovery', token.label)

            except Exception as e:  # noqa: BLE001
                self.logger.warning('Failed to cache DEK for token %s: %s', token.label, e)

        except Exception:
            self.logger.exception('Unexpected error during backup password recovery')
            messages.add_message(
                self.request,
                messages.ERROR,
                'Unexpected error during backup password recovery'
            )
            return False
        else:
            self.logger.info('Successfully completed backup password recovery for token %s', token.label)
            messages.add_message(
                self.request,
                messages.SUCCESS,
                'DEK successfully recovered using backup password and re-secured with new HSM key.'
            )
            return True

class BackupRestoreView(BackupPasswordRecoveryMixin, LoggerMixin, View):
    """Upload a dump file and restore the database from it with optional backup password."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle POST requests to upload a backup file and restore the database.

        Args:
            request (HttpRequest): The HTTP request containing the uploaded backup file.

        Returns:
            HttpResponse: A redirect to the appropriate page based on the outcome.
        """
        from setup_wizard.forms import BackupRestoreForm

        form = BackupRestoreForm(request.POST, request.FILES)

        if not form.is_valid():
            for field, errors in form.errors.items():
                for error in errors:
                    messages.add_message(request, messages.ERROR, f'{field}: {error}')
            return redirect('setup_wizard:restore_options')

        backup_file = form.cleaned_data['backup_file']
        backup_password = form.cleaned_data.get('backup_password')

        temp_dir = settings.BACKUP_FILE_PATH
        temp_path = temp_dir / backup_file.name
  
        try:
            # Save uploaded file
            with temp_path.open('wb+') as f:
                for chunk in backup_file.chunks():
                    f.write(chunk)

            call_command('dbrestore', '-z', '--noinput', '-I', str(temp_path))

            # Execute trustpoint restore command
            call_command('trustpointrestore')

            # Handle backup password for DEK recovery if provided
            if backup_password:
                success = self._handle_backup_password_recovery(backup_password)
                if not success:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        'Database restored successfully, but backup password recovery failed.'
                    )
                else:
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        f'Trustpoint restored successfully from {backup_file.name}'
                    )

                    self.logger.info('Backup restore completed successfully from file: %s', backup_file.name)

        except CommandError as e:
            messages.error(request, str(e))
        except FileNotFoundError as e:
            err_msg = f'Backup file not found: {backup_file.name}'
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
        except PermissionError:
            err_msg = f'Permission denied accessing backup file: {backup_file.name}'
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
        except subprocess.CalledProcessError:
            err_msg = f'Backup processing failed (pg_restore/awk) for file: {backup_file.name}'
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
        except Exception as e:
            err_msg = f'Unexpected error restoring database from {backup_file.name}: {e}'
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
        finally:
            # Clean up temporary file
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception as e:  # noqa: BLE001
                self.logger.warning('Failed to clean up temporary file %s: %s', temp_path, e)

        return redirect('users:login')

class BackupAutoRestorePasswordView(BackupPasswordRecoveryMixin, LoggerMixin, FormView):
    """View for handling backup password entry during auto restore process.

    This view allows users to enter the backup password needed to recover
    the DEK (Data Encryption Key) during the auto restore process. It validates
    the current wizard state and processes the password recovery.
    """

    http_method_names = ('get', 'post')
    template_name = 'setup_wizard/auto_restore_password.html'
    success_url = reverse_lazy('users:login')
    form_class = PasswordAutoRestoreForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_AUTO_RESTORE_PASSWORD:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['page_title'] = _('Auto Restore - Enter Backup Password')
        context['page_description'] = _('Enter the backup password to complete the auto restore process.')
        return context

    def form_valid(self, form: PasswordAutoRestoreForm) -> HttpResponse:
        """Handle valid form submission."""
        backup_password = form.cleaned_data.get('password')

        try:
            # Attempt to recover DEK using backup password
            success = self.handle_backup_password_recovery(backup_password)

            if not success:
                # Error messages are already added by handle_backup_password_recovery
                return self.form_invalid(form)

            # Execute the transition script to complete auto restore
            execute_shell_script(SCRIPT_WIZARD_AUTORESTORE_PASSWORD)

            messages.add_message(
                self.request,
                messages.SUCCESS,
                'Auto restore completed successfully. You can now log in.'
            )
            self.logger.info('Auto restore completed successfully with backup password recovery')
            return super().form_valid(form)

        except subprocess.CalledProcessError as exc:
            err_msg = f'Auto restore script failed: {self._map_exit_code_to_message(exc.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return self.form_invalid(form)

        except FileNotFoundError:
            err_msg = f'Auto restore script not found: {SCRIPT_WIZARD_AUTORESTORE_PASSWORD}'
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
        messages.add_message(
            self.request,
            messages.ERROR,
            'Please correct the errors below and try again.'
        )
        return super().form_invalid(form)

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

class SetupWizardGenerateTlsServerCredentialView(LoggerMixin, FormView[StartupWizardTlsCertificateForm]):
    """View for generating TLS Server Credentials in the setup wizard.

    This view handles the generation of TLS Server Credentials as part of the
    setup wizard. It provides a form for the user to input necessary information
    such as IP addresses and domain names, and processes the data to generate
    the required TLS certificates.

    Attributes:
        http_method_names (ClassVar[list[str]]): HTTP methods allowed for this view.
        template_name (str): Path to the template used for rendering the form.
        form_class (Form): The form class used to validate user input.
        success_url (str): The URL to redirect to upon successful credential generation.
    """

    http_method_names = ('get', 'post')
    template_name = 'setup_wizard/generate_tls_server_credential.html'
    form_class = StartupWizardTlsCertificateForm
    success_url = reverse_lazy('setup_wizard:tls_server_credential_apply')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Override the dispatch method to enforce wizard state validation.

        This method ensures that the user is redirected appropriately based on the
        current wizard state. If the application is not running in a Docker container,
        the user is redirected to the login page.

        Args:
            request (HttpRequest): The incoming HTTP request.
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            HttpResponse: A redirect response to the appropriate page or
                          the next handler in the dispatch chain.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_SETUP_MODE:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: StartupWizardTlsCertificateForm) -> HttpResponse:
        """Handle a valid form submission for TLS Server Credential generation.

        Args:
            form: The validated form containing user input
                                     for generating the TLS Server Credential.

        Returns:
            HttpResponseRedirect: Redirect to the success URL upon successful
                                  credential generation, or an error page if
                                  an exception occurs.

        Raises:
            TrustpointTlsServerCredentialError: If no TLS server credential is found.
            subprocess.CalledProcessError: If the associated shell script fails.
        """
        try:
            # Generate the TLS Server Credential
            cleaned_data = form.cleaned_data
            generator = TlsServerCredentialGenerator(
                ipv4_addresses=cleaned_data['ipv4_addresses'],
                ipv6_addresses=cleaned_data['ipv6_addresses'],
                domain_names=cleaned_data['domain_names'],
            )
            tls_server_credential = generator.generate_tls_server_credential()

            trustpoint_tls_server_credential = CredentialModel.save_credential_serializer(
                credential_serializer=tls_server_credential,
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
            )

            active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
            active_tls.credential = trustpoint_tls_server_credential
            active_tls.save()

            execute_shell_script(SCRIPT_WIZARD_SETUP_MODE)

            messages.add_message(self.request, messages.SUCCESS, 'TLS Server Credential generated successfully.')

            return super().form_valid(form)
        except subprocess.CalledProcessError as exception:
            err_msg = f'Script error: {self._get_error_message_from_return_code(exception.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:setup_mode', permanent=False)
        except FileNotFoundError:
            err_msg = f'Transition script not found: {SCRIPT_WIZARD_SETUP_MODE}.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:setup_mode', permanent=False)
        except Exception:
            err_msg = 'Error generating TLS Server Credential.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:setup_mode', permanent=False)

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_SETUP_MODE state. State file not found.',
            2: 'Found multiple wizard state files. The wizard state appears corrupted.',
            3: 'Failed to remove the WIZARD_SETUP_MODE state file.',
            4: 'Failed to create the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred during setup mode transition.')

class SetupWizardImportTlsServerCredentialView(View):
    """View for handling the import of TLS Server Credentials."""

    http_method_names = ('get',)

    def get(self) -> HttpResponse:
        """Handle GET requests for importing TLS Server Credentials.

        Returns:
            HttpResponse: A redirect to the initial setup wizard page if the
                          import feature is not implemented or the wizard state
                          is incorrect.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_SETUP_MODE:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        messages.add_message(
            self.request, messages.ERROR, 'Import of the TLS-Server credential is not yet implemented.'
        )
        return redirect('setup_wizard:setup_mode', permanent=False)

class SetupWizardTlsServerCredentialApplyView(LoggerMixin, FormView[EmptyForm]):
    """View for handling the application of TLS Server Credentials in the setup wizard.

    Attributes:
        http_method_names (list[str]): Allowed HTTP methods for this view ('get' and 'post').
        form_class (Form): The form used for processing TLS Server Credential application.
        template_name (str): The template used to render the view.
        success_url (str): The URL to redirect to upon successful form submission.
    """

    http_method_names = ('get', 'post')
    form_class = EmptyForm
    template_name = 'setup_wizard/tls_server_credential_apply.html'

    def get_success_url(self) -> str:
        """Return the success URL based on storage type."""
        try:
            config = KeyStorageConfig.get_config()
            if config.storage_type in [
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM
            ]:
                return reverse_lazy('setup_wizard:backup_password')
            return reverse_lazy('setup_wizard:demo_data')
        except KeyStorageConfig.DoesNotExist:
            return reverse_lazy('setup_wizard:demo_data')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests for the TLS Server Credential application view.

        Args:
            request (HttpRequest): The HTTP request object.
            *args (Any): Positional arguments passed to the method.
            **kwargs (Any): Keyword arguments passed to the method.

        Returns:
            HttpResponse: A redirect response to the appropriate wizard state or the requested page.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        file_format = self.kwargs.get('file_format')
        if file_format:
            return self._generate_trust_store_response(file_format)

        return super().get(request, *args, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for the TLS Server Credential application view.

        Args:
            *args (Any): Positional arguments passed to the method.
            **kwargs (Any): Keyword arguments passed to the method.

        Returns:
            HttpResponse: A redirect response to the appropriate page based on the wizard state.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().post(*args, **kwargs)

    def form_valid(self, form: EmptyForm) -> HttpResponse:
        """Process a valid form submission during the TLS Server Credential application.

        Args:
            form: The form instance containing the submitted data.

        Returns:
            HttpResponseRedirect: Redirect to the next step or an error page based on the outcome.
        """
        try:
            trustpoint_tls_server = ActiveTrustpointTlsServerCredentialModel.objects.first()
            if not trustpoint_tls_server:
                self._raise_tls_credential_error('No ActiveTrustpointTlsServerCredentialModel found.')

            trustpoint_tls_server_credential_model = trustpoint_tls_server.credential
            if not trustpoint_tls_server_credential_model:
                self._raise_tls_credential_error('No Trustpoint TLS Server Credential found.')

            self._write_pem_files(trustpoint_tls_server_credential_model)

            try:
                config = KeyStorageConfig.get_config()
                if config.storage_type in [
                    KeyStorageConfig.StorageType.SOFTHSM,
                    KeyStorageConfig.StorageType.PHYSICAL_HSM
                ]:
                    storage_param = 'hsm'
                else:
                    storage_param = 'no_hsm'
            except KeyStorageConfig.DoesNotExist:
                storage_param = 'no_hsm'
                self.logger.warning('KeyStorageConfig not found, defaulting to no_hsm mode')

            execute_shell_script(SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY, storage_param)

            messages.add_message(self.request, messages.SUCCESS, 'TLS Server Credential applied successfully.')
            return super().form_valid(form)

        except subprocess.CalledProcessError as exception:
            err_msg = f'Error applying TLS Server Credential: {self._map_exit_code_to_message(exception.returncode)}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)
        except FileNotFoundError:
            err_msg = 'File not found.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)
        except TrustpointWizardError:
            err_msg = 'Trustpoint Wizard Error occurred.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)
        except Exception:
            err_msg = 'An unexpected error occurred.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

    def _raise_tls_credential_error(self, message: str) -> None:
        """Raise a TrustpointTlsServerCredentialError with a given message.

        Args:
            message: The error message to include in the exception.
        """
        raise TrustpointTlsServerCredentialError(message)

    def _map_exit_code_to_message(self, return_code: int) -> str:
        """Maps shell script exit codes to user-friendly error messages."""
        error_messages = {
            1: 'State file not found. Ensure Trustpoint is in the correct state.',
            2: 'Multiple state files detected. The wizard state is corrupted.',
            3: 'Failed to create the required TLS directory for Apache.',
            4: 'Failed to clear existing files in the Apache TLS directory.',
            5: 'Failed to copy Trustpoint TLS files to the Apache directory.',
            6: 'Failed to remove existing Apache sites from sites-enabled.',
            7: 'Failed to copy HTTP config to Apache sites-available.',
            8: 'Failed to copy HTTP config to Apache sites-enabled.',
            9: 'Failed to copy HTTPS config to Apache sites-available.',
            10: 'Failed to copy HTTPS config to Apache sites-enabled.',
            11: 'Failed to enable Apache mod_ssl.',
            12: 'Failed to enable Apache mod_rewrite.',
            13: 'Failed to restart Apache gracefully.',
            14: 'Failed to remove the current state file.',
            15: 'Failed to create the next state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred.')

    def _generate_trust_store_response(self, file_format: str) -> HttpResponse:
        """Generate a response containing the trust store in the requested format.

        Args:
            file_format: The desired file format for the trust store (e.g., 'pem', 'pkcs7_der', 'pkcs7_pem').

        Returns:
            HttpResponse: A response with the trust store content or an error message.
        """
        try:
            active_tls_credential_model = ActiveTrustpointTlsServerCredentialModel.objects.get(pk=1)
            trustpoint_tls_server_credential_model = active_tls_credential_model.credential
        except ActiveTrustpointTlsServerCredentialModel.DoesNotExist:
            trustpoint_tls_server_credential_model = None

        if not trustpoint_tls_server_credential_model:
            messages.add_message(self.request, messages.ERROR, 'No trust store available for download.')
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        valid_formats = {'pem', 'pkcs7_der', 'pkcs7_pem'}
        if file_format not in valid_formats:
            messages.add_message(
                self.request,
                messages.ERROR,
                f'Invalid file format requested: {file_format}. Supported formats: {", ".join(valid_formats)}.',
            )
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        try:
            serializer = trustpoint_tls_server_credential_model.certificate.get_certificate_serializer()
            trust_store, content_type = self._get_trust_store_and_content_type(file_format, serializer)
        except Exception:
            err_msg = f'Error generating {file_format} trust store.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        response = HttpResponse(content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="trust_store.{file_format}"'
        response.write(trust_store)
        return response

    @staticmethod
    def _get_trust_store_and_content_type(
        file_format: str, certificate_serializer: CertificateSerializer
    ) -> tuple[str | bytes, str]:
        """Tries to get the certificate in the requested format and adds the corresponding content type.

        Args:
            file_format: The file format requested.
            certificate_serializer: The certificate serializer.

        Returns:
            The tuple of the certificate in the requested format and the content type.
        """
        if file_format == 'pem':
            trust_store = certificate_serializer.as_pem()
            content_type = 'application/x-pem-file'
        elif file_format == 'pkcs7_der':
            trust_store = certificate_serializer.as_pkcs7_der()
            content_type = 'application/pkcs7-mime'
        elif file_format == 'pkcs7_pem':
            trust_store = certificate_serializer.as_pkcs7_pem()
            content_type = 'application/x-pem-file'
        else:
            err_msg = f'Unknown file_format requested: {file_format}'
            raise ValueError(err_msg)

        try:
            return trust_store.decode(), content_type
        except UnicodeDecodeError:
            pass

        return trust_store, content_type

    @staticmethod
    def _write_pem_files(credential_model: CredentialModel) -> None:
        """Writes the private key, certificate, and trust store PEM files to disk.

        Args:
            credential_model (CredentialModel): The credential model instance containing the keys and certificates.
        """
        private_key_pem = credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
        certificate_pem = credential_model.get_certificate_serializer().as_pem().decode()
        trust_store_pem = credential_model.get_certificate_chain_serializer().as_pem().decode()

        APACHE_KEY_PATH.write_text(private_key_pem)
        APACHE_CERT_PATH.write_text(certificate_pem)
        APACHE_CERT_CHAIN_PATH.write_text(trust_store_pem)

class SetupWizardTlsServerCredentialApplyCancelView(LoggerMixin, View):
    """View for handling the cancellation of TLS Server Credential application.

    Attributes:
        http_method_names: Allowed HTTP methods for this view.
    """

    http_method_names = ('get',)

    def get(self, request: HttpRequest) -> HttpResponse:
        """Handle GET requests for the TLS Server Credential import view.

        Args:
            request: The HTTP request object.

        Returns:
            HttpResponse: A redirect to the next step or an error response.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return self._clear_credential_and_certificate_data_and_execute(request)

    def _clear_credential_and_certificate_data_and_execute(self, request: HttpRequest) -> HttpResponse:
        """Clear the credential and certificate data and executes the corresponding action suing a shell script.

        Args:
            request: The HTTP request object.
        """
        try:
            self._clear_credential_and_certificate_data()

            execute_shell_script(SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL)

            messages.add_message(request, messages.INFO, 'Generation of the TLS-Server credential canceled.')
            return redirect('setup_wizard:setup_mode', permanent=False)

        except subprocess.CalledProcessError as exception:
            err_msg = (
                f'Cancel script failed with exit code {exception.returncode}: '
                f'{self._map_exit_code_to_message(exception.returncode)}'
            )
            messages.add_message(request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        except FileNotFoundError:
            err_msg = f'Cancel script not found: {SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL}'
            messages.add_message(request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        except ProtectedError:
            err_msg = 'Could not clear certificates/credentials from DB.'
            messages.add_message(request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        except Exception:
            err_msg = 'An unexpected error occurred.'
            messages.add_message(request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

    def _clear_credential_and_certificate_data(self) -> None:
        """Clears all credential and certificate data if canceled in the 'WIZARD_TLS_SERVER_CREDENTIAL_APPLY' state."""
        IssuingCaModel.objects.all().delete()
        CredentialModel.objects.all().delete()
        #ActiveTrustpointTlsServerCredentialModel.objects.all().delete()  # noqa: ERA001
        CertificateModel.objects.all().delete()

    def _map_exit_code_to_message(self, return_code: int) -> str:
        """Maps shell script exit codes to user-friendly error messages."""
        error_messages = {
            1: "The state file for 'WIZARD_TLS_SERVER_CREDENTIAL_APPLY' was not found. Ensure Trustpoint "
            'is in the correct state.',
            2: 'Multiple state files were detected, indicating a corrupted wizard state. '
            'Please resolve the inconsistency.',
            3: "Failed to remove the current 'WIZARD_TLS_SERVER_CREDENTIAL_APPLY' state file. Check file permissions.",
            4: "Failed to create the 'WIZARD_INITIAL' state file. Ensure the directory is writable and "
            'permissions are set correctly.',
        }
        return error_messages.get(return_code, 'An unknown error occurred during the cancel operation.')

class SetupWizardDemoDataView(LoggerMixin, FormView[EmptyForm]):
    """View for handling the demo data setup during the setup wizard.

    This view allows the user to either add demo data to the database or proceed without
    it. It validates the current wizard state and transitions to the next state upon
    successful completion.
    """

    http_method_names = ('get', 'post')
    form_class = EmptyForm
    template_name = 'setup_wizard/demo_data.html'
    success_url = reverse_lazy('setup_wizard:create_super_user')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_DEMO_DATA:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: EmptyForm) -> HttpResponse:
        """Handle form submission for demo data setup."""
        try:
            if 'without-demo-data' in self.request.POST:
                messages.add_message(self.request, messages.INFO, 'Setup Trustpoint with no demo data')
                self._execute_notifications()
                execute_shell_script(SCRIPT_WIZARD_DEMO_DATA)
            elif 'with-demo-data' in self.request.POST:
                messages.add_message(self.request, messages.INFO, 'Setup Trustpoint with demo data')
                self._add_demo_data()
                self._execute_notifications()
                execute_shell_script(SCRIPT_WIZARD_DEMO_DATA)
            else:
                messages.add_message(self.request, messages.ERROR, 'Invalid option selected for demo data setup.')
                return redirect('setup_wizard:demo_data', permanent=False)

            call_command('execute_all_notifications')

        except subprocess.CalledProcessError as exception:
            err_msg = (
                f'Demo data script failed with exit code {exception.returncode}: '
                f'{self._map_exit_code_to_message(exception.returncode)}'
            )
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:demo_data', permanent=False)
        except FileNotFoundError:
            err_msg = f'Demo data script not found: {SCRIPT_WIZARD_DEMO_DATA}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:demo_data', permanent=False)
        except ValueError:
            err_msg = 'Value error occurred.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:demo_data', permanent=False)
        except Exception:
            err_msg = 'An unexpected error occurred.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:demo_data', permanent=False)

        return super().form_valid(form)

    def _add_demo_data(self) -> None:
        """Add demo data to the database."""
        try:
            call_command('add_domains_and_devices')
        except Exception as e:
            err_msg = f'Error adding demo data: {e}'
            raise ValueError(err_msg) from e

    def _execute_notifications(self) -> None:
        """Creating notifications."""
        try:
            call_command('execute_all_notifications')
        except Exception as e:
            err_msg = f'Error executing notifications: {e}'
            raise ValueError(err_msg) from e

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages.

        Args:
            return_code: The exit code returned by the script.

        Returns:
            str: A descriptive error message corresponding to the exit code.
        """
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_DEMO_DATA state.',
            2: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            3: 'Failed to remove the WIZARD_DEMO_DATA state file.',
            4: 'Failed to create WIZARD_CREATE_SUPER_USER state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred while executing the demo data script.')


class SetupWizardCreateSuperUserView(LoggerMixin, FormView[UserCreationForm[User]]):
    """View for handling the creation of a superuser during the setup wizard.

    This view is part of the setup wizard process. It allows an admin to create a
    superuser account, ensuring that the application has at least one administrative
    user configured. The view validates the input using the `UserCreationForm`
    and transitions the wizard state upon successful completion.
    """

    http_method_names = ('get', 'post')
    form_class = UserCreationForm
    template_name = 'setup_wizard/create_super_user.html'
    success_url = reverse_lazy('users:login')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_CREATE_SUPER_USER:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: UserCreationForm[User]) -> HttpResponse:
        """Handle form submission for creating a superuser.

        Args:
            form: The form containing the data for the superuser creation.

        Returns:
            HttpResponseRedirect: Redirect to the next step or login page.
        """
        try:
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            call_command('createsuperuser', interactive=False, username=username, email='')

            user = User.objects.get(username=username)
            user.set_password(password)
            user.save()
            messages.add_message(self.request, messages.SUCCESS, 'Successfully created super-user.')

            execute_shell_script(SCRIPT_WIZARD_CREATE_SUPER_USER)
        except User.DoesNotExist as e:
            messages.add_message(self.request, messages.ERROR, f'User not found error: {e}')
            return redirect('setup_wizard:create_super_user', permanent=False)
        except subprocess.CalledProcessError as e:
            messages.add_message(
                self.request,
                messages.ERROR,
                f'Create superuser script failed with exit code {e.returncode}: '
                f'{self._map_exit_code_to_message(e.returncode)}',
            )
            return redirect('setup_wizard:create_super_user', permanent=False)
        except FileNotFoundError:
            err_msg = f'Create superuser script not found: {SCRIPT_WIZARD_CREATE_SUPER_USER}'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:create_super_user', permanent=False)
        except ValueError:
            err_msg = 'Value error occurred.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:create_super_user', permanent=False)
        except Exception:
            err_msg = 'An unexpected error occurred.'
            messages.add_message(self.request, messages.ERROR, err_msg)
            self.logger.exception(err_msg)
            return redirect('setup_wizard:create_super_user', permanent=False)

        return super().form_valid(form)

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_CREATE_SUPER_USER state.',
            2: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            3: 'Failed to remove the WIZARD_CREATE_SUPER_USER state file.',
            4: 'Failed to create the WIZARD_COMPLETED state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred while executing the create superuser script.')
