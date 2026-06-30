"""This module contains forms for the setup wizard app."""

from __future__ import annotations

import contextlib
import ipaddress
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast, override

from django import forms
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy

from .models import SetupWizardConfigModel
from .pkcs11_local_dev import local_dev_pkcs11_handoff_available, local_dev_pkcs11_module_path
from .pkcs11_staging import existing_wizard_pkcs11_staged_file
from .tls_credential import extract_staged_tls_sans, staged_tls_common_name

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from django.utils.functional import Promise

FINAL_WIZARD_PKCS11_MODULE_PATH = Path(settings.HSM_LIB_DIR) / 'uploaded-pkcs11-module.so'
FINAL_WIZARD_PKCS11_PIN_PATH = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
FINAL_WIZARD_PKCS11_CONFIG_PATH = Path(settings.HSM_CONFIG_DIR) / 'uploaded-pkcs11-provider.cfg'

MIN_TCP_PORT = 1
MAX_TCP_PORT = 65535
ELF_MAGIC = b'\x7fELF'

CRYPTO_STORAGE_OPTION_DESCRIPTIONS = {
    str(SetupWizardConfigModel.CryptoStorageType.SoftwareStorage): gettext_lazy(
        'Use the built-in software backend.'
    ),
    str(SetupWizardConfigModel.CryptoStorageType.HsmStorage): gettext_lazy(
        'Use the PKCS#11 backend with a configured HSM, SoftHSM, or PKCS#11 proxy/module.'
    ),
    str(SetupWizardConfigModel.CryptoStorageType.RestBackend): gettext_lazy(
        'Planned backend type for future remote crypto integrations. Visible here for roadmap transparency, but not '
        'usable yet.'
    ),
}

CRYPTO_BACKEND_TYPE_CHOICES = (
    (SetupWizardConfigModel.CryptoStorageType.SoftwareStorage, gettext_lazy('Software Backend')),
    (SetupWizardConfigModel.CryptoStorageType.HsmStorage, gettext_lazy('PKCS#11 Backend')),
    (SetupWizardConfigModel.CryptoStorageType.RestBackend, gettext_lazy('REST Backend')),
)

DEMO_DATA_OPTION_DESCRIPTIONS = {
    'True': gettext_lazy('Populate the installation with demo content to make evaluation and testing easier.'),
    'False': gettext_lazy('Start with an empty system and configure all operational data manually.'),
}

TLS_CONFIG_OPTION_DESCRIPTIONS = {
    'generate': gettext_lazy('Generate a new TLS server credential from IP addresses and DNS names.'),
    'pkcs12': gettext_lazy('Upload an existing TLS server credential as a PKCS#12 bundle.'),
    'separate_files': gettext_lazy('Upload certificate and private key as separate files.'),
}

TLS_CONFIG_TYPE_CHOICES = tuple(
    (choice.value, choice.label) for choice in SetupWizardConfigModel.FreshInstallTlsConfigType
)

MAX_DNS_NAME_LENGTH = 253


def _safe_existing_file(path: Path) -> Path | None:
    """Return the path when it exists as a file without leaking OS errors."""
    try:
        if path.is_file():
            return path
    except OSError:
        return None
    return None


def _safe_existing_file_from_value(path_value: object) -> Path | None:
    """Return an existing file from a string-like path value."""
    normalized_path = str(path_value or '').strip()
    if not normalized_path:
        return None
    return _safe_existing_file(Path(normalized_path))


class EmptyForm(forms.Form):
    """A form without any fields."""


class WizardCardRadioSelect(forms.RadioSelect):
    """RadioSelect that attaches description text to each option."""

    def __init__(
        self,
        attrs: dict[str, Any] | None = None,
        choices: Iterable[tuple[Any, Any] | tuple[str, Iterable[tuple[Any, Any]]]] = (),
        *,
        descriptions: Mapping[str, str | Promise] | None = None,
        disabled_values: set[str] | None = None,
    ) -> None:
        """Initialize the widget.

        Args:
            attrs: HTML attributes for the widget.
            choices: Choice values rendered by the radio widget.
            descriptions: Mapping from choice value to explanation text.
            disabled_values: Choice values that should render disabled.
        """
        self.descriptions = descriptions or {}
        self.disabled_values = {str(value) for value in disabled_values or set()}
        super().__init__(attrs=attrs, choices=choices)

    @override
    def create_option(
        self,
        name: str,
        value: object,
        label: str | int,
        selected: bool,
        index: int,
        subindex: int | None = None,
        attrs: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Build a choice option and attach its description text."""
        option = super().create_option(name, value, label, selected, index, subindex=subindex, attrs=attrs)
        option_attrs = cast('dict[str, object]', option['attrs'])
        is_disabled = str(value) in self.disabled_values
        if is_disabled:
            option_attrs['disabled'] = True
            option_attrs['aria-disabled'] = 'true'
        option['description'] = self.descriptions.get(str(value), '')
        option['disabled'] = is_disabled
        return option


class MultipleFileInput(forms.ClearableFileInput):
    """File input widget that allows selecting multiple files."""

    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    """File field that returns a list of uploaded files."""

    widget = MultipleFileInput

    def clean(self, data: object, initial: object = None) -> list[object]:
        """Validate and normalize one or more uploaded files."""
        single_clean = super().clean
        if isinstance(data, (list, tuple)):
            return [single_clean(item, initial) for item in data]
        if not data:
            return []
        return [single_clean(data, initial)]


class FreshInstallModelBaseForm(forms.ModelForm[SetupWizardConfigModel]):
    """Base ModelForm for setup-wizard steps backed by SetupWizardConfigModel."""

    class Meta:
        """Shared ModelForm configuration for setup-wizard model-backed forms."""

        model = SetupWizardConfigModel
        fields: tuple[str, ...] = ()


def _software_backend_available_in_wizard() -> bool:
    """Return whether the software backend may be configured."""
    return True


def _pkcs11_backend_available_in_wizard() -> bool:
    """Return whether the PKCS#11 backend may be configured in the wizard."""
    return True


class FreshInstallAdminUserModelForm(FreshInstallModelBaseForm):
    """Form for staging the first operational administrator."""

    password1 = forms.CharField(
        label=gettext_lazy('Password'),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )
    password2 = forms.CharField(
        label=gettext_lazy('Password confirmation'),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )

    class Meta:
        """ModelForm configuration for the operational admin user step."""

        model = SetupWizardConfigModel
        fields = ('operational_admin_username', 'operational_admin_email')
        labels: ClassVar[dict[str, str | Promise]] = {
            'operational_admin_username': gettext_lazy('Admin username'),
            'operational_admin_email': gettext_lazy('Admin email'),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Style the admin-user fields."""
        super().__init__(*args, **kwargs)
        self.is_admin_user_config = True
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-control')

    def clean_operational_admin_username(self) -> str:
        """Normalize and require the operational admin username."""
        username = (self.cleaned_data.get('operational_admin_username') or '').strip()
        if not username:
            err_msg = gettext_lazy('Enter the operational admin username.')
            raise forms.ValidationError(err_msg)
        return username

    def clean(self) -> dict[str, Any]:
        """Validate the staged operational admin password."""
        cleaned_data = super().clean() or {}
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            self.add_error('password2', gettext_lazy('The two password fields did not match.'))
        if password1:
            try:
                validate_password(password1)
            except DjangoValidationError as exc:
                self.add_error('password1', exc)
        return cleaned_data

    @override
    def save(self, commit: bool = True) -> SetupWizardConfigModel:
        """Persist the staged admin fields and password hash."""
        instance = super().save(commit=False)
        instance.operational_admin_password_hash = make_password(self.cleaned_data['password1'])
        if commit:
            instance.save()
        return instance


class FreshInstallDatabaseModelForm(FreshInstallModelBaseForm):
    """Form for staging the operational PostgreSQL connection."""

    class Meta:
        """ModelForm configuration for the operational database step."""

        model = SetupWizardConfigModel
        fields = (
            'operational_db_host',
            'operational_db_port',
            'operational_db_name',
            'operational_db_user',
            'operational_db_password',
        )
        labels: ClassVar[dict[str, str | Promise]] = {
            'operational_db_host': gettext_lazy('PostgreSQL host'),
            'operational_db_port': gettext_lazy('PostgreSQL port'),
            'operational_db_name': gettext_lazy('Database name'),
            'operational_db_user': gettext_lazy('Database user'),
            'operational_db_password': gettext_lazy('Database password'),
        }
        widgets: ClassVar[dict[str, forms.Widget]] = {
            'operational_db_password': forms.PasswordInput(render_value=True),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Style the database fields."""
        super().__init__(*args, **kwargs)
        self.is_database_config = True
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-control')

    def clean_operational_db_host(self) -> str:
        """Normalize and require the PostgreSQL host."""
        value = (self.cleaned_data.get('operational_db_host') or '').strip()
        if not value:
            raise forms.ValidationError(gettext_lazy('Enter the PostgreSQL host name or IP address.'))
        return value

    def clean_operational_db_name(self) -> str:
        """Normalize and require the PostgreSQL database name."""
        value = (self.cleaned_data.get('operational_db_name') or '').strip()
        if not value:
            raise forms.ValidationError(gettext_lazy('Enter the PostgreSQL database name.'))
        return value

    def clean_operational_db_port(self) -> int:
        """Validate the PostgreSQL TCP port."""
        value = self.cleaned_data['operational_db_port']
        if not isinstance(value, int):
            raise forms.ValidationError(gettext_lazy('Enter a valid TCP port.'))
        if value < MIN_TCP_PORT or value > MAX_TCP_PORT:
            raise forms.ValidationError(gettext_lazy('Enter a TCP port between 1 and 65535.'))
        return value

    def clean_operational_db_user(self) -> str:
        """Normalize and require the PostgreSQL user."""
        value = (self.cleaned_data.get('operational_db_user') or '').strip()
        if not value:
            raise forms.ValidationError(gettext_lazy('Enter the PostgreSQL user name.'))
        return value


class FreshInstallCryptoStorageModelForm(FreshInstallModelBaseForm):
    """Form for selecting the cryptographic storage backend during setup."""

    class Meta:
        """ModelForm configuration for the storage step."""

        model = SetupWizardConfigModel
        fields = ('crypto_storage',)
        widgets: ClassVar[dict[str, forms.Widget]] = {
            'crypto_storage': WizardCardRadioSelect(
                descriptions=CRYPTO_STORAGE_OPTION_DESCRIPTIONS,
            ),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Disable backend choices that are not available in the current environment."""
        super().__init__(*args, **kwargs)
        self.is_crypto_storage_config = True
        crypto_storage_field = cast('forms.ChoiceField', self.fields['crypto_storage'])
        crypto_storage_field.choices = CRYPTO_BACKEND_TYPE_CHOICES

        widget = cast('WizardCardRadioSelect', crypto_storage_field.widget)
        disabled_values: set[str] = set()
        if not _software_backend_available_in_wizard():
            disabled_values.add(str(SetupWizardConfigModel.CryptoStorageType.SoftwareStorage))
        if not _pkcs11_backend_available_in_wizard():
            disabled_values.add(str(SetupWizardConfigModel.CryptoStorageType.HsmStorage))
        disabled_values.add(str(SetupWizardConfigModel.CryptoStorageType.RestBackend))
        widget.disabled_values = disabled_values

    def clean_crypto_storage(self) -> SetupWizardConfigModel.CryptoStorageType:
        """Reject backend choices that are currently unavailable in the wizard."""
        crypto_storage = cast('SetupWizardConfigModel.CryptoStorageType', self.cleaned_data['crypto_storage'])
        if int(crypto_storage) == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage:
            if not _software_backend_available_in_wizard():
                err_msg = gettext_lazy('The software backend is not available in this environment.')
                raise forms.ValidationError(err_msg)
            return crypto_storage
        if int(crypto_storage) == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            if not _pkcs11_backend_available_in_wizard():
                err_msg = gettext_lazy('The PKCS#11 crypto backend is currently unavailable.')
                raise forms.ValidationError(err_msg)
            return crypto_storage
        if int(crypto_storage) == SetupWizardConfigModel.CryptoStorageType.RestBackend:
            err_msg = gettext_lazy('The REST crypto backend is not implemented yet.')
            raise forms.ValidationError(err_msg)
        err_msg = gettext_lazy('Unsupported crypto backend selection.')
        raise forms.ValidationError(err_msg)


class FreshInstallBackendConfigModelForm(FreshInstallModelBaseForm):
    """Form for configuring the selected backend during setup."""

    pkcs11_module_upload = forms.FileField(
        required=False,
        label=gettext_lazy('PKCS#11 library upload'),
        help_text=gettext_lazy('Upload the PKCS#11 shared library that Trustpoint should install for this instance.'),
    )
    pkcs11_user_pin = forms.CharField(
        required=False,
        label=gettext_lazy('User PIN'),
        strip=False,
        help_text=gettext_lazy(
            'Enter the user PIN once. Trustpoint creates the protected user-pin.txt file during setup.'
        ),
        widget=forms.PasswordInput(
            attrs={
                'autocomplete': 'new-password',
                'placeholder': 'Enter the PKCS#11 user PIN',
            }
        ),
    )
    pkcs11_config_upload = forms.FileField(
        required=False,
        label=gettext_lazy('Provider config file'),
        help_text=gettext_lazy(
            'Optional. Upload the PKCS#11 provider configuration file when the selected module requires one.'
        ),
    )
    pkcs11_config_env_var = forms.CharField(
        required=False,
        label=gettext_lazy('Provider config env var'),
        initial='',
        help_text=gettext_lazy(
            'Environment variable used by this PKCS#11 module to find the uploaded provider config file.'
        ),
    )
    MAX_PKCS11_LIBRARY_UPLOAD_BYTES = 32 * 1024 * 1024
    MAX_PKCS11_CONFIG_UPLOAD_BYTES = 256 * 1024

    class Meta:
        """ModelForm configuration for the backend-config step."""

        model = SetupWizardConfigModel
        fields = (
            'fresh_install_pkcs11_token_label',
            'fresh_install_pkcs11_slot_id',
            'fresh_install_pkcs11_enforce_app_secret_protection',
        )
        labels: ClassVar[dict[str, str | Promise]] = {
            'fresh_install_pkcs11_token_label': gettext_lazy('Token label'),
            'fresh_install_pkcs11_slot_id': gettext_lazy('Slot ID (optional)'),
            'fresh_install_pkcs11_enforce_app_secret_protection': gettext_lazy(
                'Require HSM protection for application secrets'
            ),
        }
        help_texts: ClassVar[dict[str, str | Promise]] = {
            'fresh_install_pkcs11_token_label': gettext_lazy(
                'Enter the token label that Trustpoint should use when selecting the PKCS#11 token. '
                'Leave empty when selecting by slot ID only.'
            ),
            'fresh_install_pkcs11_slot_id': gettext_lazy(
                'Optional PKCS#11 slot ID. Use this when the provider token label cannot be resolved reliably.'
            ),
            'fresh_install_pkcs11_enforce_app_secret_protection': '',
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Adjust the visible fields to the currently selected backend."""
        super().__init__(*args, **kwargs)
        selected_backend = getattr(
            self.instance, 'crypto_storage', SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
        )
        self.is_pkcs11_backend_config = selected_backend == SetupWizardConfigModel.CryptoStorageType.HsmStorage
        self.is_software_backend_config = selected_backend == SetupWizardConfigModel.CryptoStorageType.SoftwareStorage
        self.local_dev_pkcs11_handoff_available = self.is_pkcs11_backend_config and local_dev_pkcs11_handoff_available()

        if selected_backend != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            for field_name in (
                'pkcs11_module_upload',
                'pkcs11_config_upload',
                'pkcs11_config_env_var',
                'fresh_install_pkcs11_token_label',
                'fresh_install_pkcs11_slot_id',
                'pkcs11_user_pin',
                'fresh_install_pkcs11_enforce_app_secret_protection',
            ):
                self.fields[field_name].widget = forms.HiddenInput()
                self.fields[field_name].required = False
            return

        self.fields['pkcs11_module_upload'].widget.attrs.update({'class': 'form-control'})
        self.fields['pkcs11_config_upload'].widget.attrs.update({'class': 'form-control'})
        self.fields['pkcs11_config_env_var'].widget.attrs.update(
            {
                'class': 'form-control',
                'placeholder': 'PKCS11_CONFIG',
            }
        )
        self.fields['fresh_install_pkcs11_token_label'].widget.attrs.update(
            {
                'class': 'form-control',
                'placeholder': 'Trustpoint-SoftHSM',
            }
        )
        self.fields['fresh_install_pkcs11_slot_id'].widget.attrs.update(
            {
                'class': 'form-control',
                'placeholder': '1',
            }
        )
        self.fields['fresh_install_pkcs11_enforce_app_secret_protection'].widget.attrs.update(
            {'class': 'form-check-input'}
        )
        self.fields['pkcs11_user_pin'].widget.attrs.update({'class': 'form-control'})
        self._apply_pkcs11_defaults()

    def _apply_pkcs11_defaults(self) -> None:
        """Prefill the PKCS#11 step with staged values or current installation defaults."""
        self.initial['fresh_install_pkcs11_token_label'] = (
            self.instance.fresh_install_pkcs11_token_label or getattr(settings, 'HSM_DEFAULT_TOKEN_LABEL', '')
        )
        self.initial['fresh_install_pkcs11_slot_id'] = self.instance.fresh_install_pkcs11_slot_id
        self.initial['pkcs11_config_env_var'] = self.instance.fresh_install_pkcs11_config_env_var
        self.staged_pkcs11_module_name = self._staged_pkcs11_module_name()
        self.has_staged_pkcs11_pin = (
            existing_wizard_pkcs11_staged_file(self.instance.fresh_install_pkcs11_auth_source_ref) is not None
        )
        self.has_existing_pkcs11_pin = self._existing_pkcs11_pin_file() is not None
        self.staged_pkcs11_config_name = self._staged_pkcs11_config_name()

    def refresh_pkcs11_state(self) -> None:
        """Refresh public PKCS#11 helper attributes after staging files changed."""
        self._apply_pkcs11_defaults()

    def _existing_local_dev_pkcs11_module_file(self) -> Path | None:
        """Return the local development PKCS#11 module file when this wizard uses it."""
        if not self.local_dev_pkcs11_handoff_available:
            return None

        local_dev_module = local_dev_pkcs11_module_path()
        if str(self.instance.fresh_install_pkcs11_module_path).strip() != str(local_dev_module):
            return None

        return _safe_existing_file(local_dev_module)

    def _existing_pkcs11_module_file(self) -> Path | None:
        """Return the currently staged or installed PKCS#11 module file for this wizard state."""
        staged_module = existing_wizard_pkcs11_staged_file(self.instance.fresh_install_pkcs11_module_path)
        if staged_module is not None:
            return staged_module

        local_dev_module = self._existing_local_dev_pkcs11_module_file()
        if local_dev_module is not None:
            return local_dev_module

        configured_module = _safe_existing_file_from_value(self.instance.fresh_install_pkcs11_module_path)
        if configured_module is not None:
            return configured_module

        return _safe_existing_file(FINAL_WIZARD_PKCS11_MODULE_PATH)

    def _existing_pkcs11_pin_file(self) -> Path | None:
        """Return the currently staged or installed PKCS#11 user PIN file for this wizard state."""
        staged_pin = existing_wizard_pkcs11_staged_file(self.instance.fresh_install_pkcs11_auth_source_ref)
        if staged_pin is not None:
            return staged_pin

        configured_pin = _safe_existing_file_from_value(self.instance.fresh_install_pkcs11_auth_source_ref)
        if configured_pin is not None:
            return configured_pin

        return _safe_existing_file(FINAL_WIZARD_PKCS11_PIN_PATH)

    def _existing_pkcs11_config_file(self) -> Path | None:
        """Return the currently staged or installed PKCS#11 provider config file for this wizard state."""
        staged_config = existing_wizard_pkcs11_staged_file(self.instance.fresh_install_pkcs11_config_path)
        if staged_config is not None:
            return staged_config

        configured_config = _safe_existing_file_from_value(self.instance.fresh_install_pkcs11_config_path)
        if configured_config is not None:
            return configured_config

        return _safe_existing_file(FINAL_WIZARD_PKCS11_CONFIG_PATH)

    def _staged_pkcs11_module_name(self) -> str | None:
        """Return the current wizard PKCS#11 module filename when one is available."""
        module_file = self._existing_pkcs11_module_file()
        if module_file is None:
            return None
        return module_file.name

    def _staged_pkcs11_config_name(self) -> str | None:
        """Return the current wizard PKCS#11 provider config filename when one is available."""
        config_file = self._existing_pkcs11_config_file()
        if config_file is None:
            return None
        return config_file.name

    def clean_fresh_install_pkcs11_token_label(self) -> str:
        """Normalize the optional PKCS#11 token label."""
        if self.instance.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            return ''
        return (self.cleaned_data.get('fresh_install_pkcs11_token_label') or '').strip()

    def clean_fresh_install_pkcs11_slot_id(self) -> int | None:
        """Normalize the optional PKCS#11 slot ID."""
        if self.instance.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            return None
        slot_id = self.cleaned_data.get('fresh_install_pkcs11_slot_id')
        if slot_id is None:
            return None
        if int(slot_id) < 0:
            err_msg = gettext_lazy('Enter a non-negative PKCS#11 slot ID.')
            raise forms.ValidationError(err_msg)
        return int(slot_id)

    def clean_fresh_install_pkcs11_enforce_app_secret_protection(self) -> bool:
        """Return whether setup must enforce HSM-backed application-secret protection."""
        if self.instance.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            return False
        return bool(self.cleaned_data.get('fresh_install_pkcs11_enforce_app_secret_protection'))

    def _validate_pkcs11_module_upload(self, uploaded_module: Any) -> None:
        """Validate the uploaded PKCS#11 shared library."""
        if uploaded_module is None:
            return

        filename = str(getattr(uploaded_module, 'name', '') or '')
        if not filename:
            err_msg = gettext_lazy('Upload a PKCS#11 shared library.')
            raise forms.ValidationError(err_msg)
        if '.so' not in filename.lower():
            err_msg = gettext_lazy('Upload a Linux PKCS#11 shared library file ending in .so or .so.*.')
            raise forms.ValidationError(err_msg)

        size = getattr(uploaded_module, 'size', None)
        if size is not None and size > self.MAX_PKCS11_LIBRARY_UPLOAD_BYTES:
            err_msg = gettext_lazy('The uploaded PKCS#11 library is too large.')
            raise forms.ValidationError(err_msg)

        try:
            header = uploaded_module.read(len(ELF_MAGIC))
        except (AttributeError, OSError):
            header = b''
        finally:
            with contextlib.suppress(AttributeError, OSError):
                uploaded_module.seek(0)

        if header and header != ELF_MAGIC:
            err_msg = gettext_lazy('Upload a valid Linux ELF shared library.')
            raise forms.ValidationError(err_msg)

    def _validate_pkcs11_config_upload(self, uploaded_config: Any) -> None:
        """Validate an optional provider PKCS#11 config upload."""
        if uploaded_config is None:
            return
        if getattr(uploaded_config, 'size', 0) > self.MAX_PKCS11_CONFIG_UPLOAD_BYTES:
            err_msg = gettext_lazy('The uploaded provider config file is too large.')
            raise forms.ValidationError(err_msg)

    def clean_pkcs11_config_env_var(self) -> str:
        """Normalize the optional provider config env-var name."""
        value = str(self.cleaned_data.get('pkcs11_config_env_var') or '').strip()
        if not value:
            return ''
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value):
            err_msg = gettext_lazy('Enter a valid environment variable name.')
            raise forms.ValidationError(err_msg)
        return value

    def clean(self) -> dict[str, Any]:
        """Validate the staged backend configuration."""
        cleaned_data = super().clean() or {}
        if self.instance.crypto_storage != SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            return cleaned_data

        module_upload = cleaned_data.get('pkcs11_module_upload')
        config_upload = cleaned_data.get('pkcs11_config_upload')
        config_env_var = str(cleaned_data.get('pkcs11_config_env_var') or '').strip()
        user_pin = cleaned_data.get('pkcs11_user_pin') or ''
        existing_module = self._existing_pkcs11_module_file()
        existing_pin = self._existing_pkcs11_pin_file()
        existing_config = self._existing_pkcs11_config_file()
        token_label = cleaned_data.get('fresh_install_pkcs11_token_label') or ''
        slot_id = cleaned_data.get('fresh_install_pkcs11_slot_id')

        try:
            self._validate_pkcs11_module_upload(module_upload)
        except forms.ValidationError as exception:
            self.add_error('pkcs11_module_upload', exception)
        try:
            self._validate_pkcs11_config_upload(config_upload)
        except forms.ValidationError as exception:
            self.add_error('pkcs11_config_upload', exception)

        if (config_upload is not None or existing_config is not None) and not config_env_var:
            self.add_error(
                'pkcs11_config_env_var',
                gettext_lazy('Enter the environment variable expected by this PKCS#11 provider config file.'),
            )

        if (
            module_upload is None
            and existing_module is None
            and not self.local_dev_pkcs11_handoff_available
        ):
            self.add_error(
                'pkcs11_module_upload',
                gettext_lazy('Upload a PKCS#11 library.'),
            )
        if not user_pin and existing_pin is None:
            self.add_error(
                'pkcs11_user_pin',
                gettext_lazy('Enter the PKCS#11 user PIN.'),
            )
        if not token_label and slot_id is None:
            self.add_error(
                'fresh_install_pkcs11_token_label',
                gettext_lazy('Enter a PKCS#11 token label or a slot ID.'),
            )
        return cleaned_data


class RestoreBackupImportForm(forms.Form):
    """Lightweight restore-wizard form for staging a backup archive."""

    backup_archive = forms.FileField(
        required=False,
        label=gettext_lazy('Backup archive'),
        help_text=gettext_lazy(
            'Upload a Trustpoint PostgreSQL backup archive as .dump, .dump.gz, a Trustpoint .zip bundle, '
            'or a GPG-encrypted variant.'
        ),
    )
    backup_archive_password = forms.CharField(
        required=False,
        label=gettext_lazy('Backup password'),
        help_text=gettext_lazy('Optional. Required only for password-encrypted GPG backup archives.'),
        widget=forms.PasswordInput(render_value=True),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize upload styling and remember any already staged archive."""
        self.config_model = kwargs.pop('config_model', None)
        super().__init__(*args, **kwargs)
        self.fields['backup_archive'].widget.attrs.setdefault('class', 'form-control')
        self.fields['backup_archive_password'].widget.attrs.setdefault('class', 'form-control')
        self.staged_backup_name = ''
        if self.config_model is not None:
            original_name = getattr(self.config_model, 'restore_backup_archive_original_name', '')
            archive_path = getattr(self.config_model, 'restore_backup_archive_path', '')
            self.staged_backup_name = original_name or (Path(archive_path).name if archive_path else '')

    def clean_backup_archive(self) -> Any:
        """Require a first archive upload and only accept supported PostgreSQL backup suffixes."""
        backup_archive = self.cleaned_data.get('backup_archive')
        if backup_archive is None:
            if self.staged_backup_name:
                return None
            raise forms.ValidationError(gettext_lazy('Upload a Trustpoint backup archive.'))

        filename = str(getattr(backup_archive, 'name', '')).lower()
        valid_suffixes = ('.dump', '.dump.gz', '.zip', '.dump.gpg', '.dump.gz.gpg', '.zip.gpg', '.gpg')
        if not filename.endswith(valid_suffixes):
            raise forms.ValidationError(
                gettext_lazy('Upload a .dump, .dump.gz, .zip, .dump.gpg, .dump.gz.gpg, or .zip.gpg backup archive.')
            )
        return backup_archive


class FreshInstallDemoDataModelForm(FreshInstallModelBaseForm):
    """Form for selecting whether demo data should be injected during setup."""

    inject_demo_data = forms.TypedChoiceField(
        label=gettext_lazy('Inject demo data'),
        choices=(
            (True, gettext_lazy('Yes')),
            (False, gettext_lazy('No')),
        ),
        coerce=lambda value: value in (True, 'True', 'true', '1', 1),
        widget=WizardCardRadioSelect(descriptions=DEMO_DATA_OPTION_DESCRIPTIONS),
        empty_value=None,
    )

    class Meta:
        """ModelForm configuration for the demo-data step."""

        model = SetupWizardConfigModel
        fields = ('inject_demo_data',)


class FreshInstallSummaryModelForm(FreshInstallModelBaseForm):
    """Read-only summary form for the final fresh-install step."""

    operational_admin = forms.CharField(
        label=gettext_lazy('Operational Admin'),
        required=False,
        disabled=True,
    )
    operational_database = forms.CharField(
        label=gettext_lazy('Operational Database'),
        required=False,
        disabled=True,
    )
    storage_selection = forms.CharField(
        label=gettext_lazy('Crypto Backend'),
        required=False,
        disabled=True,
    )
    app_secret_protection = forms.CharField(
        label=gettext_lazy('Application Secret Protection'),
        required=False,
        disabled=True,
    )
    inject_demo_data_selection = forms.CharField(
        label=gettext_lazy('Inject Demo Data'),
        required=False,
        disabled=True,
    )
    tls_server_configuration = forms.CharField(
        label=gettext_lazy('TLS Server Configuration'),
        required=False,
        disabled=True,
    )
    tls_common_name = forms.CharField(
        label=gettext_lazy('TLS Common Name'),
        required=False,
        disabled=True,
    )
    tls_ipv4_addresses = forms.CharField(
        label=gettext_lazy('TLS IPv4 Addresses'),
        required=False,
        disabled=True,
    )
    tls_ipv6_addresses = forms.CharField(
        label=gettext_lazy('TLS IPv6 Addresses'),
        required=False,
        disabled=True,
    )
    tls_dns_names = forms.CharField(
        label=gettext_lazy('TLS DNS Names'),
        required=False,
        disabled=True,
    )

    class Meta:
        """ModelForm configuration for the summary step."""

        model = SetupWizardConfigModel
        fields: tuple[str, ...] = ()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Populate the read-only summary values from the singleton config."""
        super().__init__(*args, **kwargs)

        instance = self.instance
        ipv4_addresses, ipv6_addresses, dns_names = extract_staged_tls_sans()
        storage_choice = cast('SetupWizardConfigModel.CryptoStorageType', instance.crypto_storage)

        self.fields['operational_admin'].initial = instance.operational_admin_username or '-'
        self.fields['operational_database'].initial = (
            f'{instance.operational_db_user}@{instance.operational_db_host}:'
            f'{instance.operational_db_port}/{instance.operational_db_name}'
        )
        self.fields['storage_selection'].initial = dict(CRYPTO_BACKEND_TYPE_CHOICES).get(
            storage_choice,
            instance.get_crypto_storage_display(),
        )
        if (
            storage_choice == SetupWizardConfigModel.CryptoStorageType.HsmStorage
            and instance.fresh_install_pkcs11_enforce_app_secret_protection
        ):
            self.fields['app_secret_protection'].initial = gettext_lazy('PKCS#11 HSM enforced')
        else:
            self.fields['app_secret_protection'].initial = gettext_lazy('Software app-secret backend')
        self.fields['inject_demo_data_selection'].initial = (
            gettext_lazy('Yes') if instance.inject_demo_data else gettext_lazy('No')
        )
        self.fields['tls_server_configuration'].initial = instance.get_fresh_install_tls_mode_display()
        self.fields['tls_common_name'].initial = staged_tls_common_name() or '-'
        self.fields['tls_ipv4_addresses'].initial = self._format_tls_summary_values(
            ipv4_addresses,
            gettext_lazy('No IPv4 Address Configured'),
        )
        self.fields['tls_ipv6_addresses'].initial = self._format_tls_summary_values(
            ipv6_addresses,
            gettext_lazy('No IPv6 Address Configured'),
        )
        self.fields['tls_dns_names'].initial = self._format_tls_summary_values(
            dns_names,
            gettext_lazy('No DNS Names Configured'),
        )

    @staticmethod
    def _format_tls_summary_values(values: list[str], empty_text: str | Promise) -> str | Promise:
        """Format TLS SAN values for display in the summary view."""
        return '\n'.join(values) if values else empty_text


class FreshInstallTlsConfigForm(forms.Form):
    """Form for configuring TLS during the fresh-install wizard."""

    _dns_label_pattern = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')

    tls_mode = forms.ChoiceField(
        label=gettext_lazy('TLS configuration method'),
        choices=TLS_CONFIG_TYPE_CHOICES,
        widget=WizardCardRadioSelect(descriptions=TLS_CONFIG_OPTION_DESCRIPTIONS),
        initial=SetupWizardConfigModel.FreshInstallTlsConfigType.GENERATE,
    )

    ipv4_addresses = forms.CharField(
        label=gettext_lazy('IPv4 addresses'),
        initial='127.0.0.1, ',
        required=False,
        help_text=gettext_lazy('Comma-separated list.'),
    )
    ipv6_addresses = forms.CharField(
        label=gettext_lazy('IPv6 addresses'),
        initial='::1, ',
        required=False,
        help_text=gettext_lazy('Comma-separated list.'),
    )
    domain_names = forms.CharField(
        label=gettext_lazy('DNS names'),
        initial='localhost, ',
        required=False,
        help_text=gettext_lazy('Comma-separated list.'),
    )

    pkcs12_file = forms.FileField(
        label=gettext_lazy('PKCS#12 file'),
        required=False,
        help_text=gettext_lazy('Supported file types: [.p12, .pfx]'),
    )
    pkcs12_password = forms.CharField(
        label=gettext_lazy('PKCS#12 password'),
        required=False,
        help_text=gettext_lazy('Optional, only needed when the PKCS#12 file is encrypted.'),
        widget=forms.PasswordInput(render_value=True),
    )

    tls_server_certificate = forms.FileField(
        label=gettext_lazy('TLS server certificate'),
        required=False,
        help_text=gettext_lazy(
            'Upload exactly one end-entity TLS server certificate file. '
            'This file may also contain part or all of the certificate chain. '
            'Supported file types: [.pem, .crt, .cer, .der, .p7b, .p7c]'
        ),
    )
    further_certificates = MultipleFileField(
        label=gettext_lazy('Further certificates'),
        required=False,
        help_text=gettext_lazy(
            'Optional. Add missing CA certificates here if the TLS server certificate file '
            'does not already contain the full chain up to the root CA. '
            'Supported file types: [.pem, .crt, .cer, .der, .p7b, .p7c]'
        ),
    )
    key_file = forms.FileField(
        label=gettext_lazy('Key file'),
        required=False,
        help_text=gettext_lazy('Supported file types: [.pem, .key, .der, .p12, .pfx]'),
    )
    key_password = forms.CharField(
        label=gettext_lazy('Key password'),
        required=False,
        help_text=gettext_lazy('Optional, only needed when the key file is encrypted.'),
        widget=forms.PasswordInput(render_value=True),
    )

    @staticmethod
    def _parse_comma_separated_values(value: str) -> list[str]:
        """Normalize a comma-separated string into a list of trimmed values."""
        return [item.strip() for item in value.split(',') if item.strip()]

    @classmethod
    def _validate_dns_name(cls, value: str) -> str:
        """Validate and normalize a DNS name.

        Python has no dedicated standard-library DNS validator, so this uses
        the stdlib IDNA codec plus conservative hostname-label checks.
        """
        try:
            normalized_value = value.rstrip('.').encode('idna').decode('ascii').lower()
        except UnicodeError as exception:
            err_msg = gettext_lazy('Contains an invalid DNS name.')
            raise forms.ValidationError(err_msg) from exception

        if not normalized_value or len(normalized_value) > MAX_DNS_NAME_LENGTH:
            err_msg = gettext_lazy('Contains an invalid DNS name.')
            raise forms.ValidationError(err_msg)

        labels = normalized_value.split('.')
        if any(not label or not cls._dns_label_pattern.fullmatch(label) for label in labels):
            err_msg = gettext_lazy('Contains an invalid DNS name.')
            raise forms.ValidationError(err_msg)
        return normalized_value

    def clean_ipv4_addresses(self) -> list[str]:
        """Validate and normalize IPv4 SAN entries."""
        data = self.cleaned_data['ipv4_addresses'].strip()
        if not data:
            return []

        try:
            return [str(ipaddress.IPv4Address(address)) for address in self._parse_comma_separated_values(data)]
        except ipaddress.AddressValueError as exception:
            err_msg = gettext_lazy('Contains an invalid IPv4 address.')
            raise forms.ValidationError(err_msg) from exception

    def clean_ipv6_addresses(self) -> list[str]:
        """Validate and normalize IPv6 SAN entries."""
        data = self.cleaned_data['ipv6_addresses'].strip()
        if not data:
            return []

        try:
            return [str(ipaddress.IPv6Address(address)) for address in self._parse_comma_separated_values(data)]
        except ipaddress.AddressValueError as exception:
            err_msg = gettext_lazy('Contains an invalid IPv6 address.')
            raise forms.ValidationError(err_msg) from exception

    def clean_domain_names(self) -> list[str]:
        """Normalize DNS SAN entries."""
        data = self.cleaned_data['domain_names'].strip()
        if not data:
            return []
        return [self._validate_dns_name(name) for name in self._parse_comma_separated_values(data)]

    def clean(self) -> dict[str, Any]:
        """Validate the field set required for the selected TLS mode."""
        cleaned_data = super().clean() or {}

        tls_mode = cleaned_data.get('tls_mode')

        if tls_mode == SetupWizardConfigModel.FreshInstallTlsConfigType.GENERATE:
            ipv4_addresses = cleaned_data.get('ipv4_addresses')
            ipv6_addresses = cleaned_data.get('ipv6_addresses')
            domain_names = cleaned_data.get('domain_names')
            if not (ipv4_addresses or ipv6_addresses or domain_names):
                err_msg = gettext_lazy('At least one IP address or DNS name is required for generation.')
                raise forms.ValidationError(err_msg)

        elif tls_mode == SetupWizardConfigModel.FreshInstallTlsConfigType.PKCS12:
            if not cleaned_data.get('pkcs12_file'):
                self.add_error('pkcs12_file', gettext_lazy('A PKCS#12 file is required.'))

        elif tls_mode == SetupWizardConfigModel.FreshInstallTlsConfigType.SEPARATE_FILES:
            if not cleaned_data.get('tls_server_certificate'):
                self.add_error('tls_server_certificate', gettext_lazy('A TLS server certificate file is required.'))
            if not cleaned_data.get('key_file'):
                self.add_error('key_file', gettext_lazy('A key file is required.'))

        return cleaned_data


class StartupWizardTlsCertificateForm(forms.Form):
    """The Setup Wizard TLS Certificate Form."""

    ipv4_addresses = forms.CharField(
        label=gettext_lazy('IPv4-Addresses (comma-separated list)'), initial='127.0.0.1, ', required=False
    )
    ipv6_addresses = forms.CharField(
        label=gettext_lazy('IPv6-Addresses (comma-separated list)'), initial='::1, ', required=False
    )
    domain_names = forms.CharField(
        label=gettext_lazy('Domain-Names (comma-separated list)'), initial='localhost, ', required=False
    )

    def clean_ipv4_addresses(self) -> list[ipaddress.IPv4Address]:
        """Splits the IPv4 addresses and returns them as a list of strings.

        Returns:
            A list of the IPv4 addresses or an empty list.

        Raises:
            ValidationError: If it contains a term that is not a valid IPv4 address.
        """
        data = self.cleaned_data['ipv4_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv4Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError as exception:
            err_msg = 'Contains an invalid IPv4-Address.'
            raise forms.ValidationError(err_msg) from exception

    def clean_ipv6_addresses(self) -> list[ipaddress.IPv6Address]:
        """Splits the IPv6 addresses and returns them as a list of strings.

        Returns:
            A list of the IPv6 addresses or an empty list.

        Raises:
            ValidationError: If it contains a term that is not a valid IPv6 address.
        """
        data = self.cleaned_data['ipv6_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv6Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError as exception:
            err_msg = 'Contains an invalid IPv6-Address.'
            raise forms.ValidationError(err_msg) from exception

    def clean_domain_names(self) -> list[str]:
        """Splits the domain names and returns them as a list of strings.

        Returns:
            A list of the domain names or an empty list.
        """
        data = self.cleaned_data['domain_names'].strip()
        if not data:
            return []

        domain_names = data.split(',')
        # TODO(AlexHx8472): Check for valid domains.    # noqa: FIX002
        return [domain_name.strip() for domain_name in domain_names if domain_name.strip() != '']

    def clean(self) -> dict[str, Any]:
        """Checks that at least one SAN entry is set.

        Returns:
            The cleaned data.

        Raises:
            ValidationError: If no SAN entry is set.
        """
        cleaned_data = super().clean() or {}
        ipv4_addresses = cleaned_data.get('ipv4_addresses')
        ipv6_addresses = cleaned_data.get('ipv6_addresses')
        domain_names = cleaned_data.get('domain_names')
        if not (ipv4_addresses or ipv6_addresses or domain_names):
            err_msg = 'At least one SAN entry is required.'
            raise forms.ValidationError(err_msg)
        return cleaned_data
