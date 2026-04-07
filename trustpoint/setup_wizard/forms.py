"""This module contains forms for the setup wizard app."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.functional import Promise
from django.utils.translation import gettext_lazy

from .models import SetupWizardConfigModel

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Any

    ChoiceLabel = str | int

CRYPTO_STORAGE_OPTION_DESCRIPTIONS = {
    str(SetupWizardConfigModel.CryptoStorageType.SoftwareStorage): gettext_lazy(
        'Store cryptographic material on the local system without a dedicated hardware security module.'
    ),
    str(SetupWizardConfigModel.CryptoStorageType.HsmStorage): gettext_lazy(
        'Use a hardware security module for stronger key protection and dedicated cryptographic operations.'
    ),
}

DEMO_DATA_OPTION_DESCRIPTIONS = {
    'True': gettext_lazy('Populate the installation with demo content to make evaluation and testing easier.'),
    'False': gettext_lazy('Start with an empty system and configure all operational data manually.'),
}

TLS_CONFIG_OPTION_DESCRIPTIONS = {
    'generate': gettext_lazy('Generate a new TLS server credential from IP addresses and DNS names.'),
    'pkcs12': gettext_lazy('Upload an existing TLS server credential as a PKCS#12 bundle.'),
    'separate_files': gettext_lazy('Upload certificate and private key as separate files.'),
}


class EmptyForm(forms.Form):
    """A form without any fields."""


class WizardCardRadioSelect(forms.RadioSelect):
    """RadioSelect that attaches description text to each option."""

    def __init__(
        self,
        *args: object,
        descriptions: Mapping[str, str | Promise] | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize the widget.

        Args:
            *args: Positional arguments forwarded to ``RadioSelect``.
            descriptions: Mapping from choice value to explanation text.
            **kwargs: Keyword arguments forwarded to ``RadioSelect``.
        """
        self.descriptions = descriptions or {}
        super().__init__(*args, **kwargs)

    def create_option(
        self,
        name: str,
        value: object,
        label: ChoiceLabel,
        selected: bool,
        index: int,
        subindex: int | None = None,
        attrs: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Build a choice option and attach its description text."""
        option = super().create_option(name, value, label, selected, index, subindex=subindex, attrs=attrs)
        option['description'] = self.descriptions.get(str(value), '')
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


class FreshInstallCryptoStorageModelForm(FreshInstallModelBaseForm):
    """Form for selecting the cryptographic storage backend during setup."""

    class Meta:
        """ModelForm configuration for the storage step."""

        model = SetupWizardConfigModel
        fields = ('crypto_storage',)
        widgets = {
            'crypto_storage': WizardCardRadioSelect(descriptions=CRYPTO_STORAGE_OPTION_DESCRIPTIONS),
        }


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


class FreshInstallTlsConfigForm(forms.Form):
    """Form for configuring TLS during the fresh-install wizard."""

    tls_mode = forms.ChoiceField(
        label=gettext_lazy('TLS configuration method'),
        choices=(
            ('generate', gettext_lazy('Generate credential')),
            ('pkcs12', gettext_lazy('Upload PKCS#12')),
            ('separate_files', gettext_lazy('Upload separate files')),
        ),
        widget=WizardCardRadioSelect(descriptions=TLS_CONFIG_OPTION_DESCRIPTIONS),
        initial='generate',
    )

    ipv4_addresses = forms.CharField(
        label=gettext_lazy('IPv4 addresses'),
        required=False,
        help_text=gettext_lazy('Comma-separated list.'),
    )
    ipv6_addresses = forms.CharField(
        label=gettext_lazy('IPv6 addresses'),
        required=False,
        help_text=gettext_lazy('Comma-separated list.'),
    )
    domain_names = forms.CharField(
        label=gettext_lazy('DNS names'),
        required=False,
        help_text=gettext_lazy('Comma-separated list.'),
    )

    pkcs12_file = forms.FileField(
        label=gettext_lazy('PKCS#12 file'),
        required=False,
    )
    pkcs12_password = forms.CharField(
        label=gettext_lazy('PKCS#12 password'),
        required=False,
        help_text=gettext_lazy('Optional, only needed when the PKCS#12 file is encrypted.'),
        widget=forms.PasswordInput(render_value=True),
    )

    tls_server_certificates = MultipleFileField(
        label=gettext_lazy('TLS server certificate files'),
        required=False,
        help_text=gettext_lazy('Select one or more certificate files.'),
    )
    key_file = forms.FileField(
        label=gettext_lazy('Key file'),
        required=False,
    )
    key_password = forms.CharField(
        label=gettext_lazy('Key password'),
        required=False,
        help_text=gettext_lazy('Optional, only needed when the key file is encrypted.'),
        widget=forms.PasswordInput(render_value=True),
    )

    @staticmethod
    def _split_csv(value: str) -> list[str]:
        """Normalize a comma-separated string into a list of trimmed values."""
        return [item.strip() for item in value.split(',') if item.strip()]

    def clean_ipv4_addresses(self) -> list[ipaddress.IPv4Address]:
        """Validate and normalize IPv4 SAN entries."""
        data = self.cleaned_data['ipv4_addresses'].strip()
        if not data:
            return []

        try:
            return [ipaddress.IPv4Address(address) for address in self._split_csv(data)]
        except ipaddress.AddressValueError as exception:
            err_msg = gettext_lazy('Contains an invalid IPv4 address.')
            raise forms.ValidationError(err_msg) from exception

    def clean_ipv6_addresses(self) -> list[ipaddress.IPv6Address]:
        """Validate and normalize IPv6 SAN entries."""
        data = self.cleaned_data['ipv6_addresses'].strip()
        if not data:
            return []

        try:
            return [ipaddress.IPv6Address(address) for address in self._split_csv(data)]
        except ipaddress.AddressValueError as exception:
            err_msg = gettext_lazy('Contains an invalid IPv6 address.')
            raise forms.ValidationError(err_msg) from exception

    def clean_domain_names(self) -> list[str]:
        """Normalize DNS SAN entries."""
        data = self.cleaned_data['domain_names'].strip()
        if not data:
            return []
        return self._split_csv(data)

    def clean(self) -> dict[str, Any]:
        """Validate the field set required for the selected TLS mode."""
        cleaned_data = super().clean()
        tls_mode = cleaned_data.get('tls_mode')

        if tls_mode == 'generate':
            ipv4_addresses = cleaned_data.get('ipv4_addresses')
            ipv6_addresses = cleaned_data.get('ipv6_addresses')
            domain_names = cleaned_data.get('domain_names')
            if not (ipv4_addresses or ipv6_addresses or domain_names):
                err_msg = gettext_lazy('At least one IP address or DNS name is required for generation.')
                raise forms.ValidationError(err_msg)

        elif tls_mode == 'pkcs12':
            if not cleaned_data.get('pkcs12_file'):
                self.add_error('pkcs12_file', gettext_lazy('A PKCS#12 file is required.'))

        elif tls_mode == 'separate_files':
            if not cleaned_data.get('tls_server_certificates'):
                self.add_error('tls_server_certificates', gettext_lazy('At least one certificate file is required.'))
            if not cleaned_data.get('key_file'):
                self.add_error('key_file', gettext_lazy('A key file is required.'))

        return cleaned_data



class StartupWizardTlsCertificateForm(forms.Form):
    """The Setup Wizard TLS Certificate Form."""

    ipv4_addresses = forms.CharField(
        label=gettext_lazy('IPv4-Addresses (comma-separated list)'), initial='127.0.0.1, ', required=False
    )
    ipv6_addresses = forms.CharField(label=gettext_lazy('IPv6-Addresses (comma-separated list)'), initial='::1, ', required=False)
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
        cleaned_data = super().clean()
        if cleaned_data is None:
            err_msg = (
                'Unexpected error occurred. Failed to get the cleaned_data '
                'of the StartupWizardTlsCertificateForm instance.'
            )
            raise forms.ValidationError(err_msg)
        ipv4_addresses = cleaned_data.get('ipv4_addresses')
        ipv6_addresses = cleaned_data.get('ipv6_addresses')
        domain_names = cleaned_data.get('domain_names')
        if not (ipv4_addresses or ipv6_addresses or domain_names):
            err_msg = 'At least one SAN entry is required.'
            raise forms.ValidationError(err_msg)
        return cleaned_data

class HsmSetupForm(forms.Form):
    """Form for HSM setup configuration."""

    module_path = forms.CharField(
        max_length=255,
        label=gettext_lazy('PKCS#11 Module Path'),
        help_text=gettext_lazy('Path to the PKCS#11 module library.'),
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        required=True
    )

    slot = forms.IntegerField(
        initial=0,
        min_value=0,
        max_value=255,
        label=gettext_lazy('Slot Number'),
        help_text=gettext_lazy('HSM slot number to use.'),
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        required=True
    )

    label = forms.CharField(
        max_length=32,
        label=gettext_lazy('Token Label'),
        help_text=gettext_lazy('Label for the HSM token.'),
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        required=True
    )

    # Hidden field to store the HSM type (will be set by the view)
    hsm_type = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, hsm_type: str = 'softhsm', *args: Any, **kwargs: Any) -> None:
        """Initialize the form with HSM type-specific defaults."""
        super().__init__(*args, **kwargs)

        self.fields['hsm_type'].initial = hsm_type

        if hsm_type == 'softhsm':
            self.fields['module_path'].initial = '/usr/lib/libpkcs11-proxy.so'
            self.fields['slot'].initial = 0
            self.fields['label'].initial = 'Trustpoint-SoftHSM'

            self.fields['module_path'].widget.attrs.update({
                'readonly': True,
                'class': 'form-control'
            })
            self.fields['slot'].widget.attrs.update({
                'readonly': True,
                'class': 'form-control'
            })
            self.fields['label'].widget.attrs.update({
                'readonly': True,
                'class': 'form-control'
            })

        elif hsm_type == 'physical':
            self.fields['module_path'].initial = ''
            self.fields['slot'].initial = 0
            self.fields['label'].initial = 'Trustpoint-Physical-HSM'

            self.fields['module_path'].widget.attrs.update({
                'placeholder': '/usr/lib/vendor/libpkcs11.so'
            })
            self.fields['label'].widget.attrs.update({
                'placeholder': 'Enter token label'
            })

    def clean(self) -> dict[str, Any]:
        """Custom validation for the form."""
        cleaned_data = super().clean()
        if cleaned_data is None:
            err_msg = (
                'Unexpected error occurred. Failed to get the cleaned_data '
                'of the HsmSetupForm instance.'
            )
            raise forms.ValidationError(err_msg)

        hsm_type = cleaned_data.get('hsm_type')

        if hsm_type == 'softhsm':
            cleaned_data['label'] = 'Trustpoint-SoftHSM'
            cleaned_data['slot'] = 0
            cleaned_data['module_path'] = '/usr/lib/libpkcs11-proxy.so'
        if hsm_type == 'physical':
            raise forms.ValidationError(gettext_lazy('Physical HSM is not yet supported.'))
        if hsm_type != 'softhsm':
            self.add_error('hsm_type', gettext_lazy('Unsupported HSM type: %(hsm_type)s') % {'hsm_type': hsm_type})

        return cleaned_data

    def clean_label(self) -> str:
        """Clean token label field."""
        hsm_type = self.data.get('hsm_type')
        if hsm_type == 'softhsm':
            return 'Trustpoint-SoftHSM'
        value = self.cleaned_data.get('label')
        if isinstance(value, str):
            return value
        return ''

    def clean_slot(self) -> int:
        """Clean slot number field."""
        hsm_type = self.data.get('hsm_type')
        if hsm_type == 'softhsm':
            return 0
        value = self.cleaned_data.get('slot')
        if isinstance(value, int):
            return value
        return 0

    def clean_module_path(self) -> str:
        """Clean module path field."""
        hsm_type = self.data.get('hsm_type')
        if hsm_type == 'softhsm':
            return '/usr/lib/libpkcs11-proxy.so'
        value = self.cleaned_data.get('module_path')
        if isinstance(value, str):
            return value
        return ''

class BackupPasswordForm(forms.Form):
    """Form for setting up backup password for PKCS#11 token."""

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': gettext_lazy('Enter backup password'),
            'autocomplete': 'new-password',
        }),
        label=gettext_lazy('Backup Password'),
        help_text=gettext_lazy('Enter a strong password to secure your backup encryption key.'),
        required=True
    )

    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': gettext_lazy('Confirm backup password'),
            'autocomplete': 'new-password',
        }),
        label=gettext_lazy('Confirm Password'),
        required=True
    )

    def clean_password(self) -> str:
        """Clean and validate the password field using Django's password validators.

        Returns:
            The cleaned password.

        Raises:
            ValidationError: If password validation fails.
        """
        password = self.cleaned_data.get('password')

        if not isinstance(password, str) or not password:
            raise forms.ValidationError(gettext_lazy('Password is required.'))

        try:
            validate_password(password)
        except DjangoValidationError as e:
            raise forms.ValidationError(e.messages) from e

        return password

    def clean(self) -> dict[str, Any]:
        """Validate the form data.

        Returns:
            The cleaned data.

        Raises:
            ValidationError: If validation fails.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            err_msg = (
                'Unexpected error occurred. Failed to get the cleaned_data '
                'of the BackupPasswordForm instance.'
            )
            raise forms.ValidationError(err_msg)
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError(gettext_lazy('Passwords do not match.'))

        return cleaned_data

class BackupRestoreForm(forms.Form):
    """Form for restoring from backup with optional backup password."""

    MAX_PASSWORD_LENGTH = 128


    backup_file = forms.FileField(
        label=gettext_lazy('Backup File'),
        help_text=gettext_lazy('Select the backup file to restore from.'),
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.dump,.gz,.sql,.zip'
        })
    )

    backup_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': gettext_lazy('Enter backup password (optional)'),
            'autocomplete': 'current-password'
        }),
        label=gettext_lazy('Backup Password'),
        help_text=gettext_lazy(
            'Enter the backup password if the backup was created with DEK encryption. '
            'Leave empty if no password was set.'
        ),
        required=False
    )

    def clean_backup_file(self) -> Any:
        """Validate the backup file."""
        backup_file = self.cleaned_data.get('backup_file')

        if not backup_file:
            raise forms.ValidationError(gettext_lazy('No backup file provided.'))

        if not hasattr(backup_file, 'name') or not isinstance(backup_file.name, str):
            raise forms.ValidationError(gettext_lazy('Invalid backup file name.'))

        # Check file extension
        allowed_extensions = ['.dump', '.gz', '.sql', '.zip']
        if not any(backup_file.name.lower().endswith(ext) for ext in allowed_extensions):
            raise forms.ValidationError(
                gettext_lazy('Invalid file type. Allowed types: %(extensions)s') %
                {'extensions': ', '.join(allowed_extensions)}
            )

        # Check file size (e.g., max 100MB)
        if backup_file.size > 100 * 1024 * 1024:
            raise forms.ValidationError(gettext_lazy('File too large. Maximum size is 100MB.'))

        return backup_file

    def clean_backup_password(self) -> str:
        """Clean the backup password field."""
        password = self.cleaned_data.get('backup_password')

        # If password is provided, do basic validation
        if password and len(password) > self.MAX_PASSWORD_LENGTH:
            msg = f'Password is too long (maximum {self.MAX_PASSWORD_LENGTH} characters).'
            raise forms.ValidationError(msg)

        return password or ''

class PasswordAutoRestoreForm(forms.Form):
    """Form for filling the password for auto-restore."""

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': gettext_lazy('Enter backup password'),
            'autocomplete': 'new-password',
        }),
        label=gettext_lazy('Backup Password'),
        required=True
    )

    def clean_password(self) -> str:
        """Clean and validate the password field using Django's password validators.

        Returns:
            The cleaned password.

        Raises:
            ValidationError: If password validation fails.
        """
        password = self.cleaned_data.get('password')

        if not isinstance(password, str) or not password:
            raise forms.ValidationError(gettext_lazy('Password is required.'))

        return password
