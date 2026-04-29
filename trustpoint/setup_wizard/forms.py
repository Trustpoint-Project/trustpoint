"""This module contains forms for the setup wizard app."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Any, ClassVar, cast

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy

from .models import SetupWizardConfigModel
from .tls_credential import extract_staged_tls_sans

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from django.utils.functional import Promise

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

TLS_CONFIG_TYPE_CHOICES = tuple(
    (choice.value, choice.label) for choice in SetupWizardConfigModel.FreshInstallTlsConfigType
)

MAX_DNS_NAME_LENGTH = 253


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

    def create_option(  # noqa: PLR0913
        self,
        name: str,
        value: object,
        label: str | int,
        selected: bool,  # noqa: FBT001
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


class FreshInstallCryptoStorageModelForm(FreshInstallModelBaseForm):
    """Form for selecting the cryptographic storage backend during setup."""

    class Meta:
        """ModelForm configuration for the storage step."""

        model = SetupWizardConfigModel
        fields = ('crypto_storage',)
        widgets: ClassVar[dict[str, forms.Widget]] = {
            'crypto_storage': WizardCardRadioSelect(
                descriptions=CRYPTO_STORAGE_OPTION_DESCRIPTIONS,
                disabled_values={str(SetupWizardConfigModel.CryptoStorageType.HsmStorage)},
            ),
        }

    def clean_crypto_storage(self) -> SetupWizardConfigModel.CryptoStorageType:
        """Reject storage backends that are currently unavailable in the wizard."""
        # noinspection PyUnnecessaryCast
        crypto_storage = cast('SetupWizardConfigModel.CryptoStorageType', self.cleaned_data['crypto_storage'])
        if int(crypto_storage) == SetupWizardConfigModel.CryptoStorageType.HsmStorage:
            err_msg = gettext_lazy('HSM storage is currently unavailable.')
            raise forms.ValidationError(err_msg)
        return crypto_storage


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

    storage_selection = forms.CharField(
        label=gettext_lazy('Storage Selection'),
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
        tls_credential = instance.fresh_install_tls_credential
        ipv4_addresses, ipv6_addresses, dns_names = extract_staged_tls_sans(tls_credential)
        self.fields['storage_selection'].initial = instance.get_crypto_storage_display()
        self.fields['inject_demo_data_selection'].initial = (
            gettext_lazy('Yes') if instance.inject_demo_data else gettext_lazy('No')
        )
        self.fields['tls_server_configuration'].initial = instance.get_fresh_install_tls_mode_display()
        self.fields['tls_common_name'].initial = (
            tls_credential.certificate.common_name if tls_credential and tls_credential.certificate else '-'
        )
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
        cleaned_data = cast('dict[str, Any]', super().clean())

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
        required=True,
    )

    slot = forms.IntegerField(
        initial=0,
        min_value=0,
        max_value=255,
        label=gettext_lazy('Slot Number'),
        help_text=gettext_lazy('HSM slot number to use.'),
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        required=True,
    )

    label = forms.CharField(
        max_length=32,
        label=gettext_lazy('Token Label'),
        help_text=gettext_lazy('Label for the HSM token.'),
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        required=True,
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

            self.fields['module_path'].widget.attrs.update({'readonly': True, 'class': 'form-control'})
            self.fields['slot'].widget.attrs.update({'readonly': True, 'class': 'form-control'})
            self.fields['label'].widget.attrs.update({'readonly': True, 'class': 'form-control'})

        elif hsm_type == 'physical':
            self.fields['module_path'].initial = ''
            self.fields['slot'].initial = 0
            self.fields['label'].initial = 'Trustpoint-Physical-HSM'

            self.fields['module_path'].widget.attrs.update({'placeholder': '/usr/lib/vendor/libpkcs11.so'})
            self.fields['label'].widget.attrs.update({'placeholder': 'Enter token label'})

    def clean(self) -> dict[str, Any]:
        """Custom validation for the form."""
        cleaned_data = super().clean()
        if cleaned_data is None:
            err_msg = 'Unexpected error occurred. Failed to get the cleaned_data of the HsmSetupForm instance.'
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
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': gettext_lazy('Enter backup password'),
                'autocomplete': 'new-password',
            }
        ),
        label=gettext_lazy('Backup Password'),
        help_text=gettext_lazy('Enter a strong password to secure your backup encryption key.'),
        required=True,
    )

    confirm_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': gettext_lazy('Confirm backup password'),
                'autocomplete': 'new-password',
            }
        ),
        label=gettext_lazy('Confirm Password'),
        required=True,
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
            err_msg = 'Unexpected error occurred. Failed to get the cleaned_data of the BackupPasswordForm instance.'
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
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.dump,.gz,.sql,.zip'}),
    )

    backup_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': gettext_lazy('Enter backup password (optional)'),
                'autocomplete': 'current-password',
            }
        ),
        label=gettext_lazy('Backup Password'),
        help_text=gettext_lazy(
            'Enter the backup password if the backup was created with DEK encryption. '
            'Leave empty if no password was set.'
        ),
        required=False,
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
                gettext_lazy('Invalid file type. Allowed types: %(extensions)s')
                % {'extensions': ', '.join(allowed_extensions)}
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
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': gettext_lazy('Enter backup password'),
                'autocomplete': 'new-password',
            }
        ),
        label=gettext_lazy('Backup Password'),
        required=True,
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
