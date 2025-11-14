"""This module contains forms for the setup wizard app."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from typing import Any


class EmptyForm(forms.Form):
    """A form without any fields."""


class StartupWizardTlsCertificateForm(forms.Form):
    """The Setup Wizard TLS Certificate Form."""

    ipv4_addresses = forms.CharField(
        label=_('IPv4-Addresses (comma-separated list)'), initial='127.0.0.1, ', required=False
    )
    ipv6_addresses = forms.CharField(label=_('IPv6-Addresses (comma-separated list)'), initial='::1, ', required=False)
    domain_names = forms.CharField(
        label=_('Domain-Names (comma-separated list)'), initial='localhost, ', required=False
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
        label=_('PKCS#11 Module Path'),
        help_text=_('Path to the PKCS#11 module library.'),
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        required=True
    )

    slot = forms.IntegerField(
        initial=0,
        min_value=0,
        max_value=255,
        label=_('Slot Number'),
        help_text=_('HSM slot number to use.'),
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        required=True
    )

    label = forms.CharField(
        max_length=32,
        label=_('Token Label'),
        help_text=_('Label for the HSM token.'),
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
            self.fields['module_path'].initial = '/usr/local/lib/libpkcs11-proxy.so'
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
            cleaned_data['module_path'] = '/usr/local/lib/libpkcs11-proxy.so'
        if hsm_type == 'physical':
            raise forms.ValidationError(_('Physical HSM is not yet supported.'))
        if hsm_type != 'softhsm':
            self.add_error('hsm_type', _('Unsupported HSM type: %(hsm_type)s') % {'hsm_type': hsm_type})

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
            return '/usr/local/lib/libpkcs11-proxy.so'
        value = self.cleaned_data.get('module_path')
        if isinstance(value, str):
            return value
        return ''

class BackupPasswordForm(forms.Form):
    """Form for setting up backup password for PKCS#11 token."""

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('Enter backup password'),
            'autocomplete': 'new-password',
        }),
        label=_('Backup Password'),
        help_text=_('Enter a strong password to secure your backup encryption key.'),
        required=True
    )

    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('Confirm backup password'),
            'autocomplete': 'new-password',
        }),
        label=_('Confirm Password'),
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
            raise forms.ValidationError(_('Password is required.'))

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
            raise forms.ValidationError(_('Passwords do not match.'))

        return cleaned_data

class BackupRestoreForm(forms.Form):
    """Form for restoring from backup with optional backup password."""

    MAX_PASSWORD_LENGTH = 128


    backup_file = forms.FileField(
        label=_('Backup File'),
        help_text=_('Select the backup file to restore from.'),
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.dump,.gz,.sql,.zip'
        })
    )

    backup_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': _('Enter backup password (optional)'),
            'autocomplete': 'current-password'
        }),
        label=_('Backup Password'),
        help_text=_(
            'Enter the backup password if the backup was created with DEK encryption. '
            'Leave empty if no password was set.'
        ),
        required=False
    )

    def clean_backup_file(self) -> Any:
        """Validate the backup file."""
        backup_file = self.cleaned_data.get('backup_file')

        if not backup_file:
            raise forms.ValidationError(_('No backup file provided.'))

        if not hasattr(backup_file, 'name') or not isinstance(backup_file.name, str):
            raise forms.ValidationError(_('Invalid backup file name.'))

        # Check file extension
        allowed_extensions = ['.dump', '.gz', '.sql', '.zip']
        if not any(backup_file.name.lower().endswith(ext) for ext in allowed_extensions):
            raise forms.ValidationError(
                _('Invalid file type. Allowed types: %(extensions)s') %
                {'extensions': ', '.join(allowed_extensions)}
            )

        # Check file size (e.g., max 100MB)
        if backup_file.size > 100 * 1024 * 1024:
            raise forms.ValidationError(_('File too large. Maximum size is 100MB.'))

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
            'placeholder': _('Enter backup password'),
            'autocomplete': 'new-password',
        }),
        label=_('Backup Password'),
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
            raise forms.ValidationError(_('Password is required.'))

        return password
