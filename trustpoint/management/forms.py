"""Forms definition."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Fieldset, Layout
from django import forms
from django.utils.translation import gettext_lazy as _
from pki.util.keys import AutoGenPkiKeyAlgorithm
from trustpoint.logger import LoggerMixin

from management.models import BackupOptions, KeyStorageConfig, PKCS11Token, SecurityConfig
from management.security import manager
from management.security.features import AutoGenPkiFeature, SecurityFeature

if TYPE_CHECKING:
    from typing import Any, ClassVar


class SecurityConfigForm(forms.ModelForm[SecurityConfig], LoggerMixin):
    """Security configuration model form."""

    FEATURE_TO_FIELDS: ClassVar[dict[type[SecurityFeature], list[str]]] = {
        AutoGenPkiFeature: ['auto_gen_pki', 'auto_gen_pki_key_algorithm'],
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the SecurityConfigForm."""
        super().__init__(*args, **kwargs)

        # Determine the 'current_mode' from form data or instance
        if 'security_mode' in self.data:
            current_mode = self.data['security_mode']
        else:
            current_mode = self.instance.security_mode if self.instance else SecurityConfig.SecurityModeChoices.LOW

        sec_manager = manager.SecurityManager()
        features_not_allowed = sec_manager.get_features_to_disable(current_mode)

        # Disable form fields that correspond to features not allowed
        for feature_cls in features_not_allowed:
            field_names = self.FEATURE_TO_FIELDS.get(type(feature_cls), [])
            for field_name in field_names:
                if field_name in self.fields:
                    self.fields[field_name].widget.attrs['disabled'] = 'disabled'

        # Disable option to change alorithm if AutoGenPKI is already enabled
        if self.instance and self.instance.auto_gen_pki:
            self.fields['auto_gen_pki_key_algorithm'].widget.attrs['disabled'] = 'disabled'

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Fieldset(
                _('Security level presets'),
                'security_mode',
            ),
            Fieldset(
                _('Advanced security settings'),
                'auto_gen_pki',
                'auto_gen_pki_key_algorithm',
            ),
        )

    security_mode = forms.ChoiceField(
        choices=SecurityConfig.SecurityModeChoices, widget=forms.RadioSelect(), label=''
    )

    auto_gen_pki = forms.BooleanField(
        required=False,
        label=_('Enable local auto-generated PKI'),
        widget=forms.CheckboxInput(
            attrs={
                'data-sl-defaults': '[true, true, false, false, false]',
                'data-hide-at-sl': '[false, false, true, true, true]',
                'data-more-secure': 'false',
            }
        ),
    )

    auto_gen_pki_key_algorithm = forms.ChoiceField(
        choices=AutoGenPkiKeyAlgorithm,
        label=_('Key Algorithm for auto-generated PKI'),
        required=False,
        widget=forms.Select(attrs={'data-hide-at-sl': '[false, false, true, true, true]'}),
    )

    class Meta:
        """ModelForm Meta configuration for SecurityConfig."""
        model = SecurityConfig
        fields: ClassVar[list[str]] = ['security_mode', 'auto_gen_pki', 'auto_gen_pki_key_algorithm']

    def clean_auto_gen_pki_key_algorithm(self) -> AutoGenPkiKeyAlgorithm:
        """Keep the current value of `auto_gen_pki_key_algorithm` from the instance if the field was disabled."""
        form_value = self.cleaned_data.get('auto_gen_pki_key_algorithm')
        if isinstance(form_value, AutoGenPkiKeyAlgorithm):
            return form_value
        if isinstance(form_value, str):
            try:
                return AutoGenPkiKeyAlgorithm(form_value)
            except ValueError:
                return AutoGenPkiKeyAlgorithm.RSA2048

        if self.instance:
            inst_val = getattr(self.instance, 'auto_gen_pki_key_algorithm', None)
            if isinstance(inst_val, AutoGenPkiKeyAlgorithm):
                return inst_val
            if isinstance(inst_val, str):
                try:
                    return AutoGenPkiKeyAlgorithm(inst_val)
                except Exception as exc:  # noqa: BLE001
                    self.logger.warning(exc, 'Exception occurred while parsing auto_gen_pki_key_algorithm')

        return AutoGenPkiKeyAlgorithm.RSA2048


class BackupOptionsForm(forms.ModelForm[BackupOptions]):
    """Form for editing BackupOptions settings."""

    class Meta:
        """ModelForm Meta configuration for BackupOptions."""
        model = BackupOptions
        fields: ClassVar[list[str]] = [
            'enable_sftp_storage',
            'host',
            'port',
            'user',
            'auth_method',
            'password',
            'private_key',
            'key_passphrase',
            'remote_directory',
        ]
        widgets: ClassVar[dict[str, Any]] = {
            'enable_sftp_storage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'host': forms.TextInput(attrs={'class': 'form-control'}),
            'port': forms.NumberInput(attrs={'class': 'form-control'}),
            'user': forms.TextInput(attrs={'class': 'form-control'}),
            'auth_method': forms.Select(attrs={'class': 'form-select'}),
            'password': forms.PasswordInput(
                attrs={'class': 'form-control'}, render_value=True
            ),
            'private_key': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
            'key_passphrase': forms.PasswordInput(
                attrs={'class': 'form-control'}, render_value=True
            ),
            'remote_directory': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def clean(self) -> dict[str, Any]:
        """Validate required fields based on selected authentication method."""
        cleaned: dict[str, Any] = super().clean() or {}
        auth = cleaned.get('auth_method')
        enable_sftp = cleaned.get('enable_sftp_storage')

        if enable_sftp:
            self._validate_sftp_fields(cleaned)
            self._validate_authentication_fields(cleaned, auth)

        return cleaned

    def _validate_sftp_fields(self, cleaned: dict[str, Any]) -> None:
        """Validate required fields for SFTP storage."""
        missing_fields = []
        host = cleaned.get('host', '').strip()
        user = cleaned.get('user', '').strip()
        remote_directory = cleaned.get('remote_directory', '').strip()

        if not host:
            missing_fields.append('Host')
        if not user:
            missing_fields.append('Username')
        if not remote_directory:
            missing_fields.append('Remote Directory')

        if missing_fields:
            self.add_error(
                None,
                f"The following fields are required when SFTP storage is enabled: {', '.join(missing_fields)}."
            )

    def _validate_authentication_fields(self, cleaned: dict[str, Any], auth: Any) -> None:
        """Validate fields based on the selected authentication method."""
        pwd = cleaned.get('password', '').strip()
        key = cleaned.get('private_key', '').strip()

        if auth == BackupOptions.AuthMethod.PASSWORD:
            self._validate_password_authentication(pwd, key, cleaned)
        elif auth == BackupOptions.AuthMethod.SSH_KEY:
            self._validate_ssh_key_authentication(pwd, key)

    def _validate_password_authentication(self, pwd: str, key: str, cleaned: dict[str, Any]) -> None:
        """Validate fields for password authentication."""
        if not pwd:
            self.add_error('password', 'Password is required when using password authentication.')
        if key or cleaned.get('key_passphrase', '').strip():
            self.add_error('private_key',
                           'Private key and passphrase must be empty when using password authentication.')
            self.add_error('key_passphrase',
                           'Private key and passphrase must be empty when using password authentication.')

    def _validate_ssh_key_authentication(self, pwd: str, key: str) -> None:
        """Validate fields for SSH key authentication."""
        if not key:
            self.add_error('private_key', 'Private key is required when using SSH Key authentication.')
        if pwd:
            self.add_error('password', 'Password must be empty when using SSH key authentication.')


class IPv4AddressForm(forms.Form):
    """A form for selecting and updating an IPv4 address.

    This form provides an interface for selecting an IPv4 address from
    a list of Subject Alternative Names (SANs).

    Attributes:
        ipv4_address: A choice field for selecting the IPv4 address.
    """

    ipv4_address = forms.ChoiceField(
        label='Update IPv4 Address'
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the IPv4AddressForm."""
        san_ips = kwargs.pop('san_ips', [])
        saved_ipv4_address = kwargs.get('initial', {}).get('ipv4_address')

        if saved_ipv4_address and saved_ipv4_address not in san_ips:
            san_ips.insert(0, saved_ipv4_address)

        super().__init__(*args, **kwargs)

        ipv4_field = cast('forms.ChoiceField', self.fields['ipv4_address'])
        ipv4_field.choices = [(ip, ip) for ip in san_ips]

class KeyStorageConfigForm(forms.ModelForm[KeyStorageConfig]):
    """Form for configuring cryptographic material storage options."""

    storage_type = forms.ChoiceField(
        widget=forms.RadioSelect,
        label=_('Storage Type'),
        help_text=_('Select how cryptographic material should be stored'),
        choices=[
            ('software', _('Software Storage')),
            ('softhsm', _('SoftHSM Container')),
            ('physical_hsm', _('Physical HSM')),
        ]
    )

    class Meta:
        """ModelForm Meta configuration for KeyStorageConfig."""
        model = KeyStorageConfig
        fields: ClassVar[list[str]] = ['storage_type']

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        super().__init__(*args, **kwargs)

    def clean(self) -> dict[str, Any]:
        """Custom validation for the form."""
        cleaned_data: dict[str, Any] = super().clean() or {}
        return cleaned_data

    def save_with_commit(self) -> KeyStorageConfig:
        """Save the form with commit, ensuring singleton behavior."""
        instance = KeyStorageConfig.get_or_create_default()
        instance.storage_type = self.cleaned_data['storage_type']
        instance.save(update_fields=['storage_type', 'last_updated'])
        return instance

    def save_without_commit(self) -> KeyStorageConfig:
        """Save the form without commit, ensuring singleton behavior."""
        instance = KeyStorageConfig.get_or_create_default()
        instance.storage_type = self.cleaned_data['storage_type']
        return instance

class PKCS11ConfigForm(forms.Form):
    """Form for configuring PKCS#11 settings including HSM PIN and token information."""

    HSM_TYPE_CHOICES: ClassVar[list[tuple[str, Any]]] = [
        ('softhsm', _('SoftHSM')),
        ('physical', _('Physical HSM')),
    ]

    hsm_type = forms.ChoiceField(
        choices=HSM_TYPE_CHOICES,
        initial='softhsm',
        widget=forms.RadioSelect,
        label=_('HSM Type'),
        help_text=_('Select the type of HSM to configure.')
    )

    label = forms.CharField(
        label=_('Token Label'),
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text=_('Unique label for the PKCS#11 token'),
        required=False
    )

    slot = forms.IntegerField(
        label=_('Slot Number'),
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text=_('Slot number where the token is located'),
        min_value=0,
        required=False
    )

    module_path = forms.CharField(
        label=_('Module Path'),
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text=_('Path to the PKCS#11 module library file'),
        initial='/usr/local/lib/libpkcs11-proxy.so',
        required=False
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the PKCS11ConfigForm with existing token data if available."""
        super().__init__(*args, **kwargs)

        try:
            token = PKCS11Token.objects.first()
            if token:
                self.fields['label'].initial = token.label
                self.fields['slot'].initial = token.slot
                self.fields['module_path'].initial = token.module_path
        except PKCS11Token.DoesNotExist:
            pass

    def clean(self) -> dict[str, Any]:
        """Custom validation for the form."""
        cleaned_data: dict[str, Any] = super().clean() or {}
        hsm_type = cleaned_data.get('hsm_type')

        if hsm_type == 'softhsm':
            cleaned_data['label'] = 'Trustpoint-SoftHSM'
            cleaned_data['slot'] = 0
            cleaned_data['module_path'] = '/usr/local/lib/libpkcs11-proxy.so'
        elif hsm_type == 'physical':
            raise forms.ValidationError(_('Physical HSM is not yet supported.'))

        return cleaned_data

    def clean_label(self) -> str:
        """Validate that label is unique, excluding current token if updating."""
        hsm_type = self.data.get('hsm_type')
        if hsm_type == 'softhsm':
            return 'Trustpoint-SoftHSM'

        label = self.cleaned_data.get('label', '')
        existing = PKCS11Token.objects.filter(label=label)

        current_token = PKCS11Token.objects.first()
        if current_token:
            existing = existing.exclude(pk=current_token.pk)

        if existing.exists():
            raise forms.ValidationError(_('A token with this label already exists.'))

        return str(label)

    def save_token_config(self) -> PKCS11Token:
        """Save or update token configuration."""
        data = self.cleaned_data
        token, created = PKCS11Token.objects.get_or_create(
            label=data['label'],
            defaults={
                'hsm_type': data['hsm_type'],
                'slot': data['slot'],
                'module_path': data['module_path'],
            }
        )

        if not created:
            for field, value in data.items():
                if field != 'label':
                    setattr(token, field, value)
            token.save()
        return token







