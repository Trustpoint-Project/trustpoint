"""Forms definition."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Fieldset, Layout
from django import forms
from django.utils.translation import gettext_lazy as _
from pki.util.keys import AutoGenPkiKeyAlgorithm

from settings.models import BackupOptions, SecurityConfig
from settings.security import manager
from settings.security.features import AutoGenPkiFeature, SecurityFeature

if TYPE_CHECKING:
    from typing import Any, ClassVar


class SecurityConfigForm(forms.ModelForm):
    """Security configuration model form."""

    FEATURE_TO_FIELDS: dict[type[SecurityFeature], list[str]] = {
        AutoGenPkiFeature: ['auto_gen_pki', 'auto_gen_pki_key_algorithm'],
    }

    def __init__(self, *args: Any, **kwargs: Any):
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
            field_names = self.FEATURE_TO_FIELDS.get(feature_cls, [])
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
        model = SecurityConfig
        fields: ClassVar[list[str]] = ['security_mode', 'auto_gen_pki', 'auto_gen_pki_key_algorithm']

    def clean_auto_gen_pki_key_algorithm(self) -> AutoGenPkiKeyAlgorithm:
        """Keep the current value of `auto_gen_pki_key_algorithm` from the instance if the field was disabled."""
        form_value = self.cleaned_data.get('auto_gen_pki_key_algorithm')
        if form_value is None:
            return self.instance.auto_gen_pki_key_algorithm if self.instance else AutoGenPkiKeyAlgorithm.RSA2048
        return form_value


class BackupOptionsForm(forms.ModelForm[BackupOptions]):
    """Form for editing BackupOptions settings."""

    class Meta:
        """ModelForm Meta configuration for BackupOptions."""
        model = BackupOptions
        fields: ClassVar[list[str]] = [
            'local_storage',
            'sftp_storage',
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
            'local_storage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'sftp_storage': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
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
        sftp_storage = cleaned.get('sftp_storage')

        if sftp_storage:
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
                    None ,
                    f"The following fields are required when SFTP storage is enabled: {', '.join(missing_fields)}."
                )

        if auth:
            pwd = cleaned.get('password', '').strip()
            key = cleaned.get('private_key', '').strip()

            if auth == BackupOptions.AuthMethod.PASSWORD and not pwd:
                self.add_error('password', 'Password is required when using password authentication.')
            if auth == BackupOptions.AuthMethod.SSH_KEY and not key:
                self.add_error('private_key', 'Private key is required when using SSH Key authentication.')

        return cleaned


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

        ipv4_field = cast(forms.ChoiceField, self.fields['ipv4_address'])
        ipv4_field.choices = [(ip, ip) for ip in san_ips]






