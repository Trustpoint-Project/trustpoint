"""Forms definition."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Fieldset, Layout
from django import forms
from django.forms import CheckboxSelectMultiple
from django.utils.translation import gettext_lazy as _
from notifications.models import NotificationConfig
from pki.util.keys import AutoGenPkiKeyAlgorithm

from settings.models import SecurityConfig
from settings.security import manager
from settings.security.features import AutoGenPkiFeature, SecurityFeature

if TYPE_CHECKING:
    from typing import ClassVar


class SecurityConfigForm(forms.ModelForm):
    """Security configuration model form."""

    FEATURE_TO_FIELDS: dict[type[SecurityFeature], list[str]] = {
        AutoGenPkiFeature: ['auto_gen_pki', 'auto_gen_pki_key_algorithm'],
    }

    def __init__(self, *args, **kwargs):
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
        choices=SecurityConfig.SecurityModeChoices.choices, widget=forms.RadioSelect(), label=''
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
        choices=AutoGenPkiKeyAlgorithm.choices,
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

class NotificationConfigForm(forms.ModelForm[NotificationConfig]):
    """Form for editing notification-related thresholds and weak algorithm/cipher settings.

    This form provides a clean admin interface for:
    - Certificate and issuing CA expiry thresholds
    - Minimum RSA key size requirement
    - Lists of weak ECC curves and signature algorithms (many-to-many selection)
    """

    class Meta:
        """Metadata for NotificationConfigForm."""

        model = NotificationConfig
        fields: ClassVar[list[str]] = [
            'cert_expiry_warning_days',
            'issuing_ca_expiry_warning_days',
            'rsa_minimum_key_size',
            'weak_ecc_curves',
            'weak_signature_algorithms',
        ]

        labels: ClassVar[dict[str, str]] = {
            'cert_expiry_warning_days': _('Certificate Expiry Warning (Days)'),
            'issuing_ca_expiry_warning_days': _('Issuing CA Expiry Warning (Days)'),
            'rsa_minimum_key_size': _('Minimum RSA Key Size (bits)'),
            'weak_ecc_curves': _('Weak ECC Curves'),
            'weak_signature_algorithms': _('Weak Signature Algorithms'),
        }

        widgets: ClassVar[dict[str, type[CheckboxSelectMultiple]]] = {
            'weak_ecc_curves': forms.CheckboxSelectMultiple,
            'weak_signature_algorithms': forms.CheckboxSelectMultiple,
        }

        help_texts: ClassVar[dict[str, str]] = {
            'cert_expiry_warning_days': _('Number of days before a certificate expires to trigger a warning.'),
            'issuing_ca_expiry_warning_days':
                _('Number of days before an issuing CA certificate expires to trigger a warning.'),
            'rsa_minimum_key_size': _('Minimum allowed RSA key length in bits.'),
            'weak_ecc_curves': _('Select one or more ECC curves that should be treated as weak.'),
            'weak_signature_algorithms': _('Select one or more signature algorithms that should be treated as weak.'),
        }

    def clean(self) -> dict[str, Any] | None:
        """Custom validation hook, if needed in future.

        Currently just calls the default implementation.
        """
        return super().clean()
