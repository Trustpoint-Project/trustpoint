# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django forms for Web UI automation configuration and lifecycle actions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, override

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit
from django import forms
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from devices.models import DeviceModel
from onboarding.authorization import PermittedProtocolsAuthorization
from onboarding.enums import NoOnboardingPkiProtocol
from onboarding.models import NoOnboardingConfigModel
from pki.models.domain import DomainModel
from util.field import UniqueNameValidator
from web_ui_automation.models import (
    WebUiAutomationAssignedProfile,
    WebUiAutomationDevice,
    WebUiAutomationProfileDefinition,
)

if TYPE_CHECKING:
    from django.db.models.query import QuerySet
from web_ui_automation.schema import validate_profile_schema


class WebUiAutomationDeviceCreateForm(
    forms.ModelForm[WebUiAutomationDevice],
):
    """Create a Trustpoint device and its Web UI automation configuration."""

    common_name = forms.CharField(
        label=_('Common Name'),
        max_length=100,
        validators=[UniqueNameValidator()],
    )
    serial_number = forms.CharField(
        label=_('Serial Number'),
        max_length=100,
        required=False,
    )
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(
        is_active=True,
    )
    domain = forms.ModelChoiceField(
        label=_('Domain'),
        queryset=domain_queryset,
        empty_label='----------',
        required=False,
    )
    username = forms.CharField(
        label=_('Username'),
        max_length=255,
        widget=forms.TextInput(
            attrs={'autocomplete': 'username'},
        ),
    )
    password = forms.CharField(
        label=_('Password'),
        max_length=1024,
        strip=False,
        widget=forms.PasswordInput(
            attrs={'autocomplete': 'current-password'},
        ),
    )
    private_key_password = forms.CharField(
        label=_('Private-Key Password'),
        max_length=1024,
        required=False,
        strip=False,
        widget=forms.PasswordInput(
            attrs={'autocomplete': 'new-password'},
        ),
    )

    class Meta:
        """Configure fields exposed during device creation."""

        model = WebUiAutomationDevice
        fields: ClassVar[list[str]] = [
            'base_url',
            'authentication_type',
        ]

    def clean_common_name(self) -> str:
        """Reject an existing Trustpoint device common name."""
        common_name: str = self.cleaned_data['common_name'].rstrip()

        if DeviceModel.objects.filter(
            common_name=common_name,
        ).exists():
            raise ValidationError(
                _('A device with this common name already exists.'),
            )

        return common_name

    @transaction.atomic
    @override
    def save(
        self,
        commit: bool = True,
    ) -> WebUiAutomationDevice:
        """Create the Trustpoint device and Web UI configuration."""
        automation_device = super().save(commit=False)

        common_name = self.cleaned_data['common_name']
        serial_number = self.cleaned_data.get('serial_number', '')
        domain = self.cleaned_data.get('domain')

        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.set_pki_protocols(
            [NoOnboardingPkiProtocol.MANUAL],
        )
        no_onboarding_config.full_clean()

        device = DeviceModel(
            common_name=common_name,
            serial_number=serial_number,
            domain=domain,
            device_type=DeviceModel.DeviceType.WEB_UI_AUTOMATION,
        )

        if not commit:
            return automation_device

        no_onboarding_config.save()

        device.no_onboarding_config = no_onboarding_config
        device.full_clean()
        PermittedProtocolsAuthorization().check(device)
        device.save()

        automation_device.device = device

        automation_device.full_clean(
            exclude=[
                'encrypted_username',
                'encrypted_password',
                'encrypted_private_key_password',
            ],
        )
        automation_device.save()

        automation_device.set_credentials(
            username=self.cleaned_data['username'],
            password=self.cleaned_data['password'],
            private_key_password=self.cleaned_data.get(
                'private_key_password',
                '',
            ),
        )

        return automation_device

class WebUiAutomationProfileForm(
    forms.ModelForm[WebUiAutomationProfileDefinition],
):
    """Create or update a Web UI automation profile."""

    class Meta:
        """Configure the automation profile form."""

        model = WebUiAutomationProfileDefinition
        fields: ClassVar[list[str]] = [
            'name',
            'profile',
        ]
        widgets: ClassVar[dict[str, forms.Widget]] = {
            'profile': forms.Textarea(
                attrs={
                    'rows': 30,
                    'class': 'form-control font-monospace',
                    'spellcheck': 'false',
                },
            ),
        }
        help_texts: ClassVar[dict[str, Any]] = {
            'profile': _(
                'Enter a valid Web UI automation profile as JSON.',
            ),
        }

    @staticmethod
    def validate_certificate_profile_field(
        profile: dict[str, Any],
    ) -> None:
        """Validate the certificate-profile identifier in a profile."""
        certificate_profile = profile.get('certificate_profile')

        if not isinstance(certificate_profile, str):
            raise ValidationError(
                _('The certificate_profile field must be a string.'),
            )

        if not certificate_profile.strip():
            raise ValidationError(
                _('The certificate_profile field must not be empty.'),
            )

    def clean_profile(self) -> dict[str, Any]:
        """Validate the JSON structure of the automation profile."""
        profile = self.cleaned_data['profile']

        if not isinstance(profile, dict):
            raise ValidationError(
                _('The automation profile must be a JSON object.'),
            )

        validate_profile_schema(profile)

        return profile


class WebUiAutomationAssignmentForm(forms.ModelForm[WebUiAutomationAssignedProfile]):
    """Configure one profile assignment."""

    class Meta:
        """Configure assignment fields exposed to users."""

        model = WebUiAutomationAssignedProfile
        fields: ClassVar[list[str]] = [
            'automation_device',
            'workflow_definition',
            'enabled',
        ]


class EnableAutomaticRenewalForm(forms.Form):
    """Validate an explicit request to enable automatic renewal."""

    def __init__(self, assignment: WebUiAutomationAssignedProfile, *args: Any, **kwargs: Any) -> None:
        """Store the assignment that should be enabled."""
        self.assignment = assignment
        super().__init__(*args, **kwargs)

    def clean(self) -> dict[str, Any]:
        """Verify all automatic-renewal preconditions."""
        cleaned_data = super().clean()
        try:
            self.assignment.validate_automatic_renewal_eligibility()
        except ValidationError as e:
            if hasattr(e, 'error_dict'):
                for field_errors in e.error_dict.values():
                    for error in field_errors:
                        self.add_error(None, error)
            else:
                raise
        return cleaned_data or {}


class ConfirmExecutionForm(forms.Form):
    """Represent an explicit onboarding or manual-renewal confirmation."""

    confirm = forms.BooleanField(
        label=_('I confirm that the certificate operation completed successfully.'),
        required=True,
    )


class WebUiAutomationDeviceUpdateForm(forms.Form):
    """Update Web UI automation device and linked device configuration."""

    common_name = forms.CharField(
        label=_('Common Name'),
        max_length=100,
    )
    serial_number = forms.CharField(
        label=_('Serial Number'),
        max_length=100,
        required=False,
    )
    domain = forms.ModelChoiceField(
        label=_('Domain'),
        queryset=DomainModel.objects.filter(is_active=True),
        empty_label='----------',
        required=False,
    )
    base_url = forms.URLField(
        label=_('Base URL'),
        max_length=500,
    )
    username = forms.CharField(
        label=_('Username'),
        max_length=255,
        required=False,
        widget=forms.TextInput(
            attrs={'autocomplete': 'username'},
        ),
    )
    password = forms.CharField(
        label=_('Password'),
        max_length=1024,
        required=False,
        strip=False,
        widget=forms.PasswordInput(
            attrs={'autocomplete': 'current-password', 'placeholder': '••••••••'},
        ),
        help_text=_('Leave blank to keep current password'),
    )

    def __init__(self, automation_device: WebUiAutomationDevice, *args: Any, **kwargs: Any) -> None:
        """Initialize form with current device values."""
        self.automation_device = automation_device
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            'common_name',
            'serial_number',
            'domain',
            'base_url',
            'username',
            'password',
            Submit('submit', _('Apply Changes'), css_class='btn btn-primary mt-3'),
        )

        if not self.is_bound:
            device = automation_device.device
            if device:
                self.initial['common_name'] = device.common_name
                self.initial['serial_number'] = device.serial_number
                self.initial['domain'] = device.domain
            self.initial['base_url'] = automation_device.base_url
            username = automation_device.get_username()
            if username:
                self.initial['username'] = username

    def clean_common_name(self) -> str:
        """Validate that common name is unique (excluding current device)."""
        common_name: str = self.cleaned_data['common_name'].rstrip()
        device = self.automation_device.device

        existing = DeviceModel.objects.filter(common_name=common_name)
        if device:
            existing = existing.exclude(pk=device.pk)

        if existing.exists():
            raise ValidationError(
                _('A device with this common name already exists.'),
            )

        return common_name

    @transaction.atomic
    def save(self) -> WebUiAutomationDevice:
        """Update the automation device and linked device."""
        automation_device = self.automation_device
        device = automation_device.device

        if not device:
            device = DeviceModel(
                device_type=DeviceModel.DeviceType.WEB_UI_AUTOMATION,
            )

        device.common_name = self.cleaned_data['common_name']
        device.serial_number = self.cleaned_data['serial_number'] or ''
        device.domain = self.cleaned_data['domain']
        device.save()

        automation_device.device = device
        automation_device.base_url = self.cleaned_data['base_url']
        automation_device.save()

        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        if username or password:
            current_username = username or automation_device.get_username()
            current_password = password or automation_device.get_password()
            automation_device.set_credentials(current_username, current_password)

        return automation_device
