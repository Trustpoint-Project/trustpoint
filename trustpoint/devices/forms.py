# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Forms exclusively used in the device application."""

from __future__ import annotations

import secrets
import string
from typing import TYPE_CHECKING, Any, cast

from crispy_bootstrap5.bootstrap5 import Field
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Layout, Submit
from django import forms
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from devices.models import (
    DeviceModel,
    OpcUaGdsPushConfig,
    RemoteDeviceCredentialDownloadModel,
)
from devices.secrets import (
    VERSIONS,
    assign_secret,
    audit_assignments,
    custom_secrets_allowed,
    ensure_eligible,
    prepare_secret,
    validate_custom_secret,
)
from devices.utils import validate_application_uri, validate_common_name_characters
from onboarding.authorization import PermittedProtocolsAuthorization
from onboarding.models import (
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.forms.san import clean_dns_sans, clean_ipv4_sans, clean_ipv6_sans
from pki.models import IssuedCredentialModel
from pki.models.certificate import RevokedCertificateModel
from pki.models.domain import DomainModel
from pki.models.truststore import TruststoreModel
from trustpoint.forms import DisableOptionsSelect
from util.field import UniqueNameValidator

if TYPE_CHECKING:
    import ipaddress

    from django.db.models.query import QuerySet


class SwitchCheckboxSelectMultiple(forms.CheckboxSelectMultiple):
    """Custom CheckboxSelectMultiple widget that renders as Bootstrap switches."""

    template_name = 'widgets/switch_checkbox_select_multiple.html'

PASSWORD_MIN_LENGTH = 12
OTP_SPLIT_PARTS = 2
ALLOWED_CHARS = allowed_chars = string.ascii_letters + string.digits


ONBOARDING_PROTOCOLS_ALLOWED_FOR_FORMS = [
    (OnboardingProtocol.CMP_SHARED_SECRET.value, OnboardingProtocol.CMP_SHARED_SECRET.label),
    (OnboardingProtocol.EST_USERNAME_PASSWORD.value, OnboardingProtocol.EST_USERNAME_PASSWORD.label),
    (OnboardingProtocol.REST_USERNAME_PASSWORD.value, OnboardingProtocol.REST_USERNAME_PASSWORD.label),
    (OnboardingProtocol.MANUAL.value, OnboardingProtocol.MANUAL.label),
    (OnboardingProtocol.AOKI.value, OnboardingProtocol.AOKI.label),
    (OnboardingProtocol.BRSKI.value, OnboardingProtocol.BRSKI.label),
    (OnboardingProtocol.OPC_GDS_PUSH.value, OnboardingProtocol.OPC_GDS_PUSH.label),
    (OnboardingProtocol.AGENT.value, OnboardingProtocol.AGENT.label),
]

ONBOARDING_CREATE_PROTOCOLS_ALLOWED_FOR_FORMS = [
    (OnboardingProtocol.CMP_SHARED_SECRET.value, OnboardingProtocol.CMP_SHARED_SECRET.label),
    (OnboardingProtocol.EST_USERNAME_PASSWORD.value, OnboardingProtocol.EST_USERNAME_PASSWORD.label),
    (OnboardingProtocol.REST_USERNAME_PASSWORD.value, OnboardingProtocol.REST_USERNAME_PASSWORD.label),
]


def _get_permitted_onboarding_protocols(
    protocol_choices: list[tuple[int, Any]] | None = None,
) -> list[tuple[int, Any]]:
    """Return the list of onboarding protocols permitted by the current security configuration.

    Returns:
        List of tuples (protocol_value, protocol_label) for permitted protocols.
    """
    from management.models import SecurityConfig  # noqa: PLC0415

    protocol_choices = protocol_choices or ONBOARDING_PROTOCOLS_ALLOWED_FOR_FORMS

    try:
        cfg: SecurityConfig = SecurityConfig.objects.get()
        permitted: list[int] = cfg.permitted_onboarding_protocols or []
    except SecurityConfig.DoesNotExist:
        return protocol_choices
    except SecurityConfig.MultipleObjectsReturned:
        cfg = SecurityConfig.objects.first()  # type: ignore[assignment]
        permitted = cfg.permitted_onboarding_protocols or [] if cfg else []

    if not permitted:
        return []

    return [
        (proto_value, proto_label)
        for proto_value, proto_label in protocol_choices
        if proto_value in permitted
    ]


def _get_secret(number_of_symbols: int = 16) -> str:
    """Generates a secret with the number of symbols provided.

    Args:
        number_of_symbols: Number of symbols of the generated secret. Defaults to 16.

    Returns:
        The generated secret.
    """
    return ''.join(secrets.choice(allowed_chars) for _ in range(number_of_symbols))


class CredentialDownloadForm(forms.Form):
    """Form to download a credential."""

    password = forms.CharField(
        label=_('Password'),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text=_('Must be at least %d characters long.') % PASSWORD_MIN_LENGTH,
    )

    @staticmethod
    def get_suggested_password(length: int = 16) -> str:
        """Generates a secure suggested password.

        Args:
            length: Length of the password to generate. Defaults to 16.

        Returns:
            A secure random password string.
        """
        return secrets.token_urlsafe(length)

    def clean(self) -> dict[str, Any]:
        """Checks if the passwords match and if the password is long enough."""
        cleaned_data = self.cleaned_data
        password = cleaned_data.get('password')
        if not password:
            self.add_error('password', _('Password is required.'))
            return cleaned_data

        pass_to_short_err_msg = _('Password must be at least %d characters long.') % PASSWORD_MIN_LENGTH
        if len(password) < PASSWORD_MIN_LENGTH:
            self.add_error('password', pass_to_short_err_msg)

        return cleaned_data


class BaseCredentialForm(forms.Form):
    """Base form for issuing credentials."""

    common_name = forms.CharField(max_length=255, label=_('Common Name'), required=True)
    pseudonym = forms.CharField(max_length=255, label=_('Pseudonym'), required=True, disabled=True)
    domain_component = forms.CharField(max_length=255, label=_('Domain Component'), required=True, disabled=True)
    serial_number = forms.CharField(max_length=255, label=_('Serial Number'), required=True, disabled=True)
    validity = forms.IntegerField(label=_('Validity (days)'), initial=10, required=True)

    def __init__(self, *args: Any, device: DeviceModel, **kwargs: Any) -> None:
        """Overwrite the constructor to accept the current device instance."""
        self.device = device
        super().__init__(*args, **kwargs)

    def clean_common_name(self) -> str:
        """Checks the common name."""
        common_name = cast('str', self.cleaned_data['common_name'])

        if not self.fields['common_name'].disabled:
            validate_common_name_characters(common_name)
            existing_credentials = IssuedCredentialModel.objects.filter(
                common_name=common_name, device=self.device
            )
            for cred in existing_credentials:

                if cred.credential.certificates.exclude(
                    revoked_certificate__isnull=False
                ).exists():
                    err_msg = _('Credential with common name %s already exists for device %s.') % (
                        common_name,
                        self.device.common_name,
                    )
                    raise forms.ValidationError(err_msg)

        return common_name

    def clean_validity(self) -> int:
        """Checks the validity."""
        validity = cast('int', self.cleaned_data['validity'])
        if validity <= 0:
            err_msg = _('Validity must be a positive integer.')
            raise forms.ValidationError(err_msg)
        return validity


class BaseServerCredentialForm(BaseCredentialForm):
    """Base form for issuing server credentials."""

    ipv4_addresses = forms.CharField(
        label=_('IPv4-Addresses (comma-separated list)'), initial='127.0.0.1, ', required=False
    )
    ipv6_addresses = forms.CharField(label=_('IPv6-Addresses (comma-separated list)'), initial='::1, ', required=False)
    domain_names = forms.CharField(
        label=_('Domain-Names (comma-separated list)'), initial='localhost, ', required=False
    )

    def clean_ipv4_addresses(self) -> list[ipaddress.IPv4Address]:
        """Normalize and validate IPv4 SAN input."""
        return clean_ipv4_sans(
            self.cleaned_data['ipv4_addresses'], error_message=_('Contains an invalid IPv4-Address.'),
        )

    def clean_ipv6_addresses(self) -> list[ipaddress.IPv6Address]:
        """Normalize and validate IPv6 SAN input."""
        return clean_ipv6_sans(
            self.cleaned_data['ipv6_addresses'], error_message=_('Contains an invalid IPv6-Address.'),
        )

    def clean_domain_names(self) -> list[str]:
        """Normalize and validate DNS SAN input, including leftmost wildcards."""
        return clean_dns_sans(self.cleaned_data['domain_names'], error_message=_('Contains an invalid DNS name.'))

    def clean(self) -> dict[str, Any]:
        """Ensures at least one SAN entry is set."""
        cleaned_data = self.cleaned_data
        if not (
            cleaned_data.get('ipv4_addresses') or cleaned_data.get('ipv6_addresses') or cleaned_data.get('domain_names')
        ):
            err_msg = _('At least one SAN entry is required.')
            raise forms.ValidationError(err_msg)
        return cleaned_data


class IssueDomainCredentialForm(BaseCredentialForm):
    """Form to issue a new domain credential."""

    def __init__(self, *args: Any, device: DeviceModel, **kwargs: Any) -> None:
        """Initialize the form with disabled common name field."""
        super().__init__(*args, device=device, **kwargs)
        self.fields['common_name'].disabled = True
        self.fields['common_name'].initial = 'Trustpoint Domain Credential'


class IssueTlsClientCredentialForm(BaseCredentialForm):
    """Form to issue a new TLS client credential."""


class IssueTlsServerCredentialForm(BaseServerCredentialForm):
    """Form to issue a new TLS server credential."""


class ApplicationUriFormMixin(forms.Form):
    """Adds a application_uri field to the form."""

    application_uri = forms.CharField(max_length=100, label=_('Application URI'), required=True)

    def clean_application_uri(self) -> str:
        """Checks if the application uri was set properly.

        Returns:
            The application uri.
        """
        application_uri: str = self.cleaned_data.get('application_uri', '').strip()

        if not application_uri:
            err_msg = _('Application URI entry is required.')
            raise forms.ValidationError(err_msg)

        validate_application_uri(application_uri)

        return application_uri


class IssueOpcUaClientCredentialForm(ApplicationUriFormMixin, BaseCredentialForm):
    """Form to issue a new OPC UA client credential."""


class IssueOpcUaServerCredentialForm(ApplicationUriFormMixin, BaseServerCredentialForm):
    """Form to issue a new OPC UA server credential."""


class BrowserLoginForm(forms.Form):
    """Form for the browser login via OTP for remote credential download."""

    otp = forms.CharField(widget=forms.PasswordInput(), label='OTP', max_length=32)

    def clean(self) -> dict[str, Any]:
        """Cleans the form data, extracting the credential ID and OTP."""
        cleaned_data = self.cleaned_data

        otp: str = cleaned_data.get('otp', '')
        if not otp:
            self.add_error('otp', _('This field is required.'))

        err_msg = _('The provided OTP is invalid.')

        otp_parts = otp.split('.')
        if len(otp_parts) != OTP_SPLIT_PARTS:
            raise forms.ValidationError(err_msg)
        try:
            credential_id = int(otp_parts[0])
        except ValueError as exception:
            raise forms.ValidationError(err_msg) from exception
        cleaned_data['credential_id'] = credential_id
        cleaned_data['otp'] = otp_parts[1]

        try:
            credential_download = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=credential_id)
        except RemoteDeviceCredentialDownloadModel.DoesNotExist as exception:
            err_msg = _('The credential download process is not valid, it may have expired.')
            raise forms.ValidationError(err_msg) from exception
        cleaned_data['credential_download'] = credential_download

        if not credential_download.check_otp(otp_parts[1]):
            err_msg = _('OTP is invalid.')
            raise forms.ValidationError(err_msg)

        return cleaned_data


class RevokeIssuedCredentialForm(forms.ModelForm[RevokedCertificateModel]):
    """Form to revoke a specific issued credential."""

    class Meta:
        """Meta class configuration."""

        model = RevokedCertificateModel
        fields = ('revocation_reason',)


class RevokeDevicesForm(forms.ModelForm[RevokedCertificateModel]):
    """Form to revoke a issued credentials associated with a specific device."""

    class Meta:
        """Meta class configuration."""

        model = RevokedCertificateModel
        fields = ('revocation_reason',)

    pks = forms.CharField(widget=forms.HiddenInput)


class DeleteDevicesForm(forms.Form):
    """Form to delete the requested devices."""

    pks = forms.CharField(widget=forms.HiddenInput)


class DeviceSecretCreationMixin(forms.Form):
    """Optional exact-value inputs shared by both device creation forms."""

    helper: FormHelper

    def setup_secret_inputs(self) -> None:
        """Default every selected protocol to generated credentials."""
        for field in VERSIONS:
            self.fields[f'{field}_action'] = forms.ChoiceField(
                choices=[('generate', _('Generate automatically')), ('custom', _('Enter custom secret'))],
                label=_('Secret source'),
                initial='generate',
                required=False,
            )
            self.fields[f'{field}_value'] = forms.CharField(
                required=False,
                strip=False,
                max_length=128,
                widget=forms.PasswordInput(),
                label=_('Custom secret'),
            )
            self.fields[f'{field}_confirm'] = forms.CharField(
                required=False,
                strip=False,
                max_length=128,
                widget=forms.PasswordInput(),
                label=_('Confirm secret'),
            )
            if custom_secrets_allowed():
                label = {
                    'est_password': _('EST / REST password (shared by both protocols)'),
                    'cmp_shared_secret': _('CMP shared secret'),
                    'scep_challenge': _('SCEP challengePassword'),
                }[field]
                self.helper.layout.extend(
                    [
                        HTML(f'<section data-device-secret="{field}" class="mt-4"><h2 class="h4 mb-3">{label}</h2>'),
                        Field(f'{field}_action'),
                        HTML('<div data-custom-secret>'),
                        HTML(
                            '{% load i18n %}<p class="alert alert-warning" role="alert">'
                            '{% trans "User-selected secrets may be weak or reused and reduce enrollment security." %}'
                            '</p>'
                        ),
                        Field(f'{field}_value'),
                        Field(f'{field}_confirm'),
                        HTML('</div></section>'),
                    ]
                )

    def clean(self) -> dict[str, Any]:
        """Validate explicit custom input even when controls are hidden by policy."""
        cleaned = super().clean() or {}
        if 'no_onboarding_pki_protocols' in self.fields:
            selected = {int(value) for value in cleaned.get('no_onboarding_pki_protocols', [])}
            active = {
                'cmp_shared_secret': bool(selected & {NoOnboardingPkiProtocol.CMP_SHARED_SECRET}),
                'est_password': bool(
                    selected
                    & {NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD, NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD}
                ),
                'scep_challenge': bool(selected & {NoOnboardingPkiProtocol.SCEP}),
            }
        else:
            protocol = str(cleaned.get('onboarding_protocol', ''))
            active = {
                'cmp_shared_secret': protocol == str(OnboardingProtocol.CMP_SHARED_SECRET.value),
                'est_password': protocol
                in {
                    str(OnboardingProtocol.EST_USERNAME_PASSWORD.value),
                    str(OnboardingProtocol.REST_USERNAME_PASSWORD.value),
                },
                'scep_challenge': False,
            }
        for field in VERSIONS:
            if cleaned.get(f'{field}_action') == 'custom':
                try:
                    if not active[field] or not custom_secrets_allowed():
                        raise forms.ValidationError(_('Custom secrets are unavailable for this protocol.'))  # noqa: TRY301
                    validate_custom_secret(cleaned.get(f'{field}_value'))
                    if cleaned.get(f'{field}_value') != cleaned.get(f'{field}_confirm'):
                        raise forms.ValidationError(_('The secret and confirmation do not match.'))  # noqa: TRY301
                except forms.ValidationError as exc:
                    self.add_error(f'{field}_value', exc)
            elif cleaned.get(f'{field}_value') or cleaned.get(f'{field}_confirm'):
                self.add_error(f'{field}_value', _('Select custom input to provide a value.'))
        return cleaned

    def prepare_creation_secret(self, config: OnboardingConfigModel | NoOnboardingConfigModel, field: str) -> None:
        """Revalidate policy inside the creation transaction."""
        prepare_secret(
            config,
            field,
            custom=self.cleaned_data.get(f'{field}_action') == 'custom',
            value=self.cleaned_data.get(f'{field}_value'),
        )

    def _render_pki_protocols_switches(self, field_name: str) -> str:
        """Renders PKI protocol switches as HTML."""
        field: forms.MultipleChoiceField = self.fields[field_name]  # type: ignore[assignment]
        html_parts = ['<div class="mt-2">']

        for choice in field.widget.choices:
            value, label = choice[0], choice[1]
            checked = str(value) in (self.initial.get(field_name, []) or [])
            html_parts.append(
                f'<div class="form-check form-switch mb-2">'
                f'<input type="checkbox" class="form-check-input" role="switch" '
                f'name="{field_name}" value="{value}" id="id_{field_name}_{value}" '
                f'{"checked" if checked else ""}>'
                f'<label class="form-check-label" for="id_{field_name}_{value}">{label}</label>'
                f'</div>'
            )

        html_parts.append('</div>')
        return ''.join(html_parts)

    def clean_common_name(self) -> str:
        """Validates the device name, i.e. checks if it is unique.

        Args:
            common_name: The desired name of the new device.

        Returns:
            The device name if it passed the checks.
        """
        common_name = cast('str', self.cleaned_data['common_name'])
        validate_common_name_characters(common_name)
        if DeviceModel.objects.filter(common_name=common_name).exists():
            err_msg = _('Device with this common name already exists.')
            raise forms.ValidationError(err_msg)
        return common_name


class ChangeDeviceSecretForm(forms.Form):
    """Explicit confirmation and single-credential replacement in CLM."""

    credential = forms.ChoiceField(choices=[], label=_('Credential'))
    action = forms.ChoiceField(
        label=_('Secret source'),
        choices=[
            ('generate', _('Generate automatically')),
            ('custom', _('Enter custom secret')),
        ]
    )
    value = forms.CharField(
        label=_('Custom secret'), required=False, strip=False, max_length=128, widget=forms.PasswordInput()
    )
    confirmation = forms.CharField(
        label=_('Confirm secret'), required=False, strip=False, max_length=128, widget=forms.PasswordInput()
    )

    def __init__(self, *args: Any, device: DeviceModel, **kwargs: Any) -> None:
        """Only offer eligible credentials; always enforce policy at save time."""
        super().__init__(*args, **kwargs)
        self.device = device
        config = device.onboarding_config or device.no_onboarding_config
        choices = []
        if config and not (
            isinstance(config, OnboardingConfigModel) and config.onboarding_protocol == OnboardingProtocol.AGENT
        ):
            for field, label in [
                ('cmp_shared_secret', _('CMP shared secret')),
                ('est_password', _('EST / REST password — changes both enabled protocols')),
                ('scep_challenge', _('SCEP challengePassword')),
            ]:
                try:
                    ensure_eligible(config, field)
                except forms.ValidationError:
                    continue
                choices.append((field, label))
        cast('forms.ChoiceField', self.fields['credential']).choices = choices
        self.custom_allowed = custom_secrets_allowed()
        if not self.custom_allowed:
            cast('forms.ChoiceField', self.fields['action']).choices = [('generate', _('Generate automatically'))]
        self.available = bool(choices)

    def clean(self) -> dict[str, Any]:
        """Require exact confirmation for custom replacements."""
        data = super().clean() or {}
        if data.get('action') == 'custom':
            validate_custom_secret(data.get('value'))
            if data.get('value') != data.get('confirmation'):
                raise forms.ValidationError(_('The secret and confirmation do not match.'))
        elif data.get('value') or data.get('confirmation'):
            raise forms.ValidationError(_('Generated replacements must omit custom values.'))
        return data

    def save(self, *, actor: Any) -> None:
        """Replace through the shared locked service."""
        config = self.device.onboarding_config or self.device.no_onboarding_config
        if config is None:
            raise forms.ValidationError(_('No enrollment configuration is available.'))
        assign_secret(
            config,
            self.cleaned_data['credential'],
            custom=self.cleaned_data['action'] == 'custom',
            value=self.cleaned_data.get('value'),
            device=self.device,
            actor=actor,
        )


class NoOnboardingCreateForm(DeviceSecretCreationMixin):
    """Form for device or OPC UA GDS object creation without onboarding."""

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)

    no_onboarding_pki_protocols = forms.MultipleChoiceField(
        choices=[
            (NoOnboardingPkiProtocol.CMP_SHARED_SECRET, NoOnboardingPkiProtocol.CMP_SHARED_SECRET.label),
            (NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD, NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD.label),
            (NoOnboardingPkiProtocol.MANUAL, NoOnboardingPkiProtocol.MANUAL.label),
            (NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD, NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD.label),
            (NoOnboardingPkiProtocol.SCEP, NoOnboardingPkiProtocol.SCEP.label),
        ],
        initial=NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
        widget=SwitchCheckboxSelectMultiple(),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the CreateDeviceForm."""
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.form_tag = False

        pki_protocols_html = self._render_pki_protocols_switches('no_onboarding_pki_protocols')

        self.helper.layout = Layout(
            HTML(
                '{% load i18n %}<section class="mb-5"><h2 class="h4 mb-1">'
                '{% trans "General" %}</h2><hr class="mb-4">'
            ),
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            HTML(
                '{% load i18n %}</section><section><h2 class="h4 mb-1">'
                '{% trans "PKI Protocol Configuration" %}</h2><hr class="mb-4">'
            ),
            HTML(
                '{% load i18n %}<fieldset><legend class="form-label fs-6">'
                '{% trans "Enabled PKI Protocols" %}</legend>'
            ),
            HTML(pki_protocols_html),
            HTML('</fieldset></section>'),
        )
        self.setup_secret_inputs()

    @transaction.atomic
    def save(self, device_type: DeviceModel.DeviceType) -> DeviceModel:
        """Stores the form as devie model object in the db.

        Args:
            device_type: The device type to set. Defaults to None.

        Returns:
            _description_
        """
        common_name = self.cleaned_data['common_name']
        serial_number = self.cleaned_data.get('serial_number', '')
        domain = self.cleaned_data.get('domain')

        no_onboarding_pki_protocols = [
            NoOnboardingPkiProtocol(int(protocol))
            for protocol in cast('list[str]', self.cleaned_data.get('no_onboarding_pki_protocols'))
        ]
        no_onboarding_config_model = NoOnboardingConfigModel()
        no_onboarding_config_model.set_pki_protocols(no_onboarding_pki_protocols)

        if NoOnboardingPkiProtocol.CMP_SHARED_SECRET in no_onboarding_pki_protocols:
            self.prepare_creation_secret(no_onboarding_config_model, 'cmp_shared_secret')

        if NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD in no_onboarding_pki_protocols:
            self.prepare_creation_secret(no_onboarding_config_model, 'est_password')

        rest_selected = NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD in no_onboarding_pki_protocols
        if rest_selected and not no_onboarding_config_model.est_password:
            self.prepare_creation_secret(no_onboarding_config_model, 'est_password')

        if NoOnboardingPkiProtocol.SCEP in no_onboarding_pki_protocols:
            self.prepare_creation_secret(no_onboarding_config_model, 'scep_challenge')

        no_onboarding_config_model.full_clean()

        device_model = DeviceModel(
            common_name=common_name, serial_number=serial_number, domain=domain, device_type=device_type
        )

        device_model.no_onboarding_config = no_onboarding_config_model
        device_model.full_clean()

        PermittedProtocolsAuthorization().check(device_model)

        no_onboarding_config_model.save()
        device_model.save()
        audit_assignments(no_onboarding_config_model, device=device_model, actor=getattr(self, 'actor', None))

        return device_model


class OnboardingCreateForm(DeviceSecretCreationMixin):
    """Form for device or OPC UA GDS object creation with onboarding."""

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)

    onboarding_protocol = forms.ChoiceField(
        choices=ONBOARDING_CREATE_PROTOCOLS_ALLOWED_FOR_FORMS,
        initial=OnboardingProtocol.CMP_SHARED_SECRET,
        label=_('Onboarding Protocol'),
        widget=DisableOptionsSelect(
            disabled_options=[
                OnboardingProtocol.MANUAL,
                OnboardingProtocol.AOKI,
                OnboardingProtocol.BRSKI,
                OnboardingProtocol.OPC_GDS_PUSH,
            ]
        ),
    )

    onboarding_pki_protocols = forms.MultipleChoiceField(
        choices=[
            (OnboardingPkiProtocol.CMP, OnboardingPkiProtocol.CMP.label),
            (OnboardingPkiProtocol.EST, OnboardingPkiProtocol.EST.label),
            (OnboardingPkiProtocol.REST, OnboardingPkiProtocol.REST.label),
        ],
        initial=OnboardingPkiProtocol.CMP,
        widget=SwitchCheckboxSelectMultiple(),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the CreateDeviceForm."""
        super().__init__(*args, **kwargs)

        permitted_protocols = _get_permitted_onboarding_protocols(ONBOARDING_CREATE_PROTOCOLS_ALLOWED_FOR_FORMS)
        onboarding_protocol_field = self.fields['onboarding_protocol']
        if isinstance(onboarding_protocol_field, forms.ChoiceField):
            onboarding_protocol_field.choices = permitted_protocols

        all_protocol_values = {proto[0] for proto in permitted_protocols}
        disabled_options = [
            str(proto.value) for proto in [
                OnboardingProtocol.MANUAL,
                OnboardingProtocol.AOKI,
                OnboardingProtocol.BRSKI,
                OnboardingProtocol.OPC_GDS_PUSH,
            ]
            if proto.value in all_protocol_values
        ]
        if isinstance(onboarding_protocol_field, forms.ChoiceField):
            onboarding_protocol_field.widget = DisableOptionsSelect(disabled_options=disabled_options)
            onboarding_protocol_field.widget.choices = onboarding_protocol_field.choices

        self.helper = FormHelper()
        self.helper.form_tag = False

        # Render the PKI protocols widget manually to avoid crispy-forms label rendering
        pki_protocols_html = self._render_pki_protocols_switches('onboarding_pki_protocols')

        self.helper.layout = Layout(
            HTML(
                '{% load i18n %}<section class="mb-5"><h2 class="h4 mb-1">'
                '{% trans "General" %}</h2><hr class="mb-4">'
            ),
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            HTML(
                '{% load i18n %}</section><section class="mb-5"><h2 class="h4 mb-1">'
                '{% trans "Onboarding Protocol" %}</h2><hr class="mb-4">'
            ),
            Field('onboarding_protocol'),
            HTML(
                '{% load i18n %}</section><section><h2 class="h4 mb-1">'
                '{% trans "PKI Protocol Configuration" %}</h2><hr class="mb-4">'
            ),
            HTML(
                '{% load i18n %}<fieldset><legend class="form-label fs-6">'
                '{% trans "Enabled PKI Protocols" %}</legend>'
            ),
            HTML(pki_protocols_html),
            HTML('</fieldset></section>'),
        )
        self.setup_secret_inputs()

    @transaction.atomic
    def save(self, device_type: DeviceModel.DeviceType) -> DeviceModel:
        """Stores the form as device model object in the db.

        Args:
            device_type: The device type to set. Defaults to None.

        Returns:
            _description_
        """
        common_name = self.cleaned_data['common_name']
        serial_number = self.cleaned_data.get('serial_number', '')
        domain = self.cleaned_data.get('domain')

        try:
            onboarding_protocol = OnboardingProtocol(int(self.cleaned_data['onboarding_protocol']))
        except Exception as exception:
            err_msg = 'Got an invalid value for the onboarding protocol.'
            raise forms.ValidationError(err_msg) from exception

        onboarding_pki_protocols = [
            OnboardingPkiProtocol(int(protocol))
            for protocol in self.cleaned_data['onboarding_pki_protocols']
        ]
        onboarding_config_model = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING, onboarding_protocol=onboarding_protocol
        )
        onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

        if onboarding_protocol == OnboardingProtocol.CMP_SHARED_SECRET:
            self.prepare_creation_secret(onboarding_config_model, 'cmp_shared_secret')

        if onboarding_protocol in (OnboardingProtocol.EST_USERNAME_PASSWORD, OnboardingProtocol.REST_USERNAME_PASSWORD):
            self.prepare_creation_secret(onboarding_config_model, 'est_password')

        onboarding_config_model.full_clean()

        device_model = DeviceModel(
            common_name=common_name,
            serial_number=serial_number,
            domain=domain,
            device_type=device_type,
            onboarding_config=onboarding_config_model,
        )

        device_model.full_clean()

        PermittedProtocolsAuthorization().check(device_model)

        onboarding_config_model.save()
        device_model.save()
        audit_assignments(onboarding_config_model, device=device_model, actor=getattr(self, 'actor', None))

        return device_model


class AgentOnboardingCreateForm(OnboardingCreateForm):
    """Specialised onboarding form for agent devices.

    The onboarding protocol is fixed to REST - Username & Password and the PKI
    protocol is fixed to REST.  Both values are submitted as hidden fields so
    form.save() can read them via cleaned_data without exposing the choices to
    the user.
    """

    onboarding_protocol = forms.ChoiceField(
        choices=[(OnboardingProtocol.REST_USERNAME_PASSWORD.value, OnboardingProtocol.REST_USERNAME_PASSWORD.label)],
        initial=OnboardingProtocol.REST_USERNAME_PASSWORD.value,
        label=_('Onboarding Protocol'),
        widget=forms.HiddenInput(),
        required=True,
    )

    # REST is the only allowed PKI protocol for agents — submitted as hidden input.
    onboarding_pki_protocols = forms.MultipleChoiceField(
        choices=[(OnboardingPkiProtocol.REST.value, OnboardingPkiProtocol.REST.label)],
        initial=[OnboardingPkiProtocol.REST.value],
        widget=forms.MultipleHiddenInput(),
        required=True,
    )

    # Agent-specific field for OS path where certificates will be stored
    agent_os_path = forms.CharField(
        max_length=255,
        required=True,
        label=_('Agent OS Path'),
        help_text=_(
            'The path where the agent will store certificates and keys '
            '(e.g., /etc/trustpoint or C:\\trustpoint)'
        ),
        initial='/etc/trustpoint',
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the AgentOnboardingCreateForm with fixed EST-only fields."""
        if 'initial' not in kwargs:
            kwargs['initial'] = {}
        kwargs['initial']['onboarding_protocol'] = OnboardingProtocol.REST_USERNAME_PASSWORD.value
        kwargs['initial']['onboarding_pki_protocols'] = [OnboardingPkiProtocol.REST.value]

        super().__init__(*args, **kwargs)

        onboarding_protocol_field = self.fields['onboarding_protocol']
        if isinstance(onboarding_protocol_field, forms.ChoiceField):
            onboarding_protocol_field.choices = [
                (OnboardingProtocol.REST_USERNAME_PASSWORD.value, OnboardingProtocol.REST_USERNAME_PASSWORD.label)
            ]

        onboarding_pki_protocols_field = self.fields['onboarding_pki_protocols']
        if isinstance(onboarding_pki_protocols_field, forms.MultipleChoiceField):
            onboarding_pki_protocols_field.choices = [
                (OnboardingPkiProtocol.REST.value, OnboardingPkiProtocol.REST.label)
            ]

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            HTML('<h2>General</h2><hr>'),
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            Field('agent_os_path'),
            HTML(
                '<div class="alert alert-info mt-3" role="alert">'
                + str(_('Onboarding protocol: REST - Username & Password (fixed). PKI protocol: REST (fixed).'))
                + '</div>'
            ),
            Field('onboarding_protocol'),
            Field('onboarding_pki_protocols'),
        )


class OpcUaGdsPushCreateForm(forms.Form):
    """Form for OPC UA GDS Push device creation with onboarding."""

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)
    ip_address = forms.GenericIPAddressField(protocol='both', required=True, label=_('IP Address'))
    opc_server_port = forms.IntegerField(min_value=1, max_value=65535, required=True, label=_('OPC Server Port'))
    opc_user = forms.CharField(
        max_length=128,
        required=False,
        label=_('OPC User'),
        help_text=_(
            'Optional OPC UA Server security administration user (role: SecurityAdmin). '
            'Leave username and password blank to use certificate-based authentication.'
        )
    )
    opc_password = forms.CharField(
        max_length=128,
        required=False,
        label=_('OPC Password'),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'})
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the CreateDeviceForm."""
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            HTML('<h2>General</h2><hr>'),
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            Field('ip_address'),
            Field('opc_server_port'),
            HTML('<h2>OPC UA Credentials</h2><hr>'),
            Field('opc_user'),
            Field('opc_password'),
        )

    def clean_common_name(self) -> str:
        """Validates the device name, i.e. checks if it is unique.

        Args:
            common_name: The desired name of the new device.

        Returns:
            The device name if it passed the checks.
        """
        common_name = str(self.cleaned_data.get('common_name'))
        if DeviceModel.objects.filter(common_name=common_name).exists():
            err_msg = _('Device with this common name already exists.')
            raise forms.ValidationError(err_msg)
        return common_name

    @transaction.atomic
    def save(self, device_type: DeviceModel.DeviceType) -> DeviceModel:
        """Stores the form as device model object in the db.

        Args:
            device_type: The device type to set.

        Returns:
            The created DeviceModel.
        """
        common_name = cast('str', self.cleaned_data.get('common_name'))
        serial_number = cast('str', self.cleaned_data.get('serial_number'))
        domain = cast('DomainModel | None', self.cleaned_data.get('domain'))
        ip_address = cast('str', self.cleaned_data.get('ip_address'))
        opc_server_port = cast('int', self.cleaned_data.get('opc_server_port'))
        opc_user = cast('str', self.cleaned_data.get('opc_user'))
        opc_password = cast('str', self.cleaned_data.get('opc_password'))

        onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
        onboarding_pki_protocols = [OnboardingPkiProtocol.OPC_GDS_PUSH]

        onboarding_config_model = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING,
            onboarding_protocol=onboarding_protocol,
        )
        onboarding_config_model.set_pki_protocols(onboarding_pki_protocols)

        onboarding_config_model.full_clean()

        device_model = DeviceModel(
            common_name=common_name,
            serial_number=serial_number,
            domain=domain,
            device_type=device_type,
            onboarding_config=onboarding_config_model,
            ip_address=ip_address,
        )

        config = OpcUaGdsPushConfig(
            device=device_model, opc_server_port=opc_server_port, opc_user=opc_user, opc_password=opc_password,
        )
        config.full_clean(exclude=['device'])
        device_model.full_clean()

        PermittedProtocolsAuthorization().check(device_model)

        onboarding_config_model.save()
        device_model.save()
        config, _created = OpcUaGdsPushConfig.objects.update_or_create(
            device=device_model,
            defaults={'opc_server_port': opc_server_port, 'opc_user': opc_user, 'opc_password': opc_password},
        )

        device_model.opc_ua_gds_push_config = config
        return device_model


class ClmDeviceNameValidationMixin(forms.Form):
    """Validate a device name while allowing the device to retain its current name."""

    instance: DeviceModel

    def clean_common_name(self) -> str:
        """Validates the device name, i.e. checks if it is unique.

        Returns:
            The device name if it passed the checks.
        """
        common_name = cast('str', self.cleaned_data['common_name'])
        validate_common_name_characters(common_name)
        if DeviceModel.objects.filter(common_name=common_name).exclude(pk=self.instance.pk).exists():
            err_msg = _('Device with this common name already exists.')
            raise forms.ValidationError(err_msg)
        return common_name


class ClmDeviceModelOnboardingForm(ClmDeviceNameValidationMixin):
    """CLM Device Model form for devices that use onboarding."""

    actor: Any = None

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)

    onboarding_protocol = forms.TypedChoiceField(
        choices=ONBOARDING_PROTOCOLS_ALLOWED_FOR_FORMS,
        label='Onboarding Protocol',
        coerce=int,
        widget=forms.Select(attrs={'disabled': 'disabled'}),
        required=False,
    )
    onboarding_status = forms.CharField(
        label='Onboading Status',
        widget=forms.TextInput(attrs={'readonly': 'readonly', 'class': 'readonly-field form-control'}),
    )

    pki_protocol_cmp = forms.BooleanField(label='CMP', required=False)
    pki_protocol_est = forms.BooleanField(label='EST', required=False)
    pki_protocol_rest = forms.BooleanField(label='REST', required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the form."""
        self.instance: DeviceModel = kwargs.pop('instance')

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            HTML('<h2>Device Onboarding Configuration</h2><hr>'),
            Field('onboarding_protocol'),
            Field('onboarding_status'),
            HTML('<h2>Enabled PKI-Protocols</h2><hr>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_cmp'),
            HTML('</div>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_est'),
            HTML('</div>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_rest'),
            HTML('</div>'),
            HTML('<hr>'),
        )

        super().__init__(*args, **kwargs)

    def save(self, onboarding_protocol: OnboardingProtocol) -> None:
        """Saves the changes to DB."""
        if not self.instance.onboarding_config:
            err_msg = _('Expected DeviceModel that is configured to use onboarding.')
            raise forms.ValidationError(err_msg)

        with transaction.atomic():
            self.instance.common_name = self.cleaned_data['common_name']
            self.instance.serial_number = self.cleaned_data['serial_number']
            self.instance.domain = self.cleaned_data['domain']

            onboarding_protocol_selected = onboarding_protocol
            self.instance.onboarding_config.onboarding_protocol = onboarding_protocol
            if onboarding_protocol_selected == OnboardingProtocol.MANUAL:
                self.instance.onboarding_config.cmp_shared_secret = ''
                self.instance.onboarding_config.est_password = ''

            if onboarding_protocol_selected == OnboardingProtocol.CMP_SHARED_SECRET:
                self.instance.onboarding_config.est_password = ''
                if (not self.instance.onboarding_config.cmp_shared_secret
                    and self.instance.onboarding_config.onboarding_status != OnboardingStatus.ONBOARDED):
                    prepare_secret(self.instance.onboarding_config, 'cmp_shared_secret')

            if onboarding_protocol_selected in (
                OnboardingProtocol.EST_USERNAME_PASSWORD,
                OnboardingProtocol.REST_USERNAME_PASSWORD,
                OnboardingProtocol.AGENT,
            ):
                self.instance.onboarding_config.cmp_shared_secret = ''
                if (not self.instance.onboarding_config.est_password
                    and self.instance.onboarding_config.onboarding_status != OnboardingStatus.ONBOARDED):
                    prepare_secret(self.instance.onboarding_config, 'est_password')

            self.instance.onboarding_config.clear_pki_protocols()
            if self.cleaned_data['pki_protocol_cmp'] is True:
                self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.CMP)
            if self.cleaned_data['pki_protocol_est'] is True:
                self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.EST)
            if self.cleaned_data['pki_protocol_rest'] is True:
                self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.REST)

            self.instance.onboarding_config.full_clean()
            self.instance.onboarding_config.save()
            self.instance.full_clean()
            self.instance.save()
            audit_assignments(self.instance.onboarding_config, device=self.instance, actor=self.actor)


class ClmDeviceModelOpcUaGdsPushOnboardingForm(forms.Form):
    """CLM Device Model form for OPC UA GDS Push devices that use onboarding."""

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)
    ip_address = forms.GenericIPAddressField(protocol='both', required=True, label=_('IP Address'))
    opc_server_port = forms.IntegerField(min_value=1, max_value=65535, required=True, label=_('OPC Server Port'))
    opc_user = forms.CharField(
        max_length=128,
        required=False,
        label=_('OPC User'),
        help_text=_(
            'Optional OPC UA Server security administration user (role: SecurityAdmin). '
            'Leave username and password blank to use certificate-based authentication.'
        )
    )
    opc_password = forms.CharField(
        max_length=128,
        required=False,
        label=_('OPC Password'),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'placeholder': '••••••••'})
    )
    truststore_queryset: QuerySet[TruststoreModel] = TruststoreModel.objects.filter(
        intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH
    )
    opc_trust_store = forms.ModelChoiceField(
        queryset=truststore_queryset, empty_label='----------', required=False, label=_('OPC UA Trust Store')
    )

    onboarding_protocol = forms.CharField(
        label='Onboarding Protocol',
        widget=forms.TextInput(attrs={'readonly': 'readonly', 'class': 'readonly-field form-control'}),
        required=False,
    )
    onboarding_status = forms.CharField(
        label='Onboarding Status',
        widget=forms.TextInput(attrs={'readonly': 'readonly', 'class': 'readonly-field form-control'}),
    )

    pki_protocol_opc_gds_push = forms.BooleanField(label='OPC - GDS Push', required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the form."""
        self.instance: DeviceModel = kwargs.pop('instance')

        config = getattr(self.instance, 'opc_ua_gds_push_config', None)
        initial = kwargs.get('initial', {})
        initial.update({
            'common_name': self.instance.common_name,
            'serial_number': self.instance.serial_number,
            'domain': self.instance.domain,
            'ip_address': self.instance.ip_address,
            'opc_server_port': config.opc_server_port if config else 4840,
            'opc_user': (
                config.opc_user
                if config else ''
            ),
            'opc_password': (
                config.opc_password
                if config else ''
            ),
            'opc_trust_store': (
                config.opc_trust_store
                if config else None
            ),
            'onboarding_protocol': (
                OnboardingProtocol(self.instance.onboarding_config.onboarding_protocol).label
                if self.instance.onboarding_config else ''
            ),
            'onboarding_status': (
                OnboardingStatus(self.instance.onboarding_config.onboarding_status).label
                if self.instance.onboarding_config else ''
            ),
            'pki_protocol_opc_gds_push': (
                self.instance.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)
                if self.instance.onboarding_config else False
            ),
        })
        kwargs['initial'] = initial

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            Field('ip_address'),
            Field('opc_server_port'),
            HTML('<h2>OPC UA Credentials</h2><hr>'),
            Field('opc_user'),
            Field('opc_password'),
            Field('opc_trust_store'),
            HTML('<h2>Device Onboarding Configuration</h2><hr>'),
            Field('onboarding_protocol'),
            Field('onboarding_status'),
            HTML('<h2>Enabled PKI-Protocols</h2><hr>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_opc_gds_push'),
            HTML('</div>'),
            HTML('<hr>'),
        )

        super().__init__(*args, **kwargs)

    def save(self) -> None:
        """Saves the changes to DB."""
        if not self.instance.onboarding_config:
            err_msg = _('Expected DeviceModel that is configured to use onboarding.')
            raise forms.ValidationError(err_msg)

        with transaction.atomic():
            self.instance.common_name = self.cleaned_data['common_name']
            self.instance.serial_number = self.cleaned_data['serial_number']
            self.instance.domain = self.cleaned_data['domain']
            self.instance.ip_address = self.cleaned_data['ip_address']
            self.instance.opc_ua_gds_push_config.opc_server_port = self.cleaned_data['opc_server_port']
            self.instance.opc_ua_gds_push_config.opc_user = self.cleaned_data['opc_user']
            self.instance.opc_ua_gds_push_config.opc_password = self.cleaned_data['opc_password']
            self.instance.opc_ua_gds_push_config.opc_trust_store = self.cleaned_data['opc_trust_store']

            self.instance.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
            self.instance.onboarding_config.clear_pki_protocols()
            if self.cleaned_data['pki_protocol_opc_gds_push'] is True:
                self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)

            self.instance.onboarding_config.full_clean()
            self.instance.onboarding_config.save()
            self.instance.opc_ua_gds_push_config.full_clean()
            self.instance.opc_ua_gds_push_config.save()
            self.instance.full_clean()
            self.instance.save()


class ClmDeviceModelNoOnboardingForm(ClmDeviceNameValidationMixin):
    """CLM Device Model form for devices that do not use onboarding."""

    actor: Any = None

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)

    pki_protocol_cmp = forms.BooleanField(label='CMP - Shared-Secret (HMAC)', required=False)
    pki_protocol_est = forms.BooleanField(label='EST - Username & Password', required=False)
    pki_protocol_manual = forms.BooleanField(label='Manual', required=False)
    pki_protocol_rest = forms.BooleanField(label='REST - Username & Password', required=False)
    pki_protocol_scep = forms.BooleanField(label='SCEP', required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the form."""
        self.instance: DeviceModel = kwargs.pop('instance')

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            HTML('<h2>Enabled PKI-Protocols</h2><hr>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_cmp'),
            HTML('</div>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_est'),
            HTML('</div>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_manual'),
            HTML('</div>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_rest'),
            HTML('</div>'),
            HTML('<div class="form-check form-switch">'),
            Field('pki_protocol_scep'),
            HTML('</div>'),
            HTML('<hr>'),
        )

        super().__init__(*args, **kwargs)

    @transaction.atomic
    def save(self) -> None: # noqa: C901
        """Saves the changes to DB."""
        if not self.instance.no_onboarding_config:
            err_msg = _('Expected DeviceModel that is configured to use onboarding.')
            raise forms.ValidationError(err_msg)

        with transaction.atomic():
            self.instance.common_name = self.cleaned_data['common_name']
            self.instance.serial_number = self.cleaned_data['serial_number']
            self.instance.domain = self.cleaned_data['domain']

        self.instance.no_onboarding_config.clear_pki_protocols()
        if self.cleaned_data['pki_protocol_cmp'] is True:
            self.instance.no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET)
            if self.instance.no_onboarding_config.cmp_shared_secret == '':
                prepare_secret(self.instance.no_onboarding_config, 'cmp_shared_secret')
        else:
            self.instance.no_onboarding_config.cmp_shared_secret = ''

        if self.cleaned_data['pki_protocol_est'] is True:
            self.instance.no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD)
            if self.instance.no_onboarding_config.est_password == '':
                prepare_secret(self.instance.no_onboarding_config, 'est_password')

        if self.cleaned_data['pki_protocol_manual'] is True:
            self.instance.no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.MANUAL)

        if self.cleaned_data['pki_protocol_rest'] is True:
            self.instance.no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD)
            if self.instance.no_onboarding_config.est_password == '':
                prepare_secret(self.instance.no_onboarding_config, 'est_password')

        est_enabled = self.cleaned_data['pki_protocol_est'] is True
        rest_enabled = self.cleaned_data['pki_protocol_rest'] is True
        if self.cleaned_data['pki_protocol_scep'] is True:
            self.instance.no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.SCEP)
            if not self.instance.no_onboarding_config.scep_challenge:
                prepare_secret(self.instance.no_onboarding_config, 'scep_challenge')
        if not est_enabled and not rest_enabled:
            self.instance.no_onboarding_config.est_password = ''

        self.instance.no_onboarding_config.full_clean()
        self.instance.no_onboarding_config.save()
        self.instance.full_clean()
        self.instance.save()
        audit_assignments(self.instance.no_onboarding_config, device=self.instance, actor=self.actor)


class OpcUaGdsPushTruststoreAssociationForm(forms.Form):
    """Form for associating a truststore with an OPC UA GDS Push device's onboarding configuration."""

    truststore_queryset: QuerySet[TruststoreModel] = TruststoreModel.objects.filter(
        intended_usage=TruststoreModel.IntendedUsage.OPC_UA_GDS_PUSH
    )
    opc_trust_store = forms.ModelChoiceField(
        queryset=truststore_queryset, empty_label='----------', required=True, label=_('OPC UA Trust Store')
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the form."""
        self.instance: DeviceModel = kwargs.pop('instance')

        self.helper = FormHelper()
        self.helper.layout = Layout(
            HTML('<h2>Associate Trust Store</h2>'),
            HTML("<p>Select a trust store to associate with this device's onboarding configuration.</p>"),
            Field('opc_trust_store'),
            HTML('<hr>'),
            Submit('submit', _('Associate Trust Store'), css_class='btn btn-primary w-100'),
            HTML('<hr>'),
        )

        super().__init__(*args, **kwargs)

    def save(self) -> None:
        """Save the truststore association to the device's GDS Push configuration."""
        if not self.instance.onboarding_config:
            err_msg = _('Expected DeviceModel that is configured to use onboarding.')
            raise forms.ValidationError(err_msg)

        with transaction.atomic():
            self.instance.opc_ua_gds_push_config.opc_trust_store = self.cleaned_data['opc_trust_store']
            self.instance.opc_ua_gds_push_config.full_clean()
            self.instance.opc_ua_gds_push_config.save(update_fields=['opc_trust_store'])


class ClmAgentDeviceForm(ClmDeviceNameValidationMixin):
    """CLM form for agent devices."""

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)

    onboarding_protocol = forms.TypedChoiceField(
        choices=ONBOARDING_PROTOCOLS_ALLOWED_FOR_FORMS,
        label='Onboarding Protocol',
        coerce=int,
        widget=forms.Select(attrs={'disabled': 'disabled'}),
        required=False,
    )
    onboarding_status = forms.CharField(
        label='Onboarding Status',
        widget=forms.TextInput(attrs={'readonly': 'readonly', 'class': 'readonly-field form-control'}),
    )

    # Agent-specific fields
    poll_interval_seconds = forms.IntegerField(
        label=_('Poll Interval (seconds)'),
        min_value=1,
        initial=300,
        help_text=_(
            'How often the agent should check in with the server.'
        ),
    )
    os_path = forms.CharField(
        max_length=255,
        label=_('OS Path'),
        initial='/etc/trustpoint',
        help_text=_(
            'The operating system path where the agent stores certificates and keys.'
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the form."""
        self.instance: DeviceModel = kwargs.pop('instance')

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            HTML('<h2>Device Onboarding Configuration</h2><hr>'),
            Field('onboarding_protocol'),
            Field('onboarding_status'),
            HTML('<h2>Agent Configuration</h2><hr>'),
            Field('poll_interval_seconds'),
            Field('os_path'),
            HTML('<hr>'),
        )

        super().__init__(*args, **kwargs)

    def save(self, onboarding_protocol: OnboardingProtocol) -> None:
        """Saves the changes to DB including agent-specific fields."""
        if not self.instance.onboarding_config:
            err_msg = _('Expected DeviceModel that is configured to use onboarding.')
            raise forms.ValidationError(err_msg)

        with transaction.atomic():
            self.instance.common_name = self.cleaned_data['common_name']
            self.instance.serial_number = self.cleaned_data['serial_number']
            self.instance.domain = self.cleaned_data['domain']

            # Set REST as the only protocol for agents
            self.instance.onboarding_config.onboarding_protocol = onboarding_protocol
            self.instance.onboarding_config.clear_pki_protocols()
            self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.REST)

            # Set password if not already set
            if (not self.instance.onboarding_config.est_password
                and self.instance.onboarding_config.onboarding_status != OnboardingStatus.ONBOARDED):
                self.instance.onboarding_config.est_password = _get_secret()

            self.instance.onboarding_config.full_clean()
            self.instance.onboarding_config.save()
            self.instance.full_clean()
            self.instance.save()

            # Update TrustpointAgent fields if this device has an agent
            from agents.models import TrustpointAgent  # noqa: PLC0415

            agent = TrustpointAgent.objects.filter(device=self.instance).first()
            if agent:
                agent.poll_interval_seconds = self.cleaned_data['poll_interval_seconds']
                agent.os_path = self.cleaned_data['os_path']
                # Ensure capabilities is set to avoid validation error
                if agent.capabilities is None:
                    agent.capabilities = []
                agent.full_clean()
                agent.save()
