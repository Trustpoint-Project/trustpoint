"""Forms exclusively used in the device application."""

from __future__ import annotations

import ipaddress
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
    IssuedCredentialModel,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
    RemoteDeviceCredentialDownloadModel,
)
from devices.utils import validate_application_uri, validate_common_name_characters
from pki.models.certificate import RevokedCertificateModel
from pki.models.domain import DomainModel
from pki.models.truststore import TruststoreModel
from trustpoint.forms import DisableOptionsSelect
from util.field import UniqueNameValidator

if TYPE_CHECKING:
    from django.db.models.query import QuerySet

PASSWORD_MIN_LENGTH = 12
OTP_SPLIT_PARTS = 2
ALLOWED_CHARS = allowed_chars = string.ascii_letters + string.digits


ONBOARDING_PROTOCOLS_ALLOWED_FOR_FORMS = [
    (OnboardingProtocol.CMP_SHARED_SECRET.value, OnboardingProtocol.CMP_SHARED_SECRET.label),
    (OnboardingProtocol.EST_USERNAME_PASSWORD.value, OnboardingProtocol.EST_USERNAME_PASSWORD.label),
    (OnboardingProtocol.MANUAL.value, OnboardingProtocol.MANUAL.label),
    (OnboardingProtocol.AOKI.value, OnboardingProtocol.AOKI.label),
    (OnboardingProtocol.BRSKI.value, OnboardingProtocol.BRSKI.label),
    (OnboardingProtocol.OPC_GDS_PUSH.value, OnboardingProtocol.OPC_GDS_PUSH.label),
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
        """Checks the IPv4 addresses."""
        data = self.cleaned_data['ipv4_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv4Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError as exception:
            err_msg = _('Contains an invalid IPv4-Address.')
            raise forms.ValidationError(err_msg) from exception

    def clean_ipv6_addresses(self) -> list[ipaddress.IPv6Address]:
        """Checks the IPv6 addresses."""
        data = self.cleaned_data['ipv6_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv6Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError as exception:
            err_msg = _('Contains an invalid IPv6-Address.')
            raise forms.ValidationError(err_msg) from exception

    def clean_domain_names(self) -> list[str]:
        """Checks the domain names."""
        data = self.cleaned_data['domain_names'].strip()
        return [domain.strip() for domain in data.split(',') if domain.strip()]

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


class IssueOpcUaGdsPushDomainCredentialForm(ApplicationUriFormMixin, BaseCredentialForm):
    """Form to issue a new OPC UA GDS Push domain credential."""

    def __init__(self, *args: Any, device: DeviceModel, **kwargs: Any) -> None:
        """Initialize the form with disabled common name field."""
        super().__init__(*args, device=device, **kwargs)
        self.fields['common_name'].disabled = True
        self.fields['common_name'].initial = 'Trustpoint Domain Credential'


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


class NoOnboardingCreateForm(forms.Form):
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
        ],
        initial=NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
        widget=forms.CheckboxSelectMultiple,
        label=_('Enabled PKI Protocols'),
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
            HTML('<h2 class="mt-5">PKI Protocol Configuration</h2><hr>'),
            Field('no_onboarding_pki_protocols'),
        )

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
            no_onboarding_config_model.cmp_shared_secret = _get_secret()

        if NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD in no_onboarding_pki_protocols:
            no_onboarding_config_model.est_password = _get_secret()

        no_onboarding_config_model.full_clean()

        device_model = DeviceModel(
            common_name=common_name, serial_number=serial_number, domain=domain, device_type=device_type
        )

        device_model.no_onboarding_config = no_onboarding_config_model
        device_model.full_clean()

        no_onboarding_config_model.save()
        device_model.save()

        return device_model


class OnboardingCreateForm(forms.Form):
    """Form for device or OPC UA GDS object creation with onboarding."""

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)

    onboarding_protocol = forms.ChoiceField(
        choices=ONBOARDING_PROTOCOLS_ALLOWED_FOR_FORMS,
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
        ],
        initial=OnboardingPkiProtocol.CMP,
        widget=forms.CheckboxSelectMultiple,
        label=_('Enabled PKI Protocols'),
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
            HTML('<h2 class="mt-5">Onboarding Protocol</h2><hr>'),
            Field('onboarding_protocol'),
            HTML('<h2 class="mt-5">PKI Protocol Configuration</h2><hr>'),
            Field('onboarding_pki_protocols'),
        )

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
            onboarding_config_model.cmp_shared_secret = _get_secret()

        if onboarding_protocol == OnboardingProtocol.EST_USERNAME_PASSWORD:
            onboarding_config_model.est_password = _get_secret()

        onboarding_config_model.full_clean()

        device_model = DeviceModel(
            common_name=common_name,
            serial_number=serial_number,
            domain=domain,
            device_type=device_type,
            onboarding_config=onboarding_config_model,
        )

        device_model.full_clean()

        onboarding_config_model.save()
        device_model.save()

        return device_model


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
        help_text=_('OPC UA Server security administration user (role: SecurityAdmin)')
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
            opc_user=opc_user,
            opc_password=opc_password
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
            opc_server_port=opc_server_port,
        )

        device_model.full_clean()

        onboarding_config_model.save()
        device_model.save()

        return device_model


class ClmDeviceModelOnboardingForm(forms.Form):
    """CLM Device Model form for devices that use onboarding."""

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
            Field('pki_protocol_cmp'),
            Field('pki_protocol_est'),
            HTML('<hr>'),
            Submit('submit', _('Apply Changes'), css_class='btn btn-primary w-100'),
        )

        super().__init__(*args, **kwargs)

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
            if onboarding_protocol_selected == OnboardingProtocol.MANUAL:
                self.instance.onboarding_config.cmp_shared_secret = ''
                self.instance.onboarding_config.est_password = ''

            if onboarding_protocol_selected == OnboardingProtocol.CMP_SHARED_SECRET:
                self.instance.onboarding_config.est_password = ''
                if not self.instance.onboarding_config.cmp_shared_secret:
                    self.instance.onboarding_config.cmp_shared_secret = _get_secret()

            if onboarding_protocol_selected == OnboardingProtocol.EST_USERNAME_PASSWORD:
                self.instance.onboarding_config.cmp_shared_secret = ''
                if not self.instance.onboarding_config.est_password:
                    self.instance.onboarding_config.est_password = _get_secret()

            self.instance.onboarding_config.onboarding_protocol = onboarding_protocol
            self.instance.onboarding_config.clear_pki_protocols()
            if self.cleaned_data['pki_protocol_cmp'] is True:
                self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.CMP)
            if self.cleaned_data['pki_protocol_est'] is True:
                self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.EST)

            self.instance.onboarding_config.full_clean()
            self.instance.onboarding_config.save()
            self.instance.full_clean()
            self.instance.save()


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
        help_text=_('OPC UA Server security administration user (role: SecurityAdmin)')
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

        initial = kwargs.get('initial', {})
        initial.update({
            'common_name': self.instance.common_name,
            'serial_number': self.instance.serial_number,
            'domain': self.instance.domain,
            'ip_address': self.instance.ip_address,
            'opc_server_port': self.instance.opc_server_port,
            'opc_user': (
                self.instance.onboarding_config.opc_user
                if self.instance.onboarding_config else ''
            ),
            'opc_password': (
                self.instance.onboarding_config.opc_password
                if self.instance.onboarding_config else ''
            ),
            'opc_trust_store': (
                self.instance.onboarding_config.opc_trust_store
                if self.instance.onboarding_config else None
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
            Field('pki_protocol_opc_gds_push'),
            HTML('<hr>'),
            Submit('submit', _('Apply Changes'), css_class='btn btn-primary w-100'),
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
            self.instance.opc_server_port = self.cleaned_data['opc_server_port']
            self.instance.onboarding_config.opc_user = self.cleaned_data['opc_user']
            self.instance.onboarding_config.opc_password = self.cleaned_data['opc_password']
            self.instance.onboarding_config.opc_trust_store = self.cleaned_data['opc_trust_store']

            self.instance.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
            self.instance.onboarding_config.clear_pki_protocols()
            if self.cleaned_data['pki_protocol_opc_gds_push'] is True:
                self.instance.onboarding_config.add_pki_protocol(OnboardingPkiProtocol.OPC_GDS_PUSH)

            self.instance.onboarding_config.full_clean()
            self.instance.onboarding_config.save()
            self.instance.full_clean()
            self.instance.save()


class ClmDeviceModelNoOnboardingForm(forms.Form):
    """CLM Device Model form for devices that do not use onboarding."""

    common_name = forms.CharField(max_length=100, validators=[UniqueNameValidator()])
    serial_number = forms.CharField(max_length=100, required=False)
    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label='----------', required=False)

    pki_protocol_cmp = forms.BooleanField(label='CMP - Shared-Secret (HMAC)', required=False)
    pki_protocol_est = forms.BooleanField(label='EST - Username & Password', required=False)
    pki_protocol_manual = forms.BooleanField(label='Manual', required=False)

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
            Field('pki_protocol_cmp'),
            Field('pki_protocol_est'),
            Field('pki_protocol_manual'),
            HTML('<hr>'),
            Submit('submit', _('Apply Changes'), css_class='btn btn-primary w-100'),
        )

        super().__init__(*args, **kwargs)

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

    def save(self) -> None:
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
                self.instance.no_onboarding_config.cmp_shared_secret = _get_secret()
        else:
            self.instance.no_onboarding_config.cmp_shared_secret = ''

        if self.cleaned_data['pki_protocol_est'] is True:
            self.instance.no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD)
            if self.instance.no_onboarding_config.est_password == '':
                self.instance.no_onboarding_config.est_password = _get_secret()
        else:
            self.instance.no_onboarding_config.est_password = ''

        if self.cleaned_data['pki_protocol_manual'] is True:
            self.instance.no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.MANUAL)

        self.instance.no_onboarding_config.full_clean()
        self.instance.no_onboarding_config.save()
        self.instance.full_clean()
        self.instance.save()


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
        """Saves the truststore association to the device's onboarding config."""
        if not self.instance.onboarding_config:
            err_msg = _('Expected DeviceModel that is configured to use onboarding.')
            raise forms.ValidationError(err_msg)

        with transaction.atomic():
            self.instance.onboarding_config.opc_trust_store = self.cleaned_data['opc_trust_store']
            self.instance.onboarding_config.full_clean()
            self.instance.onboarding_config.save()


class OpcUaGdsPushTruststoreMethodSelectForm(forms.Form):
    """Form for selecting the method to associate a truststore with an OPC UA GDS Push device.

    Attributes:
        method_select (ChoiceField): A dropdown to select the method for truststore association.
            - `upload_truststore`: Upload a new truststore prior to association.
            - `select_truststore`: Use an existing truststore for association.
    """

    method_select = forms.ChoiceField(
        label=_('Select Method'),
        choices=[
            ('upload_truststore', _('Upload a new truststore prior to association')),
            ('select_truststore', _('Use an existing truststore for association')),
        ],
        initial='select_truststore',
        required=True,
    )
