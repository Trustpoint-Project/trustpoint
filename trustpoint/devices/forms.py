"""Forms exclusively used in the device application."""

from __future__ import annotations

import ipaddress
import secrets
import typing
from typing import TYPE_CHECKING, Any, cast

from crispy_bootstrap5.bootstrap5 import Field
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Div, Layout
from django import forms
from django.forms import models
from django.utils.translation import gettext_lazy as _
from pki.models.certificate import RevokedCertificateModel
from pki.models.domain import DomainModel
from pki.models.truststore import TruststoreModel
from util.field import UniqueNameValidator

from devices.models import DeviceModel, IssuedCredentialModel, RemoteDeviceCredentialDownloadModel
from devices.widgets import DisableSelectOptionsWidget
from trustpoint.forms import CleanedDataNotNoneMixin

if TYPE_CHECKING:
    from django.db.models.query import QuerySet

PASSWORD_MIN_LENGTH = 12
OTP_SPLIT_PARTS = 2


class IssueDomainCredentialForm(forms.Form):
    """Form to issue a new domain credential."""

    common_name = forms.CharField(max_length=255, label=_('Common Name'), required=True, disabled=True)
    domain_component = forms.CharField(max_length=255, label=_('Domain Component'), required=True, disabled=True)
    serial_number = forms.CharField(max_length=255, label=_('Serial Number'), required=True, disabled=True)


class CredentialDownloadForm(CleanedDataNotNoneMixin, forms.Form):
    """Form to download a credential."""

    password = forms.CharField(
        label=_('Password'),
        widget=forms.PasswordInput,
        help_text=_('Must be at least %d characters long.') % PASSWORD_MIN_LENGTH,
    )
    confirm_password = forms.CharField(label=_('Confirm Password'), widget=forms.PasswordInput)

    def clean(self) -> dict[str, Any]:
        """Checks if the passwords match and if the password is long enough."""
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password:
            if password != confirm_password:
                self.add_error('confirm_password', _('Passwords do not match.'))

            if len(password) < PASSWORD_MIN_LENGTH:
                self.add_error('password', _('Password must be at least %d characters long.') % PASSWORD_MIN_LENGTH)

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

        default_cn = device.common_name + '-' + self.__class__.__name__.replace('Form', '').replace('Issue', '')
        self.fields['common_name'].initial = default_cn

    def clean_common_name(self) -> str:
        """Checks the common name."""
        common_name = cast(str, self.cleaned_data['common_name'])
        if IssuedCredentialModel.objects.filter(common_name=common_name, device=self.device).exists():
            err_msg = _('Credential with common name %s already exists for device %s.') % (
                common_name,
                self.device.common_name,
            )
            raise forms.ValidationError(err_msg)
        return common_name

    def clean_validity(self) -> int:
        """Checks the validity."""
        validity = cast(int, self.cleaned_data['validity'])
        if validity <= 0:
            err_msg = _('Validity must be a positive integer.')
            raise forms.ValidationError(err_msg)
        return validity


class BaseServerCredentialForm(CleanedDataNotNoneMixin, BaseCredentialForm):
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
        cleaned_data = super().clean()
        if not (
            cleaned_data.get('ipv4_addresses') or cleaned_data.get('ipv6_addresses') or cleaned_data.get('domain_names')
        ):
            err_msg = _('At least one SAN entry is required.')
            raise forms.ValidationError(err_msg)
        return cleaned_data


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

        return application_uri


class IssueOpcUaClientCredentialForm(CleanedDataNotNoneMixin, ApplicationUriFormMixin, BaseCredentialForm):
    """Form to issue a new OPC UA client credential."""


class IssueOpcUaServerCredentialForm(ApplicationUriFormMixin, BaseServerCredentialForm):
    """Form to issue a new OPC UA server credential."""


class BrowserLoginForm(CleanedDataNotNoneMixin, forms.Form):
    """Form for the browser login via OTP for remote credential download."""

    otp = forms.CharField(widget=forms.PasswordInput(), label='OTP', max_length=32)

    def clean(self) -> dict[str, Any]:
        """Cleans the form data, extracting the credential ID and OTP."""
        cleaned_data = super().clean()

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


class CredentialRevocationForm(forms.ModelForm[RevokedCertificateModel]):
    """Form to revoke a device credential."""

    class Meta:
        """Meta class configuration."""

        model = RevokedCertificateModel
        fields: typing.ClassVar = ['revocation_reason']


class CreateDeviceForm(CleanedDataNotNoneMixin, forms.ModelForm[DeviceModel]):
    """The CreateDeviceForm class."""

    class Meta:
        """Meta class configuration."""

        model = DeviceModel
        fields: typing.ClassVar = [
            'common_name',
            'serial_number',
            'domain',
            'domain_credential_onboarding',
            'onboarding_and_pki_configuration',
            'idevid_trust_store',
            'pki_configuration',
        ]
        labels: typing.ClassVar = {
            'domain_credential_onboarding': _('Domain Credential Onboarding'),
            'onboarding_and_pki_configuration': _('Onboarding and PKI configuration'),
        }

    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(queryset=domain_queryset, empty_label=None, required=True)

    onboarding_and_pki_configuration = forms.ChoiceField(
        choices=[
            ('cmp_shared_secret', _('CMP with shared secret onboarding')),
            ('cmp_idevid', _('CMP with IDevID onboarding')),
            ('aoki_cmp', _('CMP with AOKI onboarding')),
            ('brski_cmp', _('CMP with BRSKI onboarding')),
            ('est_username_password', _('EST with username and password onboarding')),
            ('est_idevid', _('EST with IDevID onboarding')),
            ('aoki_est', _('EST with AOKI onboarding')),
            ('brski_est', _('EST with BRSKI onboarding')),
        ],
        widget=DisableSelectOptionsWidget(
            disabled_values=['aoki_est', 'brski_est', 'aoki_cmp', 'brski_cmp']
        ),
        initial='cmp_idevid',
    )

    pki_configuration = forms.ChoiceField(
        choices=[
            ('manual_download', _('Manual Download')),
            ('cmp_shared_secret', _('CMP with shared secret authentication')),
            ('est_username_password', _('EST with username and password authentication')),
        ],
        widget=DisableSelectOptionsWidget(disabled_values=[]),
        initial='cmp_shared_secret',
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the CreateDeviceForm."""
        super().__init__(*args, **kwargs)

        idevid_trust_store_field = cast(models.ModelChoiceField[TruststoreModel], self.fields['idevid_trust_store'])
        idevid_trust_store_field.queryset = TruststoreModel.objects.filter(
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            HTML('<h2>General</h2><hr>'),
            Field('common_name'),
            Field('serial_number'),
            Field('domain'),
            HTML('<h2 class="mt-5">Onboarding Configuration</h2><hr>'),
            Field('domain_credential_onboarding'),
            HTML('<h2 class="mt-5">PKI Configuration</h2><hr>'),
            Div(
                Field('onboarding_and_pki_configuration'),
                Div(Field('idevid_trust_store'), id='id_idevid_trust_store_select_wrapper'),
                id='id_onboarding_and_pki_configuration_wrapper',
            ),
            Div(Field('pki_configuration'), css_class='d-none', id='id_pki_configuration_wrapper'),
            HTML('<div class="mb-4"></div>'),
        )
        self.fields['domain'].widget.attrs.update({'required': 'True'})

    @staticmethod
    def clean_device_name(device_name: str) -> str:
        """Validates the device name, i.e. checks if it is unique.

        Args:
            device_name: The desired name of the new device.

        Returns:
            The device name if it passed the checks.
        """
        UniqueNameValidator(device_name)
        return device_name

    def clean(self) -> dict[str, Any]:
        """Cleans the form data.

        Returns:
            The cleaned form data.
        """
        cleaned_data = super().clean()
        instance: DeviceModel = super().save(commit=False)
        domain_credential_onboarding = cleaned_data.get('domain_credential_onboarding')
        if domain_credential_onboarding:
            instance.onboarding_status = DeviceModel.OnboardingStatus.PENDING
            onboarding_and_pki_configuration = cleaned_data.get('onboarding_and_pki_configuration')

            # TODO(AlexHx8472): Integrate EST   # noqa: FIX002
            match onboarding_and_pki_configuration:
                case 'cmp_shared_secret':
                    instance.onboarding_protocol = DeviceModel.OnboardingProtocol.CMP_SHARED_SECRET
                    instance.pki_protocol = DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE
                    instance.idevid_trust_store = None
                    # 16 * 8 = 128 random bits
                    instance.cmp_shared_secret = secrets.token_urlsafe(16)
                case 'cmp_idevid':
                    idevid_trust_store = cleaned_data.get('idevid_trust_store')
                    if not idevid_trust_store:
                        err_msg = 'Must specify an IDevID Trust-Store for IDevID onboarding.'
                        raise forms.ValidationError(err_msg)
                    if idevid_trust_store.intended_usage != TruststoreModel.IntendedUsage.IDEVID.value:
                        err_msg = 'The Trust-Store must have the intended usage IDevID.'
                        raise forms.ValidationError(err_msg)
                    instance.onboarding_protocol = DeviceModel.OnboardingProtocol.CMP_IDEVID
                    instance.pki_protocol = DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE
                case 'est_username_password':
                    instance.onboarding_protocol = DeviceModel.OnboardingProtocol.EST_PASSWORD
                    instance.pki_protocol = DeviceModel.PkiProtocol.EST_CLIENT_CERTIFICATE
                    instance.idevid_trust_store = None
                    instance.est_password = secrets.token_urlsafe(16)
                case 'est_idevid':
                    instance.onboarding_protocol = DeviceModel.OnboardingProtocol.EST_IDEVID
                    instance.pki_protocol = DeviceModel.PkiProtocol.EST_CLIENT_CERTIFICATE
                    instance.idevid_trust_store = None # Truststore association via DevID registration
                case _:
                    err_msg = 'Unknown Onboarding and PKI configuration value found.'
                    raise forms.ValidationError(err_msg)
        else:
            instance.onboarding_status = DeviceModel.OnboardingStatus.NO_ONBOARDING
            instance.onboarding_protocol = DeviceModel.OnboardingProtocol.NO_ONBOARDING
            instance.idevid_trust_store = None
            pki_configuration = cleaned_data.get('pki_configuration')

            # TODO(AlexHx8472): Integrate EST   # noqa: FIX002
            match pki_configuration:
                case 'manual_download':
                    instance.pki_protocol = DeviceModel.PkiProtocol.MANUAL
                case 'cmp_shared_secret':
                    instance.pki_protocol = DeviceModel.PkiProtocol.CMP_SHARED_SECRET
                    # 16 * 8 = 128 random bits
                    instance.cmp_shared_secret = secrets.token_urlsafe(16)
                case 'est_username_password':
                    instance.pki_protocol = DeviceModel.PkiProtocol.EST_PASSWORD
                    instance.est_password = secrets.token_urlsafe(16)
                case _:
                    err_msg = 'Unknown PKI configuration value found.'
                    raise forms.ValidationError(err_msg)

        return cleaned_data


class CreateOpcUaGdsForm(CreateDeviceForm):
    """Form for creating OPC UA GDS devices with a limited set of fields."""

    class Meta(CreateDeviceForm.Meta):
        """Meta class configuration."""

        model = DeviceModel
        fields: typing.ClassVar = [
            'common_name',
            'domain',
            'domain_credential_onboarding',
            'onboarding_and_pki_configuration',
            'pki_configuration',
        ]
        labels: typing.ClassVar = {
            'domain_credential_onboarding': _('Domain Credential Onboarding'),
            'onboarding_and_pki_configuration': _('Onboarding and PKI configuration'),
        }

    onboarding_and_pki_configuration = forms.ChoiceField(
        choices=[
            ('cmp_shared_secret', _('CMP with shared secret onboarding')),
            ('est_username_password', _('EST with username and password onboarding')),
        ],
        widget=DisableSelectOptionsWidget(
            disabled_values=[
            ]
        ),
        initial='est_username_password',
    )

    pki_configuration = forms.ChoiceField(
        choices=[
            ('cmp_shared_secret', _('CMP with shared secret authentication')),
            ('est_username_password', _('EST with username and password authentication')),
        ],
        widget=DisableSelectOptionsWidget(
            disabled_values=[
            ]
        ),
        initial='est_username_password'
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the OPC UA GDS form."""
        try:
            super().__init__(*args, **kwargs)
        except KeyError as e:
            if "idevid_trust_store" in str(e):
                pass
            else:
                raise

        self.fields.pop('idevid_trust_store', None)

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            HTML('<h2>General</h2><hr>'),
            Field('common_name'),
            Field('domain'),
            HTML('<h2 class="mt-5">Onboarding Configuration</h2><hr>'),
            Field('domain_credential_onboarding'),
            HTML('<h2 class="mt-5">PKI Configuration</h2><hr>'),
            Div(
                Field('onboarding_and_pki_configuration'),
                id='id_onboarding_and_pki_configuration_wrapper',
            ),
            Div(Field('pki_configuration'), css_class='d-none', id='id_pki_configuration_wrapper'),
            HTML('<div class="mb-4"></div>'),
        )
        self.fields['domain'].widget.attrs.update({
            'required': 'True'
        })