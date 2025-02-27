"""Forms exclusively used in the device application."""

from __future__ import annotations

import ipaddress
from typing import Any, cast
import secrets

from django import forms
from django.forms import ModelChoiceField
from django.utils.translation import gettext_lazy as _

from devices.models import DeviceModel, IssuedCredentialModel
from pki.models.certificate import RevokedCertificateModel
from pki.models.domain import DomainModel

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, HTML, Div
from crispy_bootstrap5.bootstrap5 import Field

from pki.models.truststore import TruststoreModel
from devices.widgets import DisableSelectOptionsWidget
from django.db.models.query import QuerySet


PASSWORD_MIN_LENGTH = 12


class IssueDomainCredentialForm(forms.Form):
    """Form to issue a new domain credential."""

    common_name = forms.CharField(max_length=255, label=_('Common Name'), required=True, disabled=True)
    domain_component = forms.CharField(max_length=255, label=_('Domain Component'), required=True, disabled=True)
    serial_number = forms.CharField(max_length=255, label=_('Serial Number'), required=True, disabled=True)


class CredentialDownloadForm(forms.Form):
    """Form to download a credential."""

    password = forms.CharField(
        label=_('Password'),
        widget=forms.PasswordInput,
        help_text=_('Must be at least %d characters long.') % PASSWORD_MIN_LENGTH,
    )
    confirm_password = forms.CharField(label=_('Confirm Password'), widget=forms.PasswordInput)

    def clean(self) -> dict[str, Any]:
        """Checks if the passwords match and if the password is long enough."""
        cleaned_data = cast(dict[str, Any], super().clean())
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password:
            if password != confirm_password:
                self.add_error('confirm_password', _('Passwords do not match.'))

            if len(password) < PASSWORD_MIN_LENGTH:
                self.add_error('password', _('Password must be at least %d characters long.') % PASSWORD_MIN_LENGTH)

        return cleaned_data


class IssueTlsClientCredentialForm(forms.Form):
    """Form to issue a new TLS client credential."""

    def __init__(self, *args: Any, device: DeviceModel, **kwargs: Any) -> None:
        """Overwrite the constructor to accept the current device instance."""
        self.device = device
        super().__init__(*args, **kwargs)

    common_name = forms.CharField(
        max_length=255,
        label=_('Common Name'),
        required=True,
    )
    pseudonym = forms.CharField(max_length=255, label=_('Pseudonym'), required=True, disabled=True)
    domain_component = forms.CharField(max_length=255, label=_('Domain Component'), required=True, disabled=True)
    serial_number = forms.CharField(max_length=255, label=_('Serial Number'), required=True, disabled=True)
    validity = forms.IntegerField(label=_('Validity (days)'), initial=10, required=True)

    def clean_common_name(self) -> str:
        """Checks the common name."""
        common_name = cast(str, self.cleaned_data['common_name'])
        if IssuedCredentialModel.objects.filter(common_name=common_name, device=self.device).exists():
            err_msg = (
                f'Credential with common name {common_name} ' f'already exists for device {self.device.unique_name}.'
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


class IssueTlsServerCredentialForm(forms.Form):
    """Form to issue a new TLS server credential."""

    def __init__(self, *args: Any, device: DeviceModel, **kwargs: Any) -> None:
        """Overwrite the constructor to accept the current device instance."""
        self.device = device
        super().__init__(*args, **kwargs)

    common_name = forms.CharField(max_length=100, label=_('Common Name'), required=True)
    pseudonym = forms.CharField(max_length=100, label=_('Pseudonym'), required=True, disabled=True)
    serial_number = forms.CharField(max_length=100, label=_('Serial Number'), required=True, disabled=True)
    domain_component = forms.CharField(max_length=255, label=_('Domain Component'), required=True, disabled=True)
    validity = forms.IntegerField(label=_('Validity (days)'), initial=10, required=True)
    ipv4_addresses = forms.CharField(
        label=_('IPv4-Addresses (comma-separated list)'), initial='127.0.0.1, ', required=False
    )
    ipv6_addresses = forms.CharField(label=_('IPv6-Addresses (comma-separated list)'), initial='::1, ', required=False)
    domain_names = forms.CharField(
        label=_('Domain-Names (comma-separated list)'), initial='localhost, ', required=False
    )

    def clean_common_name(self) -> str:
        """Checks the common name."""
        common_name = cast(str, self.cleaned_data['common_name'])
        if IssuedCredentialModel.objects.filter(common_name=common_name, device=self.device).exists():
            err_msg = _('Credential with common name %s already exists for device %s.') % (
                common_name,
                self.device.unique_name,
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
        if not data:
            return []

        domain_names = data.split(',')
        # TODO(AlexHx8472): Check for valid domains.
        return [domain_name.strip() for domain_name in domain_names if domain_name.strip() != '']

    def clean(self) -> dict[str, Any]:
        """Checks that at least one of IPv4, IPv6 and Domain Names is set."""
        cleaned_data = cast(dict[str, Any], super().clean())
        ipv4_addresses = cleaned_data.get('ipv4_addresses')
        ipv6_addresses = cleaned_data.get('ipv6_addresses')
        domain_names = cleaned_data.get('domain_names')
        if not (ipv4_addresses or ipv6_addresses or domain_names):
            err_msg = _('At least one SAN entry is required.')
            raise forms.ValidationError(err_msg)
        return cleaned_data


class BrowserLoginForm(forms.Form):
    """Form for the browser login via OTP for remote credential download."""
    otp = forms.CharField(widget=forms.PasswordInput(), label='OTP', max_length=32)

    def clean(self) -> dict[str, Any] | None:
        """Cleans the form data, extracting the credential ID and OTP."""
        # splits the submitted OTP, which is in the format 'credential_id.otp'
        cleaned_data = super().clean()
        otp = cleaned_data.get('otp')
        if not otp:
            self.add_error('otp', _('This field is required.'))
        err_msg = _('The provided OTP is invalid.')
        otp_parts = otp.split('.')
        if len(otp_parts) != 2:  # noqa: PLR2004
            raise forms.ValidationError(err_msg)
        try:
            cred_id = int(otp_parts[0])
        except ValueError as e:
            raise forms.ValidationError(err_msg) from e
        cleaned_data['cred_id'] = cred_id
        cleaned_data['otp'] = otp_parts[1]
        return cleaned_data


class CredentialRevocationForm(forms.ModelForm[RevokedCertificateModel]):
    """Form to revoke a device credential."""
    class Meta:
        model = RevokedCertificateModel
        fields = ['revocation_reason']


class CreateDeviceForm(forms.ModelForm[DeviceModel]):

    class Meta:
        model = DeviceModel
        fields = [
            'unique_name',
            'serial_number',
            'domain',
            'domain_credential_onboarding',
            'onboarding_and_pki_configuration',
            'idevid_trust_store',
            'pki_configuration'
        ]
        labels = {
            'domain_credential_onboarding':
                _('Domain Credential Onboarding'),
        }

    domain_queryset = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(
        queryset=domain_queryset,
        empty_label=None
    )

    onboarding_and_pki_configuration = forms.ChoiceField(
        choices=[
            ('cmp_shared_secret', _('CMP with shared secret onboarding')),
            ('cmp_idevid', _('CMP with IDEVID onboarding')),
            ('aoki_cmp', _('CMP with AOKI onboarding')),
            ('brski_cmp', _('CMP with BRSKI onboarding')),
            ('est_username_password', _('EST with username and password onboarding')),
            ('est_idevid', _('EST with IDEVID onboarding')),
            ('aoki_est', _('EST with AOKI onboarding')),
            ('brski_est', _('EST with BRSKI onboarding'))
        ],
        widget=DisableSelectOptionsWidget(
            disabled_values=[
                'aoki_est',
                'brski_est',
                'aoki_cmp',
                'brski_cmp',
                'est_username_password',
                'est_idevid'
            ]
        ),
        initial='cmp_idevid'
    )

    pki_configuration = forms.ChoiceField(
        choices=[
            ('manual_download', _('Manual Download')),
            ('cmp_shared_secret', _('CMP with shared secret authentication')),
            ('est_username_password', _('EST with username and password authentication')),
        ],
        widget=DisableSelectOptionsWidget(
            disabled_values=[
                'est_username_password'
            ]
        ),
        initial='cmp_shared_secret'
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        truststore_field = self.fields['idevid_trust_store']
        if isinstance(truststore_field, ModelChoiceField):
            truststore_field.queryset = TruststoreModel.objects.filter(
                intended_usage=TruststoreModel.IntendedUsage.IDEVID
            )

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            HTML('<h2>General</h2><hr>'),
            Field('unique_name'),
            Field('serial_number'),
            Field('domain'),
            HTML('<h2 class="mt-5">Onboarding Configuration</h2><hr>'),
            Field('domain_credential_onboarding'),
            HTML('<h2 class="mt-5">PKI Configuration</h2><hr>'),
            Div(
            Field('onboarding_and_pki_configuration'),
                Div(
                    Field('idevid_trust_store'),
                    id='id_idevid_trust_store_select_wrapper'
                ),
                id='id_onboarding_and_pki_configuration_wrapper'
            ),
            Div(
                Field('pki_configuration'),
                css_class='d-none',
                id='id_pki_configuration_wrapper'
            ),
            HTML('<div class="mb-4"></div>'),
        )

    def clean(self) -> dict[str, Any]:
        cleaned_data: bool = super().clean() or {}
        instance: DeviceModel = super().save(commit=False)
        domain_credential_onboarding = cleaned_data.get('domain_credential_onboarding')
        if domain_credential_onboarding:
            instance.onboarding_status = DeviceModel.OnboardingStatus.PENDING
            onboarding_and_pki_configuration = cleaned_data.get('onboarding_and_pki_configuration')

            # TODO(AlexHx8472): Integrate EST
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
                        raise forms.ValidationError('Must specify an IDevID Trust-Store for IDevID onboarding.')
                    if not idevid_trust_store.intended_usage == TruststoreModel.IntendedUsage.IDEVID.value:
                        raise forms.ValidationError('The Trust-Store must have the intended usage IDevID.')
                    instance.onboarding_protocol = DeviceModel.OnboardingProtocol.CMP_IDEVID
                    instance.pki_protocol = DeviceModel.PkiProtocol.CMP_CLIENT_CERTIFICATE
                case _:
                    raise forms.ValidationError('Unknown Onboarding and PKI configuration value found.')
        else:
            instance.onboarding_status = DeviceModel.OnboardingStatus.NO_ONBOARDING
            instance.onboarding_protocol = DeviceModel.OnboardingProtocol.NO_ONBOARDING
            instance.idevid_trust_store = None
            pki_configuration = cleaned_data.get('pki_configuration')

            # TODO(AlexHx8472): Integrate EST
            match pki_configuration:
                case 'manual_download':
                    instance.pki_protocol = DeviceModel.PkiProtocol.MANUAL
                case 'cmp_shared_secret':
                    instance.pki_protocol = DeviceModel.PkiProtocol.CMP_SHARED_SECRET
                    # 16 * 8 = 128 random bits
                    instance.cmp_shared_secret = secrets.token_urlsafe(16)
                case _:
                    raise forms.ValidationError('Unknown PKI configuration value found.')


        return cleaned_data