"""Django forms for certificate profile configuration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar, cast

from django import forms
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from pydantic import ValidationError as PydanticValidationError

from management.models import SecurityConfig
from pki.models.cert_profile import CertificateProfileModel
from pki.util.cert_profile import CERT_PROFILE_KEYWORDS, JSONProfileVerifier
from pki.util.cert_profile import CertProfileModel as CertProfilePydanticModel
from pki.util.cert_req_converter import JSONCertRequestConverter
from request.template_vars import build_variable_map_from_models, resolve_string, resolve_template_variables
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from cryptography.x509.base import CertificateBuilder

    from devices.models import DeviceModel
    from pki.models.domain import DomainModel
    from request.request_context import BaseRequestContext


def _validity_days_from_components(
    days: float | None = None,
    hours: float | None = None,
    minutes: float | None = None,
    seconds: float | None = None,
    duration_seconds: float | None = None,
) -> float:
    """Return the total validity expressed in days from individual time components."""
    total: float = 0.0
    if days:
        total += float(days)
    if hours:
        total += float(hours) / 24
    if minutes:
        total += float(minutes) / 1440
    if seconds:
        total += float(seconds) / 86400
    if duration_seconds:
        total += duration_seconds / 86400
    return total


def check_validity_days_against_security_config(total_days: float) -> None:
    """Raise :class:`~django.core.exceptions.ValidationError` if *total_days* exceeds the policy limit."""
    try:
        cfg = SecurityConfig.objects.get()
    except SecurityConfig.DoesNotExist:
        return
    except SecurityConfig.MultipleObjectsReturned:
        cfg_or_none = SecurityConfig.objects.order_by('pk').first()
        if cfg_or_none is None:
            return
        cfg = cfg_or_none

    max_days: int | None = cfg.max_cert_validity_days
    if max_days is None:
        return

    if total_days > float(max_days):
        raise ValidationError(
            _(
                'The requested certificate validity of %(req_days).1f days exceeds the maximum of '
                '%(max_days)d days permitted by the active security policy.'
            ) % {
                'req_days': total_days,
                'max_days': max_days,
            }
        )

class CertProfileConfigForm(LoggerMixin, forms.ModelForm[CertificateProfileModel]):
    """Form for creating or updating Certificate Profiles.

    This form is based on the CertificateProfileModel and allows users to
    create or update certificate profiles by specifying a unique name and
    profile JSON configuration.

    Attributes:
        unique_name (CharField): A unique name for the certificate profile.
        profile_json (JSONField): The JSON configuration for the certificate profile.
    """

    class Meta:
        """Meta information for the CertProfileConfigForm."""

        model = CertificateProfileModel
        fields: ClassVar[list[str]] = ['unique_name', 'profile_json','is_default']

    def clean_unique_name(self) -> str:
        """Validates the unique name to ensure it is not already in use.

        Raises:
            ValidationError: If the unique name is already associated with an existing certificate profile.
        """
        unique_name = self.cleaned_data['unique_name']
        qs = CertificateProfileModel.objects.filter(unique_name=unique_name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            error_message = 'Unique name is already taken. Choose another one.'
            raise ValidationError(error_message)
        return cast('str', unique_name)

    def clean_profile_json(self) -> str:
        """Validates the profile JSON to ensure it is a valid certificate profile.

        Raises:
            ValidationError: If the profile JSON is not a valid certificate profile,
                or if the configured validity exceeds the security policy limit.
        """
        profile_json = self.cleaned_data['profile_json']
        if type(profile_json) is dict:
            json_dict = profile_json
        else:
            try:
                json_dict = json.loads(str(profile_json))
            except json.JSONDecodeError as e:
                error_message = f'Invalid JSON format: {e!s}'
                raise forms.ValidationError(error_message) from e
        try:
            validated = CertProfilePydanticModel.model_validate(json_dict)
        except PydanticValidationError as e:
            error_message = f'This JSON is not a valid certificate profile: {e!s}'
            raise forms.ValidationError(error_message) from e
        self.instance.display_name = json_dict.get('display_name', '')
        self.instance.credential_type = json_dict.get('credential_type', 'application')

        self._check_validity_against_security_config(validated)

        return json.dumps(json_dict)

    @staticmethod
    def _validity_total_days(validated: CertProfilePydanticModel) -> float:
        """Return the total validity of *validated* expressed in days."""
        v = validated.validity
        return _validity_days_from_components(
            days=v.days,
            hours=v.hours,
            minutes=v.minutes,
            seconds=float(v.seconds) if v.seconds is not None else None,
            duration_seconds=v.duration.total_seconds() if v.duration is not None else None,
        )

    @staticmethod
    def _check_validity_against_security_config(validated: CertProfilePydanticModel) -> None:
        """Raise ValidationError if the profile's validity exceeds the security policy limit."""
        total_days = CertProfileConfigForm._validity_total_days(validated)
        check_validity_days_against_security_config(total_days)

class ProfileBasedFormFieldBuilder(LoggerMixin):
    """Django form field builder that leverages JSONProfileVerifier.

    This builder uses JSONProfileVerifier.get_sample_request() to understand the
    profile structure, eliminating the need for manual profile parsing logic.

    Attributes:
        profile: The certificate profile definition
        verifier: JSONProfileVerifier instance for profile interpretation
        fields: Dictionary of generated Django form fields
    """

    SUBJECT_LABELS: ClassVar[dict[str, str]] = {
        'cn': 'Common Name (CN)',
        'common_name': 'Common Name (CN)',
        'o': 'Organization (O)',
        'organization_name': 'Organization (O)',
        'ou': 'Organizational Unit (OU)',
        'organizational_unit_name': 'Organizational Unit (OU)',
        'c': 'Country (C)',
        'country_name': 'Country (C)',
        'st': 'State or Province (ST)',
        'state_or_province_name': 'State or Province (ST)',
        'l': 'Locality (L)',
        'locality_name': 'Locality (L)',
        'emailAddress': 'Email Address',
        'email_address': 'Email Address',
        'serial_number': 'Serial Number',
    }

    SAN_LABELS: ClassVar[dict[str, str]] = {
        'dns_names': 'DNS Names (comma separated)',
        'ip_addresses': 'IP Addresses (comma separated)',
        'rfc822_names': 'Email Addresses (comma separated)',
        'uris': 'URIs (comma separated)',
    }

    VALIDITY_LABELS: ClassVar[dict[str, str]] = {
        'not_before': 'Not Before',
        'not_after': 'Not After',
        'days': 'Days',
        'hours': 'Hours',
        'minutes': 'Minutes',
        'seconds': 'Seconds',
    }

    def __init__(self, profile: dict[str, Any]) -> None:
        """Initialize the builder with a profile.

        Args:
            profile: Certificate profile definition
        """
        self.profile = profile
        self.verifier = JSONProfileVerifier(profile)
        self.fields: dict[str, forms.Field] = {}

    def build_all_fields(self) -> dict[str, forms.Field]:
        """Build all fields from the profile by analyzing a sample request.

        This leverages JSONProfileVerifier.get_sample_request() to understand
        the profile structure, eliminating manual parsing.
        """
        sample_request = self.profile # Use the normalized profile for field generation

        self._build_fields_from_sample(sample_request)

        return self.fields

    def _build_fields_from_sample(self, sample_request: dict[str, Any]) -> None:
        """Build form fields based on the sample request structure."""
        subject = sample_request.get('subject', {})
        profile_subject = self.profile.get('subject', {})

        if profile_subject.get('allow') == '*':
            self._build_all_subject_fields(profile_subject)
        elif subject:
            self._build_subject_fields_from_sample(subject)

        extensions = sample_request.get('extensions', {})
        if extensions:
            san = extensions.get('subject_alternative_name', {})
            profile_extensions = self.profile.get('extensions', {})
            profile_san = profile_extensions.get('subject_alternative_name', profile_extensions.get('san', {}))

            if isinstance(profile_san, dict) and profile_san.get('allow') == '*':
                self._build_all_san_fields(profile_san)
            elif san:
                self._build_san_fields_from_sample(san)

        validity = sample_request.get('validity', {})
        if validity:
            self._build_validity_fields_from_sample(validity)

    def _build_all_subject_fields(self, profile_subject: dict[str, Any]) -> None:
        """Build all possible subject fields when allow='*'."""
        for field_name in self.SUBJECT_LABELS:
            if field_name in ('cn', 'o', 'ou', 'c', 'st', 'l', 'emailAddress'):
                continue

            field_spec = profile_subject.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
            else:
                is_required = False
                is_mutable = True
                field_value = ''

            display_label = self.SUBJECT_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value or ''

            if field_name in ('c', 'country_name'):
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'}),
                    min_length=2,
                    max_length=2
                )
            else:
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'})
                )

    def _build_all_san_fields(self, profile_san: dict[str, Any]) -> None:
        """Build all possible SAN fields when allow='*'."""
        for field_name in self.SAN_LABELS:
            field_spec = profile_san.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
                if isinstance(field_value, list):
                    field_value = ', '.join(str(v) for v in field_value)
            else:
                is_required = False
                is_mutable = True
                field_value = ''

            display_label = self.SAN_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value or ''

            self.fields[field_name] = forms.CharField(
                required=is_required,
                label=mark_safe(display_label),  # noqa: S308
                initial=initial_value,
                disabled=not is_mutable,
                widget=forms.TextInput(attrs={'class': 'form-control'})
            )

    def _build_subject_fields_from_sample(self, subject: dict[str, Any]) -> None:
        """Build subject fields based on sample values."""
        profile_subject = self.profile.get('subject', {})

        for field_name, sample_value in subject.items():
            if field_name in CERT_PROFILE_KEYWORDS:
                continue

            field_spec = profile_subject.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
            else:
                is_required = field_name in profile_subject.get('required', [])
                is_mutable = (
                    field_name in profile_subject.get('mutable', [])
                    or field_name not in profile_subject.get('value', {})
                )
                is_changeme = isinstance(sample_value, str) and sample_value.startswith('CHANGEME_')
                field_value = '' if is_changeme else sample_value

            display_label = self.SUBJECT_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value or ''

            if field_name in ('c', 'country_name'):
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'}),
                    min_length=2,
                    max_length=2
                )
            else:
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'})
                )

    def _build_san_fields_from_sample(self, san: dict[str, Any]) -> None:
        """Build SAN fields based on sample values."""
        profile_extensions = self.profile.get('extensions', {})
        profile_san = profile_extensions.get('subject_alternative_name', profile_extensions.get('san', {}))

        for field_name, sample_value in san.items():
            if field_name in CERT_PROFILE_KEYWORDS or field_name == 'critical':
                continue

            field_spec = profile_san.get(field_name, {}) if isinstance(profile_san, dict) else {}
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
                if isinstance(field_value, list):
                    field_value = ', '.join(str(v) for v in field_value)
            else:
                is_required = field_name in profile_san.get('required', []) if isinstance(profile_san, dict) else False
                is_mutable = (
                    field_name in profile_san.get('mutable', [])
                    or field_name not in profile_san.get('value', {})
                ) if isinstance(profile_san, dict) else True
                is_changeme = isinstance(sample_value, str) and sample_value.startswith('CHANGEME_')
                if is_changeme:
                    field_value = ''
                elif isinstance(sample_value, list):
                    field_value = ', '.join(str(v) for v in sample_value)
                else:
                    field_value = sample_value or ''

            display_label = self.SAN_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value or ''

            self.fields[field_name] = forms.CharField(
                required=is_required,
                label=mark_safe(display_label),  # noqa: S308
                initial=initial_value,
                disabled=not is_mutable,
                widget=forms.TextInput(attrs={'class': 'form-control'})
            )

    def _build_validity_fields_from_sample(self, validity: dict[str, Any]) -> None:
        """Build validity fields based on sample values."""
        profile_validity = self.profile.get('validity', {})

        for ts_field in ('not_before', 'not_after'):
            ts_value = validity.get(ts_field)
            if ts_value is not None:
                display_label = self.VALIDITY_LABELS.get(ts_field, ts_field.replace('_', ' ').title())
                formatted = str(ts_value)
                self.fields[ts_field] = forms.CharField(
                    required=False,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=formatted,
                    disabled=True,
                    widget=forms.TextInput(attrs={'class': 'form-control'}),
                )

        for field_name, sample_value in validity.items():
            if field_name in CERT_PROFILE_KEYWORDS or field_name in ('not_before', 'not_after', 'duration'):
                continue

            field_spec = profile_validity.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', 0))
            else:
                is_required = field_name in profile_validity.get('required', [])
                is_mutable = (
                    field_name in profile_validity.get('mutable', [])
                    or field_name not in profile_validity.get('value', {})
                )
                is_changeme = isinstance(sample_value, str) and sample_value.startswith('CHANGEME_')
                field_value = 0 if is_changeme else (sample_value if sample_value is not None else 0)

            display_label = self.VALIDITY_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value if field_value is not None else 0

            self.fields[field_name] = forms.IntegerField(
                required=is_required,
                label=mark_safe(display_label),  # noqa: S308
                initial=initial_value,
                disabled=not is_mutable,
                widget=forms.NumberInput(attrs={'class': 'form-control'})
            )


class CertificateIssuanceForm(LoggerMixin, forms.Form):
    """Form for certificate issuance based on a certificate profile.

    This form dynamically generates fields based on a certificate profile and
    leverages existing infrastructure for profile interpretation and certificate building:

    - Uses JSONProfileVerifier.get_sample_request() to understand what fields to show
    - Validates user input with JSONProfileVerifier.apply_profile_to_request()
    - Delegates certificate building to JSONCertRequestConverter.from_json()

    This eliminates code duplication and ensures consistent profile interpretation
    across the application (55% code reduction from original implementation).

    Attributes:
        profile: The certificate profile definition
        verifier: JSONProfileVerifier instance for validation
        fields: Dynamically generated Django form fields
    """

    def __init__(
        self,
        profile: dict[str, Any],
        *args: Any,
        device: DeviceModel | None = None,
        domain: DomainModel | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the form with a profile.

        Args:
            profile: Certificate profile definition (JSON format)
            *args: Additional positional arguments passed to parent form
            device: Optional device model for resolving template variables
                in field initial values (e.g. ``{{ device.rfc_4122_uuid }}``).
            domain: Optional domain model for resolving template variables.
            **kwargs: Additional keyword arguments passed to parent form
        """
        super().__init__(*args, **kwargs)
        self.profile = profile
        self.verifier = JSONProfileVerifier(profile)
        self.profile = self.verifier.get_profile()  # Normalize profile to ensure consistent field generation
        field_builder = ProfileBasedFormFieldBuilder(self.profile)
        self.fields = field_builder.build_all_fields()

        template_vars = build_variable_map_from_models(device=device, domain=domain)
        if template_vars:
            for field in self.fields.values():
                if isinstance(field.initial, str):
                    field.initial = resolve_string(field.initial, template_vars)

    def get_certificate_builder(
        self, request_context: BaseRequestContext | None = None,
    ) -> CertificateBuilder:
        """Build a CertificateBuilder from the form data.

        This method converts the form data to JSON format and delegates
        to JSONCertRequestConverter.from_json() to create the CertificateBuilder.

        Returns:
            CertificateBuilder ready for signing
        """
        cert_request = self._form_data_to_json_request()

        validated_request = self.verifier.apply_profile_to_request(cert_request)

        if request_context is not None:
            validated_request = resolve_template_variables(validated_request, request_context)

        return JSONCertRequestConverter.from_json(validated_request)

    def _form_data_to_json_request(self) -> dict[str, Any]:
        """Convert cleaned form data to JSON certificate request format.

        Returns:
            dict: JSON certificate request compatible with JSONCertRequestConverter
        """
        cleaned_data = self.cleaned_data
        request: dict[str, Any] = {'type': 'cert_request'}

        subject = self._build_subject_from_form_data(cleaned_data)
        if subject:
            request['subject'] = subject

        extensions = self._build_extensions_from_form_data(cleaned_data)
        if extensions:
            request['extensions'] = extensions

        validity = self._build_validity_from_form_data(cleaned_data)
        if validity:
            request['validity'] = validity

        return request

    def _build_subject_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, str]:
        """Build subject DN from form data.

        This method handles both abbreviated and full field names.
        """
        return {
            field_name: value
            for field_name, value in cleaned_data.items()
            if field_name in ProfileBasedFormFieldBuilder.SUBJECT_LABELS and value
        }

    def _build_extensions_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, Any]:
        """Build certificate extensions from form data."""
        extensions = {}

        san = self._build_san_from_form_data(cleaned_data)
        if san:
            extensions['subject_alternative_name'] = san

        return extensions

    def _build_san_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, list[str]]:
        """Build SAN extension from form data."""
        san = {}
        for field_name in ProfileBasedFormFieldBuilder.SAN_LABELS:
            value = cleaned_data.get(field_name)
            if value:
                values = [v.strip() for v in value.split(',') if v.strip()]
                if values:
                    san[field_name] = values
        return san

    def _build_validity_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, int]:
        """Build validity period from form data."""
        validity = {}
        for field_name in ('days', 'hours', 'minutes', 'seconds'):
            value = cleaned_data.get(field_name)
            if value:
                validity[field_name] = int(value)
        return validity

    def clean(self) -> dict[str, Any]:
        """Validate the requested certificate validity against the active security policy."""
        cleaned_data = cast('dict[str, Any]', super().clean())
        total_days = _validity_days_from_components(
            days=cleaned_data.get('days'),
            hours=cleaned_data.get('hours'),
            minutes=cleaned_data.get('minutes'),
            seconds=cleaned_data.get('seconds'),
        )
        check_validity_days_against_security_config(total_days)
        return cleaned_data
