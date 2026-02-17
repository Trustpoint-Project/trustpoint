"""Django forms for certificate profile configuration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar, cast

from django import forms
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from pydantic import ValidationError as PydanticValidationError

from pki.models.cert_profile import CertificateProfileModel
from pki.util.cert_profile import CERT_PROFILE_KEYWORDS, JSONProfileVerifier
from pki.util.cert_profile import CertProfileModel as CertProfilePydanticModel
from pki.util.cert_req_converter import JSONCertRequestConverter
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from cryptography.x509.base import CertificateBuilder

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
            ValidationError: If the profile JSON is not a valid certificate profile.
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
            CertProfilePydanticModel.model_validate(json_dict)
        except PydanticValidationError as e:
            error_message = f'This JSON is not a valid certificate profile: {e!s}'
            raise forms.ValidationError(error_message) from e
        self.instance.display_name = json_dict.get('display_name', '')
        return json.dumps(json_dict)

class ProfileBasedFormFieldBuilder:
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
    }

    SAN_LABELS: ClassVar[dict[str, str]] = {
        'dns_names': 'DNS Names (comma separated)',
        'ip_addresses': 'IP Addresses (comma separated)',
        'rfc822_names': 'Email Addresses (comma separated)',
        'uris': 'URIs (comma separated)',
    }

    VALIDITY_LABELS: ClassVar[dict[str, str]] = {
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
        sample_request = self.verifier.get_sample_request()

        self._build_fields_from_sample(sample_request)

        return self.fields

    def _build_fields_from_sample(self, sample_request: dict[str, Any]) -> None:
        """Build form fields based on the sample request structure."""
        subject = sample_request.get('subject', {})
        profile_subject = self.profile.get('subj', {})

        if profile_subject.get('allow') == '*':
            self._build_all_subject_fields(profile_subject)
        elif subject:
            self._build_subject_fields_from_sample(subject)

        extensions = sample_request.get('extensions', {})
        if extensions:
            san = extensions.get('subject_alternative_name', {})
            profile_extensions = self.profile.get('ext', {})
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

            initial_value = field_value if field_value else ''

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

            initial_value = field_value if field_value else ''

            self.fields[field_name] = forms.CharField(
                required=is_required,
                label=mark_safe(display_label),  # noqa: S308
                initial=initial_value,
                disabled=not is_mutable,
                widget=forms.TextInput(attrs={'class': 'form-control'})
            )

    def _build_subject_fields_from_sample(self, subject: dict[str, Any]) -> None:
        """Build subject fields based on sample values."""
        profile_subject = self.profile.get('subj', {})

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

            initial_value = field_value if field_value else ''

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
        profile_extensions = self.profile.get('ext', {})
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
                    field_value = sample_value if sample_value else ''

            display_label = self.SAN_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value if field_value else ''

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


class CertificateIssuanceForm(forms.Form):
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

    def __init__(self, profile: dict[str, Any], *args: Any, **kwargs: Any) -> None:
        """Initialize the form with a profile.

        Args:
            profile: Certificate profile definition (JSON format)
            *args: Additional positional arguments passed to parent form
            **kwargs: Additional keyword arguments passed to parent form
        """
        super().__init__(*args, **kwargs)
        self.profile = profile
        self.verifier = JSONProfileVerifier(profile)

        field_builder = ProfileBasedFormFieldBuilder(profile)
        self.fields = field_builder.build_all_fields()

    def get_certificate_builder(self) -> CertificateBuilder:
        """Build a CertificateBuilder from the form data.

        This method converts the form data to JSON format and delegates
        to JSONCertRequestConverter.from_json() to create the CertificateBuilder.

        Returns:
            CertificateBuilder ready for signing
        """
        #raise ValueError('Test Error')
        cert_request = self._form_data_to_json_request()

        validated_request = self.verifier.apply_profile_to_request(cert_request)

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
        for field_name in ProfileBasedFormFieldBuilder.VALIDITY_LABELS:
            value = cleaned_data.get(field_name)
            if value:
                validity[field_name] = int(value)
        return validity
