"""JSON Certificate Profile implementation.

This module provides functionality to verify certificate requests against JSON-based profiles.

Profiles define allowed fields, prohibited fields, and other constraints for certificate requests.
They can also specify default values for fields and validate the request against these rules.
"""

from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    create_model,
    field_validator,
    model_validator,
)

ALIAS_CN = AliasChoices('common_name', 'cn', 'CN', 'commonName', '2.5.4.3')

class SubjectModel(BaseModel):
    """Model for the subject DN of a certificate profile."""
    common_name: str | None = Field(alias=ALIAS_CN, default=None)
    #organization: str | None = None
    #organizational_unit: str | None = None
    #country: str | None = None
    #state: str | None = None
    #locality: str | None = None

    # Should allow unknown fields, but not required
    model_config = ConfigDict(extra='forbid')  # allow, ignore (default)

class SanExtensionModel(BaseModel):
    """Model for the SAN extension of a certificate profile."""
    dns_names: list[str] | None = None
    ip_addresses: list[str] | None = None
    rfc822_names: list[str] | None = None
    uris: list[str] | None = None
    other_names: list[str] | None = None

    model_config = ConfigDict(extra='forbid')  # allow, ignore (default)

class ExtensionsModel(BaseModel):
    """Model for the extensions of a certificate profile."""
    basic_constraints: str | None = None
    key_usage: str | None = None
    extended_key_usage: str | None = None
    subject_alternative_name: SanExtensionModel | None = None

class ValidityModel(BaseModel):
    """Model for the validity period of a certificate profile."""
    not_before: str | None = None  # ISO 8601 format
    not_after: str | None = None  # ISO 8601 format
    days: float | None = None  # Number of days for validity
    hours: float | None = None  # Number of hours for validity
    minutes: float | None = None  # Number of minutes for validity
    seconds: int | None = None  # Number of seconds for validity
    duration: str | None = None  # Duration string in ISO 8601 format

    offset_s: int | None = None  # Offset in seconds
    validity_max: str | None = None  # Maximum validity period in ISO 8601 format
    validity_min: str | None = None  # Minimum validity period in ISO 8601 format

    model_config = ConfigDict(extra='ignore')  # allow, ignore (default)

class CertProfileBaseModel(BaseModel):
    """Base model for each nesting level of certificate profiles.

    This allows for granular control over allowed fields and constraints at each level.
    """
    allow: list[str] | Literal['*'] | None = None
    reject_mods: bool = Field(default=False)

class CertProfileModel(CertProfileBaseModel):
    """Model for a certificate profile."""
    type: Literal['cert_profile']
    subject: SubjectModel | None = Field(alias='subj', default=None)
    extensions: ExtensionsModel | None = Field(alias='ext', default=None)


class CertRequestModel(BaseModel):
    """Model for a certificate request."""
    type: Literal['cert_request'] = 'cert_request'
    subject: SubjectModel | None = Field(alias='subj', default=None)
    extensions: ExtensionsModel | None = Field(alias='ext', default=None)

    model_config = ConfigDict(extra='forbid')


class JSONProfileVerifier:
    """Class to verify certificate requests against JSON-based profiles."""

    def _build_model_from_dict(self, data: dict[str, Any], model_name: str = 'DynProfileModel') -> type[BaseModel]:
        fields = {}
        for key, value in data.items():
            if isinstance(value, dict):
                # Recursively generate a sub-model
                nested_model = self._build_model_from_dict(value, model_name=f'{model_name}_{key}')
                fields[key] = (type(nested_model), nested_model)
            else:
                fields[key] = (type(value), value)
        return create_model(model_name, **fields)

    def __init__(self, profile: dict[str, Any]) -> None:
        """Initialize the verifier with a certificate profile."""
        validated_profile = CertProfileModel.model_validate(profile)
        self.profile = validated_profile
        print('Profile:', self.profile)

        fields = {}
        for key, value in profile.items():
            if isinstance(value, dict):
                # Recursively generate a sub-model
                nested_model = self._build_model_from_dict(value, model_name=f'DynProfileModel_{key}')
                fields[key] = (type(nested_model), nested_model)
            else:
                fields[key] = (type(value), value)
        fields['type'] = (Literal['cert_request'] | None, None)  # Ensure type is 'cert_request' if present
        print('Fields:', fields)

        validators = {}

        #@model_validator(mode='before')
        @field_validator('*', mode='after')
        @staticmethod
        def forbid_none_fields(value: str | None, info: dict[str, Any]) -> None:
            print(f'Validating field: {info.field_name} with value: {value}')
            if info.field_name in fields and fields[info.field_name][1] is None and value is not None:
                msg = f"Field '{info.field_name}' is not allowed in the profile."
                raise ValidationError(msg)

        validators['forbid_none_fields'] = forbid_none_fields

        config = ConfigDict(extra='allow')

        self.request_validation_model = create_model(
            'ProfileAwareCertRequestModel', __validators__=validators, __config__=config, **fields)


    def apply_profile(self, request: dict[str, Any]) -> dict[str, Any]:
        """Verify a certificate request against the profile and attempt to change it to match the profile.

        Raises a ProfileValidationError if the request cannot be changed to match the profile.
        """
        validated_request = self.request_validation_model.model_validate(request)
        validated_dict = self.request_validation_model.model_dump(validated_request)
        print('Validation Model:', validated_dict)
        return validated_dict

    @staticmethod
    def validate_request(request: dict[str, Any]) -> dict[str, Any]:
        """Validates and normalizes a certificate request.

        This just checks its structure, it does not validate against a profile.
        """
        req_model = CertRequestModel.model_validate(request)
        return req_model.model_dump()
