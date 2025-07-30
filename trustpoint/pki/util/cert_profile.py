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

class ExtensionsModel(BaseModel):
    """Model for the extensions of a certificate profile."""
    basic_constraints: str | None = None
    key_usage: str | None = None
    extended_key_usage: str | None = None
    subject_alternative_name: str | None = None

class CertProfileModel(BaseModel):
    """Model for a certificate profile."""
    type: Literal['cert_profile']
    subj: SubjectModel | None = Field(alias='subject', default=None)
    ext: ExtensionsModel | None = Field(alias='extensions', default=None)

    allow: list[str] | Literal['*'] | None = None
    reject_mods: bool = Field(default=False)


class CertRequestModel(BaseModel):
    """Model for a certificate request."""
    type: Literal['cert_request']
    subj: SubjectModel
    ext: ExtensionsModel | None = Field(alias='extensions', default=None)

    model_config = ConfigDict(extra='forbid')


class JSONProfileVerifier:
    """Class to verify certificate requests against JSON-based profiles."""

    def __init__(self, profile: dict) -> None:
        """Initialize the verifier with a certificate profile."""
        validated_profile = CertProfileModel.model_validate(profile)
        self.profile = validated_profile
        print('Profile:', self.profile)

        fields = {}
        for key, value in profile.items():
            inferred_type = type(value)
            fields[key] = (inferred_type, value)
        fields['type'] = (Literal['cert_request'] | None, None)  # Ensure type is 'cert_request' if present
        print('Fields:', fields)

        validators = {}

        #@model_validator(mode='before')
        @field_validator('*', mode='after')
        @staticmethod
        def forbid_none_fields(value: str | None, info: dict[str, Any]) -> str | None:
            print(f'Validating field: {info.field_name} with value: {value}')
            if info.field_name in fields and fields[info.field_name][1] is None and value is not None:
                msg = f"Field '{info.field_name}' is not allowed in the profile."
                raise ValidationError(msg)

        validators['forbid_none_fields'] = forbid_none_fields

        self.request_validation_model = create_model('ProfileAwareCertRequestModel', __validators__=validators, **fields)


    def apply_profile(self, request: CertRequestModel) -> CertRequestModel:
        """Verify a certificate request against the profile and attempt to change it to match the profile.

        Raises a ProfileValidationError if the request cannot be changed to match the profile.
        """
        validated_request = self.request_validation_model.model_validate(request)
        print('Validation Model:', self.request_validation_model.model_dump(validated_request))
        return validated_request
