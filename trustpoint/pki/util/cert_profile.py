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


class InheritedProfileConfig():
    """Constraints set in the profile that are inherited by deeper nesting levels."""
    allow_implicit: bool = False
    reject_mods: bool = False
    mutable: bool = False

    def __init__(self, *, allow_implicit: bool = False, reject_mods: bool = False, mutable: bool = False) -> None:
        """Initialize the inherited profile configuration."""
        self.allow_implicit = allow_implicit
        self.reject_mods = reject_mods
        self.mutable = mutable

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

    @staticmethod
    def _is_simple_type(value: Any) -> bool:
        """Check if the value is a simple type (not a dict, list, class).

        Excludes None, since we check it separately.
        """
        return isinstance(value, (str, int, float, bool))

    def _apply_profile_rules(self, request: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
        """Apply the actual profile rules to one level of the request dict.

        It needs them both request and profile to be in the same structure and hierarchy,
        e.g. both in the "subject" sub-dict.
        """
        profile_allow = profile.get('allow') # TODO: If '*', inherit from hierarchy parent
        profile_reject_mods = profile.get('reject_mods', False) # TODO: inherit from hierarchy parent
        profile_mutable = profile.get('mutable', False)  # TODO: inherit from hierarchy parent

        # consider the fields that are only in the request, but not in the profile
        # don't need to do any nested stuff here,
        # since if the key is not in the profile, it will also not constrain sub-keys
        for field, value in request.items():
            if field not in profile:
                if profile_allow == '*' or field in profile_allow:
                    # Field is implicitly allowed, keep it
                    continue
                # Field is not allowed, remove it
                if profile_reject_mods and value:
                    msg = f"Field '{field}' is not explicitly allowed in the profile."
                    raise ValidationError(msg)
                del request[field]
                continue

        # Constraining profile fields that should not literally be in the request
        skip_keys = {'allow', 'reject_mods', 'mutable', 'default', 'value', 'required'}
        filtered_profile = {k: v for k, v in profile.items() if k not in skip_keys}

        for field, profile_value in filtered_profile.items():
            request_value = request.get(field)
            if profile_value is None and request_value is not None:
                # Field is not allowed in the profile, but present in the request
                if profile_reject_mods:
                    msg = f"Field '{field}' is prohibited in the profile."
                    raise ValidationError(msg)
                del request[field]
                continue
            if field not in request:
                if isinstance(profile_value, dict):
                # check for default and required fields
                    if 'value' in profile_value:
                        # Set default value from profile
                        request[field] = profile_value['value']
                        continue
                    if 'default' in profile_value:
                        # Set default value from profile
                        request[field] = profile_value['default']
                        continue
                    if 'required' in profile_value:
                        # Required field is missing in the request
                        msg = f"Field '{field}' is required but not present in the request."
                        raise ValidationError(msg)
                    # 're' case
                    # if none of the above are present, we assume it is a nested dict
                    self._apply_profile_rules(request.setdefault(field, {}), profile_value)
                elif JSONProfileVerifier._is_simple_type(profile_value):
                    request[field] = profile_value
                else:
                    print(f"Warning: Field '{field}' in profile is of type {type(profile_value).__name__}, skipping.")
                continue
            # Field is present in both request and profile
            if isinstance(profile_value, dict):
                if 'value' in profile_value and not profile_mutable: # TODO: does not consider {"value":"x", "mutable": True}
                    # Field is not mutable, force the value from the profile
                    if profile_reject_mods and request[field] != profile_value['value']:
                        msg = f"Field '{field}' is not mutable in the profile."
                        raise ValidationError(msg)
                    request[field] = profile_value['value']
                    continue
            elif JSONProfileVerifier._is_simple_type(profile_value) and not profile_mutable:
                if profile_reject_mods and request[field] != profile_value['value']:
                    msg = f"Field '{field}' is not mutable in the profile."
                    raise ValidationError(msg)
                request[field] = profile_value
            else:
                print(f"Warning: Field '{field}' in profile is of type {type(profile_value).__name__}, skipping.")
                continue

        return request

    def apply_profile_to_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Apply the profile to a certificate request and return the modified request."""
        # For each field in the request, check on the same hierarchy level in the profile if:
        # - it is allowed.
        # - any default values are set
        # - it is mutable
        # - it is required

        # if (field null in profile and field in request)
        # - if reject_mods is True, raise ValidationError
        # - if reject_mods is False, remove field from request

        # if (field not in profile and field in request)
        # - if implicitly allowed '*' or in explicit allow list, keep it
        # - /!\ need to normalize the allow list too!
        # - if not allowed
        # - - if reject_mods is True, raise ValidationError
        # - - if reject_mods is False, remove field from request

        # if (field in profile and field not in request)
        # - set in request the default value from the profile if it exists

        # if (field in profile and field in request)
        # - if default, keep the value from the request
        # - if not mutable
        # - - if reject_mods is True, raise ValidationError
        # - - if reject_mods is False, set from profile

