"""JSON Certificate Profile implementation.

This module provides functionality to verify certificate requests against JSON-based profiles.

Profiles define allowed fields, prohibited fields, and other constraints for certificate requests.
They can also specify default values for fields and validate the request against these rules.
"""

from typing import Annotated, Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    create_model,
    field_validator,
    model_validator,
    AfterValidator
)



class ProfileValidationError(Exception):
    """Raised when the request is well-formed but does not match the profile constraints."""

ALIASES = {
    'common_name': AliasChoices('common_name', 'cn', 'CN', 'commonName', '2.5.4.3')
}

def build_alias_map() -> dict[str, str]:
    """Build a mapping of all known aliases to their canonical field names."""
    alias_map = {}
    for canonical, alias in ALIASES.items():
        for choice in alias.choices:
            alias_map[choice] = canonical
    return alias_map

alias_map = build_alias_map()

class ProfileValuePropertyModel(BaseModel):
    """Model for a profile value property."""
    value: Any | None = None
    default: Any | None = None
    required: bool = False
    mutable: bool = True

    model_config = ConfigDict(extra='forbid')

class SubjectModel(BaseModel):
    """Model for the subject DN of a certificate profile."""
    common_name: str | ProfileValuePropertyModel | None = Field(default=None, alias=ALIASES['common_name'])
    #organization: str | None = None
    #organizational_unit: str | None = None
    #country: str | None = None
    #state: str | None = None
    #locality: str | None = None

    # Should allow unknown fields, but not required
    model_config = ConfigDict(extra='allow')

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
    #allow: list[str] | Literal['*'] | None = Annotated[None, AfterValidator(normalize_allow)]
    #allow: Annotated[list[str] | Literal['*'] | None, AfterValidator(normalize_allow)] = None
    reject_mods: bool = Field(default=False)

    @field_validator('allow', mode='before')
    @classmethod
    def normalize_allow(cls, value: list[str] | Literal['*'] | None) -> list[str] | Literal['*'] | None:
        """Normalize the allow list by replacing aliases with their canonical names."""
        print('Normalizing allow list:', value)
        if not isinstance(value, list):
            return value
        normalized = []
        print('Alias map:', alias_map)
        for item in value:
            try:
                normalized.append(alias_map[item])
            except KeyError:
                normalized.append(item)
        return normalized

class ProfileSubjectModel(SubjectModel, CertProfileBaseModel):
    """Model for the subject DN of a certificate profile, with profile constraints."""

class CertProfileModel(CertProfileBaseModel):
    """Model for a certificate profile."""
    type: Literal['cert_profile']
    subject: ProfileSubjectModel | None = Field(alias='subj', default=None)
    extensions: ExtensionsModel | None = Field(alias='ext', default=None)


class CertRequestModel(BaseModel):
    """Model for a certificate request."""
    type: Literal['cert_request'] | None = 'cert_request'
    subject: SubjectModel | None = Field(alias='subj', default=None)
    extensions: ExtensionsModel | None = Field(alias='ext', default=None)

    model_config = ConfigDict(extra='allow') # extra fields are validated by _apply_profile_rules


class InheritedProfileConfig:
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

    def __init__(self, profile: dict[str, Any]) -> None:
        """Initialize the verifier with a certificate profile."""
        validated_profile = CertProfileModel.model_validate(profile)
        self.profile = validated_profile
        print('Profile:', self.profile)

        self.profile_dict = validated_profile.model_dump(exclude_unset=True)
        print('Profile Dict:', self.profile_dict)

    @staticmethod
    def validate_request(request: dict[str, Any]) -> dict[str, Any]:
        """Validates and normalizes a certificate request.

        This just checks its structure, it does not validate against a profile.
        """
        req_model = CertRequestModel.model_validate(request)
        return req_model.model_dump(exclude_unset=True)

    @staticmethod
    def _is_simple_type(value: Any) -> bool:
        """Check if the value is a simple type (not a dict, list, class).

        Excludes None, since we check it separately.
        """
        return isinstance(value, (str, int, float, bool))

    def _handle_request_only_fields(
            self, request: dict[str, Any], profile: dict[str, Any],
            profile_config: InheritedProfileConfig, allow_list: list[str] | None = None
            ) -> None:
        """Consider the fields that are only in the request, but not in the profile.

        Don't need to do any nested stuff here,
        since if the key is not in the profile, it will also not constrain sub-keys.

        Request fields are deleted in-place if they are not allowed by the profile.
        """
        if not isinstance(request, dict):
            return
        for field, value in list(request.items()):
            if field in profile or profile_config.allow_implicit or (allow_list and field in allow_list):
                # Field is explicitly or implicitly allowed, keep it
                continue
            # Field is not allowed, remove it
            if profile_config.reject_mods and value:
                msg = f"Field '{field}' is not explicitly allowed in the profile."
                raise ProfileValidationError(msg)
            del request[field]

    def _apply_profile_rules(self, request: dict[str, Any], profile: dict[str, Any],
                             parent_profile_config: InheritedProfileConfig | None = None) -> dict[str, Any]:
        """Apply the actual profile rules to one level of the request dict.

        It needs them both request and profile to be in the same structure and hierarchy,
        e.g. both in the "subject" sub-dict.
        """
        if not parent_profile_config: # top level
            parent_profile_config = InheritedProfileConfig()

        profile_allow = profile.get('allow', parent_profile_config.allow_implicit)
        profile_reject_mods = profile.get('reject_mods', parent_profile_config.reject_mods)
        profile_mutable = profile.get('mutable', parent_profile_config.mutable)

        profile_config = InheritedProfileConfig(
            allow_implicit=(profile_allow == '*'),
            reject_mods=profile_reject_mods,
            mutable=profile_mutable
        )

        if not request:
            request = {}

        self._handle_request_only_fields(
            request, profile, profile_config, profile_allow if isinstance(profile_allow, list) else None)

        # Constraining profile fields that should not literally be in the request
        skip_keys = {'type','allow', 'reject_mods', 'mutable', 'default', 'value', 'required'}
        filtered_profile = {k: v for k, v in profile.items() if k not in skip_keys}

        for field, profile_value in filtered_profile.items():
            print('Processing field:', field, 'Profile value:', profile_value, 'Request:', request)
            request_value = request.get(field)
            if profile_value is None and request_value is not None:
                # Field is not allowed in the profile, but present in the request
                if profile_reject_mods:
                    msg = f"Field '{field}' is prohibited in the profile."
                    raise ProfileValidationError(msg)
                del request[field]
                continue
            if field not in request:
                print(f'Field {field} not in request {request}')
                if isinstance(profile_value, dict):
                # check for default and required fields
                    if 'value' in profile_value:
                        # Set default value from profile
                        request[field] = profile_value['value']
                        continue
                    if 'default' in profile_value:
                        # Set default value from profile
                        print(f"Setting default for field '{field}' to {profile_value['default']}")
                        request[field] = profile_value['default']
                        continue
                    if 'required' in profile_value:
                        # Required field is missing in the request
                        msg = f"Field '{field}' is required but not present in the request."
                        raise ProfileValidationError(msg)
                    # 're' case
                    # should be fine to always call as "value" and stuff will get filtered and we end up with a no-op
                    request[field] = self._apply_profile_rules(request.setdefault(field, {}), profile_value, profile_config)
                elif JSONProfileVerifier._is_simple_type(profile_value):
                    request[field] = profile_value
                else:
                    print(f"Warning: Field '{field}' in profile is of type {type(profile_value).__name__}, skipping.")
                continue
            # Field is present in both request and profile
            if isinstance(profile_value, dict):
                request[field] = self._apply_profile_rules(request.setdefault(field, {}), profile_value, profile_config)
                local_value_mutable = profile_value.get('mutable', profile_mutable)
                if 'value' in profile_value and not local_value_mutable:
                    # Field is not mutable, force the value from the profile
                    if profile_reject_mods and request[field] != profile_value['value']:
                        msg = f"Field '{field}' is not mutable in the profile."
                        raise ProfileValidationError(msg)
                    request[field] = profile_value['value']
                    continue
            elif JSONProfileVerifier._is_simple_type(profile_value) and not profile_mutable:
                if profile_reject_mods and request[field] != profile_value:
                    msg = f"Field '{field}' is not mutable in the profile."
                    raise ProfileValidationError(msg)
                request[field] = profile_value
            else:
                print(f"Warning: Field '{field}' in profile is of type {type(profile_value).__name__}, skipping.")
                continue

        print(f'Resulting request at profile level {profile}:', request)

        return request

    def apply_profile_to_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Apply the profile to a certificate request and return the modified request."""
        validated_request = self.validate_request(request=request)
        print('Validated Request before profile rules:', validated_request)
        return self._apply_profile_rules(validated_request, self.profile_dict)
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

