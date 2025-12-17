"""JSON Certificate Profile implementation.

This module provides functionality to verify certificate requests against JSON-based profiles.

Profiles define allowed fields, prohibited fields, and other constraints for certificate requests.
They can also specify default values for fields and validate the request against these rules.
"""

import enum
import logging
from datetime import timedelta
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)
from trustpoint_core.oid import NameOid

from pki.util.ext_oids import CertificateExtensionOid  # temp

logger = logging.getLogger(__name__)

class ProfileValidationError(Exception):
    """Raised when the request is well-formed but does not match the profile constraints."""

ALIASES: dict[str, AliasChoices] = {
    #'common_name': AliasChoices('common_name', 'cn', 'CN', 'commonName', '2.5.4.3')
}

CERT_PROFILE_KEYWORDS = {'type','allow', 'reject_mods', 'mutable', 'default', 'value', 'required'}

def build_alias_map_name_oids(alias_map: dict[str, str], enum_cls: type[enum.Enum]) -> dict[str, str]:
    """Build a mapping of all known OID strings from trustpoint_core to their canonical field names."""
    for entry in enum_cls:
        canonical = entry.name.lower() # e.g. 'common_name'
        dotted_string = entry.value.dotted_string # e.g. '2.5.4.3'
        abbreviation = entry.value.abbreviation # e.g. 'CN'
        camel_case = entry.value.full_name # e.g. 'commonName'
        alias_map[dotted_string] = canonical
        choices = [dotted_string]
        if camel_case != canonical:
            alias_map[camel_case] = canonical
            choices.append(camel_case)
        alias_map[canonical] = canonical
        if abbreviation:
            abbreviation_lower = abbreviation.lower() # e.g. 'cn'
            alias_map[abbreviation] = canonical
            alias_map[abbreviation_lower] = canonical
            choices.extend([abbreviation, abbreviation_lower])
        ALIASES[canonical] = AliasChoices(canonical, *choices)
    return alias_map

alias_map = build_alias_map_name_oids({}, NameOid)
alias_map = build_alias_map_name_oids(alias_map, CertificateExtensionOid)

# Important: Pydantic V2 model_config does not follow MRO!
# Non-default Model config settings are taken from the last base class set to a non-default value.
# To be on the safe side, set model_config on the final final child classes.
# See: https://github.com/pydantic/pydantic/issues/9992

class ProfileValuePropertyModel(BaseModel):
    """Model for a profile value property."""
    value: Any | None = None
    default: Any | None = None
    required: bool = False
    mutable: bool = True

class SubjectModel(BaseModel):
    """Model for the subject DN of a certificate profile."""
    common_name: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('common_name'),
    )
    surname: str | ProfileValuePropertyModel | None = Field(default=None, validation_alias=ALIASES.get('surname'))
    serial_number: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('serial_number'),
    )
    country_name: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('country_name'),
    )
    locality_name: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('locality_name'),
    )
    state_or_province_name: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('state_or_province_name')
    )
    street_address: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('street_address')
    )
    organization_name: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('organization_name')
    )
    organizational_unit_name: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('organizational_unit_name')
    )
    title: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('title')
    )
    description: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('description')
    )
    postal_code: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('postal_code'),
    )
    email_address: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('email_address'),
    )
    name: str | ProfileValuePropertyModel | None = Field(default=None, validation_alias=ALIASES.get('name'))
    given_name: str | ProfileValuePropertyModel | None = Field(default=None, validation_alias=ALIASES.get('given_name'))
    initials: str | ProfileValuePropertyModel | None = Field(default=None, validation_alias=ALIASES.get('initials'))
    pseudonym: str | ProfileValuePropertyModel | None = Field(default=None, validation_alias=ALIASES.get('pseudonym'))
    uid: str | ProfileValuePropertyModel | None = Field(default=None, validation_alias=ALIASES.get('uid'))
    domain_component: str | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('domain_component')
    )

    # Should allow unknown fields, but not required
    model_config = ConfigDict(extra='allow')

class BaseExtensionModel(BaseModel):
    """Base model for certificate extensions."""
    critical: bool | None = None

    model_config = ConfigDict(extra='forbid')

class BasicConstraintsExtensionModel(BaseExtensionModel):
    """Model for the Basic Constraints extension of a certificate profile."""
    ca: bool | None = None
    path_length: int | None = None

    model_config = ConfigDict(extra='forbid')

class SanExtensionModel(BaseExtensionModel, ProfileValuePropertyModel):
    """Model for the SAN extension of a certificate profile."""
    dns_names: list[str] | ProfileValuePropertyModel | None = Field(default=None, validation_alias='dns')
    ip_addresses: list[str] | ProfileValuePropertyModel | None = Field(default=None, validation_alias='ip')
    rfc822_names: list[str] | ProfileValuePropertyModel | None = Field(default=None, validation_alias='rfc822')
    uris: list[str] | ProfileValuePropertyModel | None = Field(default=None, validation_alias='uri')
    other_names: list[str] | ProfileValuePropertyModel | None = Field(default=None, validation_alias='other')
    model_config = ConfigDict(extra='forbid', validate_by_alias=False, validate_by_name=True)

class CRLDistributionPointsExtensionModel(BaseExtensionModel, ProfileValuePropertyModel):
    """Model for the CRL Distribution Points extension of a certificate profile.

    Note: Only URIs in full_name are supported.
    """
    uris: list[str] | ProfileValuePropertyModel | None = None

    model_config = ConfigDict(extra='forbid')

class KeyUsageExtensionModel(BaseExtensionModel):
    """Model for the Key Usage extension of a certificate profile."""
    digital_signature: bool | None = None
    content_commitment: bool | None = None
    key_encipherment: bool | None = None
    data_encipherment: bool | None = None
    key_agreement: bool | None = None
    key_cert_sign: bool | None = None
    crl_sign: bool | None = None
    encipher_only: bool | None = None
    decipher_only: bool | None = None

    model_config = ConfigDict(extra='forbid')

class ExtendedKeyUsageExtensionModel(BaseExtensionModel):
    """Model for the Extended Key Usage extension of a certificate profile."""
    usages: list[str] | ProfileValuePropertyModel | None = None

    model_config = ConfigDict(extra='forbid')

class ExtensionsModel(BaseModel):
    """Model for the extensions of a certificate request."""
    basic_constraints: BasicConstraintsExtensionModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('basic_constraints'),
    )
    key_usage: KeyUsageExtensionModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('key_usage'),
    )
    extended_key_usage: ExtendedKeyUsageExtensionModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('extended_key_usage'),
    )
    subject_alternative_name: SanExtensionModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('subject_alternative_name'),
    )
    crl_distribution_points: CRLDistributionPointsExtensionModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('crl_distribution_points'),
    )
    #model_config = ConfigDict(validate_by_validation_alias=False, validate_by_name=True)  # noqa: ERA001


class ValidityModel(BaseModel):
    """Model for the validity period of a certificate profile."""
    not_before: AwareDatetime | None = None  # ISO 8601 format
    not_after: AwareDatetime | None = None  # ISO 8601 format
    days: float | None = None  # Number of days for validity
    hours: float | None = None  # Number of hours for validity
    minutes: float | None = None  # Number of minutes for validity
    seconds: int | None = None  # Number of seconds for validity
    duration: timedelta | None = None  # Duration string in ISO 8601 format

    offset_s: int | None = None  # Offset in seconds
    validity_max: timedelta | None = None  # Maximum validity period in ISO 8601 format
    validity_min: timedelta | None = None  # Minimum validity period in ISO 8601 format

    model_config = ConfigDict(extra='ignore')  # allow, ignore (default)

class CertProfileBaseModel(BaseModel):
    """Base model for each nesting level of certificate profiles.

    This allows for granular control over allowed fields and constraints at each level.
    """
    allow: list[str] | Literal['*'] | None = None
    reject_mods: bool = Field(default=False)

    @field_validator('allow', mode='before')
    @classmethod
    def normalize_allow(cls, value: list[str] | Literal['*'] | None) -> list[str] | Literal['*'] | None:
        """Normalize the allow list by replacing aliases with their canonical names."""
        if not isinstance(value, list):
            return value
        normalized = []
        for item in value:
            try:
                normalized.append(alias_map[item])
            except KeyError:
                normalized.append(item)
        return normalized

class ProfileSubjectModel(SubjectModel, CertProfileBaseModel):
    """Model for the subject DN of a certificate profile, with profile constraints."""

# Profile-specific extension models are required for extensions that allow lists of strings/nested structures
class ProfileSanExtensionModel(SanExtensionModel, CertProfileBaseModel):
    """Model for the SAN extension of a certificate profile, with profile constraints."""

class ProfileCrlDistributionPointsExtensionModel(CRLDistributionPointsExtensionModel, CertProfileBaseModel):
    """Model for the CRL Distribution Points extension of a certificate profile, with profile constraints."""

class ProfileExtensionsModel(CertProfileBaseModel):
    """Model for the extensions of a certificate profile, with profile constraints."""
    basic_constraints: BasicConstraintsExtensionModel | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('basic_constraints'),
    )
    key_usage: KeyUsageExtensionModel | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('key_usage'),
    )
    extended_key_usage: ExtendedKeyUsageExtensionModel | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('extended_key_usage'),
    )
    subject_alternative_name: ProfileSanExtensionModel | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('subject_alternative_name'),
    )
    crl_distribution_points: ProfileCrlDistributionPointsExtensionModel | ProfileValuePropertyModel | None = Field(
        default=None,
        validation_alias=ALIASES.get('crl_distribution_points'),
    )

class CertProfileModel(CertProfileBaseModel):
    """Model for a certificate profile."""
    type: Literal['cert_profile']
    display_name: str | None = None
    subject: ProfileSubjectModel = Field(validation_alias='subj', default=ProfileSubjectModel())
    extensions: ProfileExtensionsModel = Field(validation_alias='ext', default=ProfileExtensionsModel())
    validity: ValidityModel = Field(default=ValidityModel(days=10))


class CertRequestModel(BaseModel):
    """Model for a certificate request."""
    type: Literal['cert_request'] | None = 'cert_request'
    subject: SubjectModel = Field(validation_alias='subj', default=SubjectModel())
    extensions: ExtensionsModel = Field(validation_alias='ext', default=ExtensionsModel())
    validity: ValidityModel = Field(default=ValidityModel(days=10))

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
        logger.debug('Profile: %s', self.profile)

        self.profile_dict = validated_profile.model_dump(exclude_unset=True, exclude_defaults=False)
        logger.debug('Profile Dict: %s', self.profile_dict)

    @staticmethod
    def validate_request(request: dict[str, Any]) -> dict[str, Any]:
        """Validates and normalizes a certificate request.

        This just checks its structure, it does not validate against a profile.
        """
        req_model = CertRequestModel.model_validate(request)
        return req_model.model_dump(exclude_unset=True)

    @staticmethod
    def _is_simple_type(value: Any) -> bool:
        """Check if the value is a simple type (not a dict, class).

        Excludes None, since we check it separately.

        List is considered a simple type here (e.g. for SAN dns_names).
        """
        return isinstance(value, (str, int, float, bool, list))

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

    def _handle_profile_only_field(self, profile_value: Any, field: str, request: dict[str, Any],
                                   profile_config: InheritedProfileConfig) -> None:
        if isinstance(profile_value, dict):
        # check for default and required fields
            if 'value' in profile_value:
                # Set default value from profile
                request[field] = profile_value['value']
                return
            if 'default' in profile_value:
                # Set default value from profile
                logger.debug("Setting default for field '%s' to %s", field, profile_value['default'])
                request[field] = profile_value['default']
                return
            if 'required' in profile_value:
                # Required field is missing in the request
                msg = f"Field '{field}' is required but not present in the request."
                raise ProfileValidationError(msg)
            # TODO(Air): 're' case  # noqa: FIX002
            # should be fine to always call as "value" and stuff will get filtered and we end up with a no-op
            request[field] = self._apply_profile_rules(
                request.setdefault(field, {}), profile_value, profile_config)
        elif JSONProfileVerifier._is_simple_type(profile_value):
            request[field] = profile_value
        else:
            logger.warning("Field '%s' in profile has type %s, skipping.", field, type(profile_value).__name__)

    def _handle_profile_and_req_field(self, profile_value: Any, field: str, request: dict[str, Any],
                                      profile_config: InheritedProfileConfig) -> None:
        profile_mutable = profile_config.mutable
        profile_reject_mods = profile_config.reject_mods

        if isinstance(profile_value, dict):
            request[field] = self._apply_profile_rules(request.setdefault(field, {}), profile_value, profile_config)
            local_value_mutable = profile_value.get('mutable', profile_mutable)
            if 'value' in profile_value and not local_value_mutable:
                # Field is not mutable, force the value from the profile
                if profile_reject_mods and request[field] != profile_value['value']:
                    msg = f"Field '{field}' is not mutable in the profile."
                    raise ProfileValidationError(msg)
                request[field] = profile_value['value']
                return
        elif JSONProfileVerifier._is_simple_type(profile_value) and not profile_mutable:
            if profile_reject_mods and request[field] != profile_value:
                msg = f"Field '{field}' is not mutable in the profile."
                raise ProfileValidationError(msg)
            request[field] = profile_value
        else:
            logger.warning("Field '%s' in profile has type %s, skipping.", field, type(profile_value).__name__)

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
        skip_keys = CERT_PROFILE_KEYWORDS
        filtered_profile = {k: v for k, v in profile.items() if k not in skip_keys}

        for field, profile_value in filtered_profile.items():
            logger.debug('Processing field: %s Profile value: %s Request: %s', field, profile_value, request)
            request_value = request.get(field)
            if profile_value is None and request_value is not None:
                # Field is not allowed in the profile, but present in the request
                if profile_reject_mods:
                    msg = f"Field '{field}' is prohibited in the profile."
                    raise ProfileValidationError(msg)
                del request[field]
                continue
            if field not in request:
                logger.debug('Field %s not in request %s', field, request)
                self._handle_profile_only_field(profile_value, field, request, profile_config)
                continue
            # Field is present in both request and profile
            self._handle_profile_and_req_field(profile_value, field, request, profile_config)

        logger.debug('Resulting request at profile level %s: %s', profile, request)

        return request

    def apply_profile_to_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Apply the profile to a certificate request and return the modified request."""
        validated_request = self.validate_request(request=request)
        logger.debug('Validated Request before profile rules: %s', validated_request)
        return self._apply_profile_rules(validated_request, self.profile_dict)

    def _apply_profile_rules_sample(self, request: dict[str, Any], profile: dict[str, Any],
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

        # Constraining profile fields that should not literally be in the request
        skip_keys = CERT_PROFILE_KEYWORDS
        filtered_profile = {k: v for k, v in profile.items() if k not in skip_keys}

        for field, profile_value in filtered_profile.items():
            logger.debug('Processing field: %s Profile value: %s Request: %s', field, profile_value, request)
            logger.debug('Field %s not in request %s', field, request)
            if isinstance(profile_value, dict):
            # check for default and required fields
                if 'value' in profile_value:
                    # Set default value from profile
                    request[field] = profile_value['value']
                    continue
                if 'default' in profile_value:
                    # Set default value from profile
                    logger.debug("Setting default for field '%s' to %s", field, profile_value['default'])
                    request[field] = profile_value['default']
                    continue
                if 'required' in profile_value:
                    # Required field is missing in the request
                    request[field] = f'CHANGEME_{field}_required'
                    continue
                # TODO(Air): 're' case  # noqa: FIX002
                # should be fine to always call as "value" and stuff will get filtered and we end up with a no-op
                request[field] = self._apply_profile_rules_sample(
                    request.setdefault(field, {}), profile_value, profile_config)
            elif JSONProfileVerifier._is_simple_type(profile_value):
                request[field] = profile_value
            else:
                logger.warning("Field '%s' in profile has type %s, skipping.", field, type(profile_value).__name__)
            continue
        return request

    def get_sample_request(self) -> dict[str, Any]:
        """Generate a sample certificate request that conforms to the profile."""
        return self._apply_profile_rules_sample({}, self.profile_dict)
