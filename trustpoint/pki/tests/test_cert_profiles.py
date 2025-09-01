"""Tests for the JSON template verification module."""

import pytest
from pydantic import ValidationError

from pki.util.cert_profile import JSONProfileVerifier, ProfileValidationError


def test_valid_profile_instance() -> None:
    """Test that a valid profile instance can be created."""
    template = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'allow': '*',
        'reject_mods': False
    }
    verifier = JSONProfileVerifier(template)
    assert isinstance(verifier, JSONProfileVerifier)


def test_invalid_profile_instance() -> None:
    """Test that an invalid profile instance raises an error."""
    template = {
        'type': 'not_a_profile',
    }
    with pytest.raises(ValidationError):
        JSONProfileVerifier(template)


def test_prohibited_cn_present() -> None:
    """Test that a request with a prohibited CN fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': None},
        'reject_mods': True
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is prohibited in the profile."):
        verifier.apply_profile_to_request(request)

def test_prohibited_cn_present_no_reject() -> None:
    """Test that a request with a prohibited CN is removed when reject_mods is False."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': None},
        'reject_mods': False
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com', 'ou': 'IT'}
    }
    validated_request = verifier.apply_profile_to_request(request)
    print('Validated Request: ', validated_request)
    assert 'common_name' not in validated_request['subject']

def test_allowed_cn_present() -> None:
    """Test that a request with an allowed CN passes verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'allow': ['cn','common_name']},
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    validated_request = verifier.apply_profile_to_request(request)
    print('Validated Request: ', validated_request)
    assert validated_request['subject']['common_name'] == 'example.com'

def test_allowed_cn_alias_present() -> None:
    """Test that a request with an allowed CN passes verification (alias 'cn' for 'common_name')."""
    profile = {
        'type': 'cert_profile',
        'subj': {'allow': ['cn']},
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    validated_request = verifier.apply_profile_to_request(request)
    print('Validated Request: ', validated_request)
    assert validated_request['subject']['common_name'] == 'example.com'

def test_unspecified_cn_present_no_reject() -> None:
    """Test that a not explicitly allowed CN without implicit allow is removed from the request."""
    profile = {
        'type': 'cert_profile',
        'subj': {'allow': ['pamajauke']},
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    validated_request = verifier.apply_profile_to_request(request)
    assert 'common_name' not in validated_request['subject']

def test_unspecified_cn_present_reject() -> None:
    """Test that a not explicitly allowed CN with reject_mods=True fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'allow': ['pamajauke']},
        'reject_mods': True
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is not explicitly allowed in the profile."):
        verifier.apply_profile_to_request(request)

def test_default_cn_present_in_request() -> None:
    """Test that the request CN takes precedence over the profile's default CN."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': {'default': 'default.example.com'}},
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['subject']['common_name'] == 'example.com'

def test_default_cn_absent_in_request() -> None:
    """Test that the profile's default CN is applied when the request CN is absent."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': {'default': 'default.example.com'}},
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {}}
    validated_request = verifier.apply_profile_to_request(request)
    print('Validated Request: ', validated_request)
    assert validated_request['subject']['common_name'] == 'default.example.com'

def test_implicit_allow_subject() -> None:
    """Test that a request with implicit allow for all fields passes verification."""
    template = {
        'type': 'cert_profile',
        'allow': '*',
    }
    verifier = JSONProfileVerifier(template)
    request = {
        'subj': {'cn': 'example.com', 'ou': 'IT'},
    }
    assert verifier.apply_profile_to_request(request)

def test_implicit_allow_unknown_field() -> None:
    """Test that a request with an unknown field passes verification with implicit allow."""
    template = {
        'type': 'cert_profile',
        'allow': '*',
    }
    verifier = JSONProfileVerifier(template)
    request = {
        # This should probably still fail if the field is not recognized at all / add OID map in Trustpoint core?
        'subj': {'cn': 'example.com', 'unknown_field': 'value'},
        #'type': None
    }
    assert verifier.apply_profile_to_request(request)

def test_required_cn_absent() -> None:
    """Test that a request missing a required CN fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': {'required': True}},
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'ou': 'IT'}
    }
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is required but not present in the request."):
        verifier.apply_profile_to_request(request)

def test_incompatible_request_cn() -> None:
    """Test that a request with a CN incompatible with the profile and reject_mods fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'onlyallowed.com'},
        'reject_mods': True
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is not mutable in the profile."):
        verifier.apply_profile_to_request(request)

def test_incompatible_request_cn_no_reject_mods() -> None:
    """Test that a request with a CN incompatible with the profile and no reject_mods uses the CN from the profile."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'onlyallowed.com'},
        'reject_mods': False
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'}
    }
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['subject']['common_name'] == 'onlyallowed.com'

def test_request_normalization() -> None:
    """Test that a request is normalized correctly."""
    request = {
        'subj': {'cn': 'example.com'},
    }
    validated_request = JSONProfileVerifier.validate_request(request)
    # 'subj' should be expanded to 'subject' and 'cn' to 'common_name'
    assert validated_request['subject']['common_name'] == 'example.com'
