"""Tests for the JSON template verification module."""

import pytest
from pydantic import ValidationError

from pki.util.cert_profile import JSONProfileVerifier


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
    template = {
        'type': 'cert_profile',
        'subj': {'cn': None},
        'reject_mods': True
    }
    verifier = JSONProfileVerifier(template)
    request = {
        'subj': {'cn': 'example.com'}
    }
    with pytest.raises(ValidationError):
        verifier.apply_profile(request)

def test_allowed_cn_present() -> None:
    """Test that a request with an allowed CN passes verification."""
    template = {
        'type': 'cert_profile',
        'subj': {'allow': ['cn']},
    }
    verifier = JSONProfileVerifier(template)
    request = {
        'subj': {'cn': 'example.com'}
    }
    validated_request = verifier.apply_profile(request)
    assert validated_request['subj']['cn'] == 'example.com'

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
    assert verifier.apply_profile(request)

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
        'type': None
    }
    assert verifier.apply_profile(request)

def test_request_normalization() -> None:
    """Test that a request is normalized correctly."""
    request = {
        'subj': {'cn': 'example.com'},
    }
    validated_request = JSONProfileVerifier.validate_request(request)
    # 'subj' should be expanded to 'subject' and 'cn' to 'common_name'
    assert validated_request['subject']['common_name'] == 'example.com'
