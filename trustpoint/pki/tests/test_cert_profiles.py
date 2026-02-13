"""Tests for the JSON template verification module."""

from re import match
import pytest
from pydantic import ValidationError

from pki.util.cert_profile import JSONProfileVerifier, ProfileValidationError
from pki.util.cert_req_converter import JSONCertRequestConverter


def test_valid_profile_instance() -> None:
    """Test that a valid profile instance can be created."""
    template = {'type': 'cert_profile', 'subj': {'cn': 'example.com'}, 'allow': '*', 'reject_mods': False}
    verifier = JSONProfileVerifier(template)
    assert isinstance(verifier, JSONProfileVerifier)


def test_invalid_profile_instance() -> None:
    """Test that an invalid profile instance raises an error."""
    template = {
        'type': 'not_a_profile',
    }
    with pytest.raises(ValidationError):
        JSONProfileVerifier(template)


def test_incomplete_profile_instance() -> None:
    """Test that an incomplete profile instance raises an error.

    Behavior (subject to change) when 'subj' field is missing:
    - Effectively prohibits subject, which is not valid in X.509 certs.
    """
    template = {
        'type': 'cert_profile',
        # 'subj' field is missing
    }
    # with pytest.raises(ValidationError) as exc_info:
    JSONProfileVerifier(template)


# --- Subject field tests ---


def test_prohibited_cn_present() -> None:
    """Test that a request with a prohibited CN fails verification."""
    profile = {'type': 'cert_profile', 'subj': {'cn': None}, 'reject_mods': True}
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}}
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is prohibited in the profile."):
        verifier.apply_profile_to_request(request)


def test_prohibited_cn_present_no_reject() -> None:
    """Test that a request with a prohibited CN is removed when reject_mods is False."""
    profile = {'type': 'cert_profile', 'subj': {'cn': None}, 'reject_mods': False}
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com', 'ou': 'IT'}}
    validated_request = verifier.apply_profile_to_request(request)
    print('Validated Request: ', validated_request)
    assert 'common_name' not in validated_request['subject']


def test_allowed_cn_present() -> None:
    """Test that a request with an allowed CN passes verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'allow': ['cn', 'common_name']},
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}}
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
    request = {'subj': {'cn': 'example.com'}}
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
    request = {'subj': {'cn': 'example.com'}}
    validated_request = verifier.apply_profile_to_request(request)
    assert 'common_name' not in validated_request['subject']


def test_unspecified_cn_present_reject() -> None:
    """Test that a not explicitly allowed CN with reject_mods=True fails verification."""
    profile = {'type': 'cert_profile', 'subj': {'allow': ['pamajauke']}, 'reject_mods': True}
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}}
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is not explicitly allowed in the profile."):
        verifier.apply_profile_to_request(request)


def test_default_cn_present_in_request() -> None:
    """Test that the request CN takes precedence over the profile's default CN."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': {'default': 'default.example.com'}},
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}}
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
    request = {'subj': {'ou': 'IT'}}
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is required but not present in the request."):
        verifier.apply_profile_to_request(request)


def test_incompatible_request_cn() -> None:
    """Test that a request with a CN incompatible with the profile and reject_mods fails verification."""
    profile = {'type': 'cert_profile', 'subj': {'cn': 'onlyallowed.com'}, 'reject_mods': True}
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}}
    with pytest.raises(ProfileValidationError, match="Field 'common_name' is not mutable in the profile."):
        verifier.apply_profile_to_request(request)


def test_incompatible_request_cn_no_reject_mods() -> None:
    """Test that a request with a CN incompatible with the profile and no reject_mods uses the CN from the profile."""
    profile = {'type': 'cert_profile', 'subj': {'cn': 'onlyallowed.com'}, 'reject_mods': False}
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}}
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['subject']['common_name'] == 'onlyallowed.com'


# --- Extension tests ---


def test_required_ext_absent() -> None:
    """Test that a request missing a required extension fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'san': {'required': True}},
        'reject_mods': True,
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {}}
    with pytest.raises(
        ProfileValidationError, match="Field 'subject_alternative_name' is required but not present in the request."
    ):
        verifier.apply_profile_to_request(request)


def test_default_ext_present_in_req() -> None:
    """Test that the request extension takes precedence over the profile's default extension."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        #'ext': {'san': {'default': {'dns_names': ['default.example.com']}}},
        # This variant also works:
        'ext': {'san': {'dns_names': {'default': ['default.example.com']}}},
        'reject_mods': False,
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['example.com']}}}
    validated_request = verifier.apply_profile_to_request(request)
    print('Validated Request: ', validated_request)
    assert validated_request['extensions']['subject_alternative_name']['dns_names'] == ['example.com']


def test_default_ext_absent_in_req() -> None:
    """Test that the profile's default extension is applied when the request extension is absent."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'san': {'default': {'dns_names': ['example.com']}}},
        'reject_mods': False,
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {}}
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['extensions']['subject_alternative_name']['dns_names'] == ['example.com']


def test_incompatible_ext() -> None:
    """Test that a request with an extension incompatible with the profile and reject_mods fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'san': {'dns_names': ['default.example.com']}},
        'reject_mods': True,
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['incompatible.example.com']}}}
    with pytest.raises(ProfileValidationError, match="Field 'dns_names' is not mutable in the profile."):
        verifier.apply_profile_to_request(request)


def test_incompatible_ext_extra_field() -> None:
    """Test that a request with an extension incompatible with the profile (extra field in req) and reject_mods fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'san': {'dns_names': ['ok.example.com']}},
        'reject_mods': True,
    }
    verifier = JSONProfileVerifier(profile)
    request = {
        'subj': {'cn': 'example.com'},
        'ext': {'san': {'dns_names': ['ok.example.com'], 'uris': ['https://not-ok.example.com']}},
    }
    with pytest.raises(ProfileValidationError, match="Field 'uris' is not explicitly allowed in the profile."):
        verifier.apply_profile_to_request(request)


def test_incompatible_ext_no_reject() -> None:
    """Test that a request with an incompatible extension and no reject_mods uses the extension from the profile."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'san': {'dns_names': ['value.example.com']}},
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['incompatible.example.com']}}}
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['extensions']['subject_alternative_name']['dns_names'] == ['value.example.com']


def test_ext_value_mutable() -> None:
    """Test that a request with a mutable extension value passes verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        #'ext': {'san': {'value': {'dns_names': ['val.example.com']}, 'mutable': True}}
        # This variant works
        'ext': {
            'san': {'dns_names': ['val.example.com'], 'mutable': True},
            'crl': {'uris': ['http://crl.example.com/crl.pem']},
        },
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['mutable.example.com']}}}
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['extensions']['subject_alternative_name']['dns_names'] == ['mutable.example.com']
    assert validated_request['extensions']['crl_distribution_points']['uris'] == ['http://crl.example.com/crl.pem']


def test_prohibited_ext_present() -> None:
    """Test that a request with a prohibited extension fails verification."""
    profile = {'type': 'cert_profile', 'subj': {'cn': 'example.com'}, 'ext': {'san': None}, 'reject_mods': True}
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['prohibited.example.com']}}}
    with pytest.raises(ProfileValidationError, match="Field 'subject_alternative_name' is prohibited in the profile."):
        verifier.apply_profile_to_request(request)


def test_not_allowed_ext_present() -> None:
    """Test that a request with an extension not explicitely allowed by the profile fails verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'allow': ['key_usage']},
        'reject_mods': True,
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['not.allowed.example.com']}}}
    with pytest.raises(
        ProfileValidationError, match="Field 'subject_alternative_name' is not explicitly allowed in the profile."
    ):
        verifier.apply_profile_to_request(request)


def test_allowed_ext_present() -> None:
    """Test that a request with an allowed extension passes verification."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'allow': ['san', 'key_usage']},
        'reject_mods': True,
    }
    verifier = JSONProfileVerifier(profile)
    print(verifier.profile.model_dump())
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['allowed.example.com']}}}
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['extensions']['subject_alternative_name']['dns_names'] == ['allowed.example.com']


def test_allowed_ext_allow_any() -> None:
    """Test that a request with any extension passes verification when allow='*'."""
    profile = {'type': 'cert_profile', 'subj': {'cn': 'example.com'}, 'ext': {'allow': '*'}, 'reject_mods': True}
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['any.allowed.example.com']}}}
    validated_request = verifier.apply_profile_to_request(request)
    assert validated_request['extensions']['subject_alternative_name']['dns_names'] == ['any.allowed.example.com']


def test_allowed_ext_allow_any_explicit_profile() -> None:
    """Test that a request with a SAN extension passes verification when allow='*' and SAN specified in profile."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'allow': '*', 'san': {'mutable': True, 'dns_names': ['should.not.matter.example.com']}},
        'reject_mods': True,
    }
    verifier = JSONProfileVerifier(profile)
    request = {'subj': {'cn': 'example.com'}, 'ext': {'san': {'dns_names': ['any.allowed.example.com']}}}
    validated_request = verifier.apply_profile_to_request(request)
    print('Validated Request: ', validated_request)
    assert validated_request['extensions']['subject_alternative_name']['dns_names'] == ['any.allowed.example.com']


def test_sample_request_contains_ext_defaults() -> None:
    """Test that a sample request generated from a profile includes default extension values."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {'san': {'dns_names': {'default': ['default.example.com']}}},
        'reject_mods': False,
    }
    verifier = JSONProfileVerifier(profile)
    sample_request = verifier.get_sample_request()
    print('Sample Request: ', sample_request)
    assert sample_request['extensions']['subject_alternative_name']['dns_names'] == ['default.example.com']


def test_sample_request_contains_ext_defaults_allow_any() -> None:
    """Regression test that a sample req. from a profile includes default ext values when allow='*'."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'example.com'},
        'ext': {
            'san': {'dns_names': {'default': ['default.example.com']}, 'allow': '*'},
        },
        'reject_mods': False,
    }
    verifier = JSONProfileVerifier(profile)
    sample_request = verifier.get_sample_request()
    print('Sample Request: ', sample_request)
    assert sample_request['extensions']['subject_alternative_name']['dns_names'] == ['default.example.com']


# --- General parsing and conversion tests ---


def test_request_normalization() -> None:
    """Test that a request is normalized correctly."""
    request = {
        'subj': {'cn': 'example.com'},
    }
    validated_request = JSONProfileVerifier.validate_request(request)
    # 'subj' should be expanded to 'subject' and 'cn' to 'common_name'
    assert validated_request['subject']['common_name'] == 'example.com'


def test_csr_to_json_adapter() -> None:
    """Test that the CSR to JSON adapter works correctly."""
    import ipaddress

    from cryptography import x509

    # Generate a test Certificate Builder
    csr = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'example.com'),
                    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'Example Org'),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName('www.example.com'),
                    x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                    x509.RFC822Name('user@example.com'),
                    x509.UniformResourceIdentifier('http://www.example.com'),
                    x509.OtherName(x509.ObjectIdentifier('2.5.4.45'), b'John'),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Normally not included in CSR
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier('http://crl.example.com/crl.pem')],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    )

    csr_json = JSONCertRequestConverter.to_json(csr)
    print('JSON Cert Request:', csr_json)
    validated_request = JSONProfileVerifier.validate_request(csr_json)
    print('Validated Request:', validated_request)
    assert validated_request['subject']['common_name'] == 'example.com'


def test_json_to_cb_adapter() -> None:
    """Test that the JSON to Certificate Builder adapter works correctly."""
    from cryptography import x509

    request = {
        'subj': {'cn': 'example.com', 'o': 'Example Org'},
        'ext': {
            'san': {'dns_names': {'default': ['www.example.com']}},
            'crl': {'uris': ['http://crl.example.com/crl.pem']},
        },
        'validity': {'days': 30},
    }
    validated_request = JSONProfileVerifier.validate_request(request)
    cb = JSONCertRequestConverter.from_json(validated_request)
    print('Cert from JSON Request:', cb)
    assert cb._subject_name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'example.com'  # noqa: SLF001
    extensions = cb._extensions  # noqa: SLF001
    assert extensions is not None
    crl_dp = next((ext.value for ext in extensions if isinstance(ext.value, x509.CRLDistributionPoints)), None)
    assert crl_dp is not None
    if crl_dp:
        assert crl_dp[0].full_name[0].value == 'http://crl.example.com/crl.pem'


def test_json_to_cb_adapter_no_validity() -> None:
    """Test that the JSON to Certificate Builder adapter raises an error when validity is missing."""
    request = {
        'subj': {'cn': 'example.com', 'o': 'Example Org'},
        'ext': {
            'san': {
                'dns_names': ['www.example.com'],
            },
            'crl': {'uris': ['http://crl.example.com/crl.pem']},
        },
        # No validity field
    }
    validated_request = JSONProfileVerifier.validate_request(request)
    with pytest.raises(ValueError, match='Validity period must be specified in the profile.'):
        JSONCertRequestConverter.from_json(validated_request)
