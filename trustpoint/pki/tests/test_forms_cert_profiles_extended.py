# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for certificate profile forms and profile-driven field generation."""

from __future__ import annotations

import json
from typing import Any

import pytest
from django.core.exceptions import ValidationError

from management.models import SecurityConfig
from pki.forms.cert_profiles import (
    CertProfileConfigForm,
    ProfileBasedFormFieldBuilder,
    _validity_days_from_components,
    check_validity_days_against_security_config,
)
from pki.models.cert_profile import CertificateProfileModel

pytestmark = pytest.mark.django_db

SECONDS_PER_DAY = 86400


def _profile(**overrides: Any) -> dict[str, Any]:
    """Return a minimal valid certificate profile definition."""
    profile: dict[str, Any] = {
        'type': 'cert_profile',
        'display_name': 'Test Profile',
        'credential_type': 'application',
        'subj': {'cn': {'default': 'device.example'}},
        'validity': {'days': 10},
    }
    profile.update(overrides)
    return profile


class TestValidityComponents:
    """Conversion of validity components into days."""

    @pytest.mark.parametrize(
        ('kwargs', 'expected'),
        [
            ({'days': 2}, 2.0),
            ({'hours': 24}, 1.0),
            ({'minutes': 1440}, 1.0),
            ({'seconds': SECONDS_PER_DAY}, 1.0),
            ({'duration_seconds': SECONDS_PER_DAY}, 1.0),
            ({'days': 1, 'hours': 12}, 1.5),
            ({}, 0.0),
        ],
    )
    def test_components_are_summed_in_days(self, kwargs: dict[str, Any], expected: float) -> None:
        """Each supported component contributes its share of a day."""
        assert _validity_days_from_components(**kwargs) == pytest.approx(expected)


class TestValidityPolicyCheck:
    """Validity limits enforced by the active security policy."""

    def test_no_config_permits_any_validity(self) -> None:
        """Without a security config no validity limit is enforced."""
        SecurityConfig.objects.all().delete()

        assert check_validity_days_against_security_config(3650) is None

    def test_unset_limit_permits_any_validity(self) -> None:
        """A config without a maximum permits any validity."""
        SecurityConfig.objects.all().delete()
        SecurityConfig.objects.create(security_mode=True, max_cert_validity_days=None)

        assert check_validity_days_against_security_config(3650) is None

    def test_validity_above_limit_is_rejected(self) -> None:
        """A validity above the configured maximum is rejected."""
        SecurityConfig.objects.all().delete()
        SecurityConfig.objects.create(security_mode=True, max_cert_validity_days=30)

        with pytest.raises(ValidationError, match='exceeds the maximum'):
            check_validity_days_against_security_config(31)

    def test_validity_at_limit_is_permitted(self) -> None:
        """A validity exactly at the maximum is still permitted."""
        SecurityConfig.objects.all().delete()
        SecurityConfig.objects.create(security_mode=True, max_cert_validity_days=30)

        assert check_validity_days_against_security_config(30) is None


class TestCertProfileConfigForm:
    """Certificate profile creation and update form."""

    def test_valid_profile_is_accepted_and_metadata_extracted(self) -> None:
        """A valid profile is stored with its display name and credential type."""
        form = CertProfileConfigForm(
            data={'unique_name': 'valid_profile', 'profile_json': json.dumps(_profile())}
        )

        assert form.is_valid(), form.errors
        profile = form.save()
        assert profile.display_name == 'Test Profile'
        assert profile.credential_type == 'application'

    def test_dict_profile_input_is_accepted(self) -> None:
        """A profile supplied as a mapping is handled like JSON text."""
        form = CertProfileConfigForm(data={'unique_name': 'dict_profile', 'profile_json': _profile()})

        assert form.is_valid(), form.errors

    def test_malformed_json_is_rejected(self) -> None:
        """Syntactically invalid JSON is reported on the profile field."""
        form = CertProfileConfigForm(data={'unique_name': 'bad_json', 'profile_json': '{not json'})

        assert not form.is_valid()
        assert 'profile_json' in form.errors

    def test_semantically_invalid_profile_is_rejected(self) -> None:
        """JSON that is not a certificate profile is rejected."""
        form = CertProfileConfigForm(
            data={'unique_name': 'bad_profile', 'profile_json': json.dumps({'type': 'not_a_profile'})}
        )

        assert not form.is_valid()
        assert 'not a valid certificate profile' in str(form.errors['profile_json'])

    def test_duplicate_name_is_rejected(self) -> None:
        """A profile name that is already taken is rejected."""
        CertificateProfileModel.objects.create(
            unique_name='taken_profile', profile_json={'type': 'cert_profile'}
        )
        form = CertProfileConfigForm(
            data={'unique_name': 'taken_profile', 'profile_json': json.dumps(_profile())}
        )

        assert not form.is_valid()
        assert 'already taken' in str(form.errors['unique_name'])

    def test_existing_profile_keeps_its_own_name(self) -> None:
        """Editing a profile does not clash with its own stored name."""
        profile = CertificateProfileModel.objects.create(
            unique_name='editable_profile', profile_json={'type': 'cert_profile'}
        )
        form = CertProfileConfigForm(
            data={'unique_name': 'editable_profile', 'profile_json': json.dumps(_profile())},
            instance=profile,
        )

        assert form.is_valid(), form.errors

    def test_profile_validity_beyond_policy_is_rejected(self) -> None:
        """A profile whose validity exceeds the policy maximum is rejected."""
        SecurityConfig.objects.all().delete()
        SecurityConfig.objects.create(security_mode=True, max_cert_validity_days=5)
        form = CertProfileConfigForm(
            data={
                'unique_name': 'too_long_profile',
                'profile_json': json.dumps(_profile(validity={'days': 100})),
            }
        )

        assert not form.is_valid()
        assert 'exceeds the maximum' in str(form.errors['profile_json'])


class TestProfileBasedFormFieldBuilder:
    """Form fields generated from a certificate profile."""

    def _builder_profile(self, **overrides: Any) -> dict[str, Any]:
        """Return a normalized profile as consumed by the field builder."""
        profile: dict[str, Any] = {
            'type': 'cert_profile',
            'display_name': 'Test Profile',
            'subject': {'common_name': {'default': 'device.example'}},
            'validity': {'days': 7},
        }
        profile.update(overrides)
        return profile

    def test_subject_fields_are_built_from_profile(self) -> None:
        """Subject entries in the profile become form fields."""
        fields = ProfileBasedFormFieldBuilder(self._builder_profile()).build_all_fields()

        assert 'common_name' in fields
        assert fields['common_name'].initial == 'device.example'

    def test_required_subject_field_is_marked_required(self) -> None:
        """A required subject entry produces a required field with a badge."""
        profile = self._builder_profile(
            subject={'common_name': {'required': True, 'default': 'device.example'}}
        )

        fields = ProfileBasedFormFieldBuilder(profile).build_all_fields()

        assert fields['common_name'].required is True
        assert 'Required' in str(fields['common_name'].label)

    def test_immutable_field_is_disabled(self) -> None:
        """A non-mutable subject entry is rendered as disabled."""
        profile = self._builder_profile(
            subject={'common_name': {'mutable': False, 'default': 'fixed.example'}}
        )

        fields = ProfileBasedFormFieldBuilder(profile).build_all_fields()

        assert fields['common_name'].disabled is True

    def test_country_field_is_limited_to_two_characters(self) -> None:
        """Country entries are constrained to a two-letter code."""
        profile = self._builder_profile(subject={'country_name': {'default': 'DE'}})

        fields = ProfileBasedFormFieldBuilder(profile).build_all_fields()

        assert fields['country_name'].min_length == 2
        assert fields['country_name'].max_length == 2

    def test_wildcard_subject_builds_all_known_fields(self) -> None:
        """A wildcard subject exposes the full set of supported attributes."""
        profile = self._builder_profile(subject={'allow': '*'})

        fields = ProfileBasedFormFieldBuilder(profile).build_all_fields()

        assert 'common_name' in fields
        assert len(fields) > 2

    def test_san_fields_are_built_from_profile(self) -> None:
        """SAN entries in the profile become form fields."""
        profile = self._builder_profile(
            extensions={
                'subject_alternative_name': {
                    'dns_names': {'default': ['device.example', 'alt.example']},
                    'critical': False,
                }
            }
        )

        fields = ProfileBasedFormFieldBuilder(profile).build_all_fields()

        assert fields['dns_names'].initial == 'device.example, alt.example'

    def test_validity_fields_are_built_from_profile(self) -> None:
        """Validity components in the profile become form fields."""
        fields = ProfileBasedFormFieldBuilder(self._builder_profile()).build_all_fields()

        assert fields['days'].initial == 7
