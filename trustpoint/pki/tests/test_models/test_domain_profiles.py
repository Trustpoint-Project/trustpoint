# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for DomainModel profile management and issuing CA relationships."""

from __future__ import annotations

from typing import Any

import pytest
from django.core.exceptions import ValidationError
from trustpoint_core import oid

from pki.models import CaModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainAllowedCertificateProfileModel, DomainModel

pytestmark = pytest.mark.django_db


@pytest.fixture
def profile() -> CertificateProfileModel:
    """Return a non-default application profile."""
    return CertificateProfileModel.objects.create(
        unique_name='tls_server', display_name='TLS Server', profile_json={'type': 'cert_profile'}
    )


@pytest.fixture
def domain_credential_profile() -> CertificateProfileModel:
    """Return the conventional domain credential profile."""
    return CertificateProfileModel.objects.create(
        unique_name='domain_credential',
        display_name='Domain Credential',
        credential_type=CertificateProfileModel.ProfileCredentialType.DOMAIN,
        profile_json={'type': 'cert_profile'},
    )


@pytest.fixture
def domain(issuing_ca_instance: dict[str, Any]) -> DomainModel:
    """Return a domain backed by a real issuing CA."""
    return DomainModel.objects.create(
        unique_name='profile_domain', issuing_ca=issuing_ca_instance['issuing_ca'], is_active=True
    )


class TestDomainValidation:
    """Domain creation constraints."""

    def test_autogen_root_ca_cannot_back_a_domain(self, issuing_ca_instance: dict[str, Any]) -> None:
        """Auto-generated root CAs may not be used as a domain issuing CA."""
        ca = issuing_ca_instance['issuing_ca']
        ca.ca_type = CaModel.CaTypeChoice.AUTOGEN_ROOT
        domain = DomainModel(unique_name='invalid_domain', issuing_ca=ca)

        with pytest.raises(ValidationError, match='auto-generated root'):
            domain.clean()

    def test_missing_issuing_ca_raises_value_error(self) -> None:
        """A domain without an issuing CA cannot resolve one."""
        domain = DomainModel.objects.create(unique_name='no_ca_domain')

        with pytest.raises(ValueError, match='does not have a corresponding Issuing CA'):
            domain.get_issuing_ca_or_value_error()

    def test_str_returns_unique_name(self, domain: DomainModel) -> None:
        """The string form of a domain is its unique name."""
        assert str(domain) == 'profile_domain'


class TestDomainSignatureSuite:
    """Signature suite derived from the domain issuing CA."""

    def test_signature_suite_matches_issuing_ca_certificate(
        self, domain: DomainModel, issuing_ca_instance: dict[str, Any]
    ) -> None:
        """The suite is derived from the issuing CA certificate."""
        expected = oid.SignatureSuite.from_certificate(issuing_ca_instance['cert'])

        assert domain.signature_suite == expected
        assert domain.public_key_info == expected.public_key_info

    def test_signature_suite_display_is_human_readable(self, domain: DomainModel) -> None:
        """The display helper returns a non-placeholder value for a real CA."""
        assert domain.signature_suite_display != '-'

    def test_signature_suite_is_none_without_certificate(self, domain: DomainModel) -> None:
        """A CA whose credential has no certificate yields no suite."""
        domain.issuing_ca.credential.certificate = None

        assert domain.signature_suite is None
        assert domain.public_key_info is None
        assert domain.signature_suite_display == '-'


class TestDomainCredentialProfile:
    """Resolution of the profile used for domain credentials."""

    def test_configured_profile_is_returned(
        self, domain: DomainModel, profile: CertificateProfileModel
    ) -> None:
        """An explicitly configured profile takes precedence."""
        domain.domain_credential_profile = profile
        domain.save()

        assert domain.get_domain_credential_profile() == profile
        assert domain.get_domain_credential_profile_name() == 'tls_server'

    def test_configured_profile_is_added_to_allowed_profiles(
        self, domain: DomainModel, profile: CertificateProfileModel
    ) -> None:
        """Saving links the domain credential profile into the allowed set."""
        domain.domain_credential_profile = profile
        domain.save()

        assert domain.certificate_profiles.filter(certificate_profile=profile).exists()

    def test_default_profile_is_used_as_fallback(
        self, domain: DomainModel, domain_credential_profile: CertificateProfileModel
    ) -> None:
        """Without configuration the conventional default profile is used."""
        assert domain.get_domain_credential_profile() == domain_credential_profile
        assert domain.get_domain_credential_profile_name() == 'domain_credential'

    def test_missing_default_profile_raises(self, domain: DomainModel) -> None:
        """A missing default profile is reported with an actionable error."""
        with pytest.raises(ValueError, match='domain_credential'):
            domain.get_domain_credential_profile()


class TestDomainAllowedProfiles:
    """Allowed certificate profile management."""

    def test_default_profiles_are_added_on_creation(self, issuing_ca_instance: dict[str, Any]) -> None:
        """Profiles marked as default are allowed for new domains."""
        default = CertificateProfileModel.objects.create(
            unique_name='default_profile', profile_json={'type': 'cert_profile'}, is_default=True
        )
        CertificateProfileModel.objects.create(
            unique_name='optional_profile', profile_json={'type': 'cert_profile'}, is_default=False
        )

        domain = DomainModel.objects.create(
            unique_name='defaults_domain', issuing_ca=issuing_ca_instance['issuing_ca']
        )

        assert [entry.certificate_profile for entry in domain.certificate_profiles.all()] == [default]

    def test_set_allowed_profiles_replaces_previous_selection(
        self, domain: DomainModel, profile: CertificateProfileModel
    ) -> None:
        """Setting allowed profiles replaces the existing configuration."""
        other = CertificateProfileModel.objects.create(
            unique_name='other_profile', profile_json={'type': 'cert_profile'}
        )
        domain.set_allowed_cert_profiles({str(profile.id): 'web'})
        assert domain.get_allowed_cert_profile_names() == {'tls_server', 'web'}

        domain.set_allowed_cert_profiles({str(other.id): ''})

        assert domain.get_allowed_cert_profile_names() == {'other_profile'}

    def test_duplicate_aliases_are_rejected_and_reported(self, domain: DomainModel) -> None:
        """A duplicated alias is dropped and reported back to the caller."""
        first = CertificateProfileModel.objects.create(
            unique_name='first_profile', profile_json={'type': 'cert_profile'}
        )
        second = CertificateProfileModel.objects.create(
            unique_name='second_profile', profile_json={'type': 'cert_profile'}
        )

        rejected = domain.set_allowed_cert_profiles({str(first.id): 'dup', str(second.id): 'dup'})

        assert rejected == {('dup', 'second_profile')}
        aliases = {entry.alias for entry in domain.certificate_profiles.all()}
        assert aliases == {'dup', ''}

    def test_domain_credential_profile_is_always_allowed(
        self, domain: DomainModel, profile: CertificateProfileModel
    ) -> None:
        """The domain credential profile cannot be removed from the allowed set."""
        domain.domain_credential_profile = profile
        domain.save()
        other = CertificateProfileModel.objects.create(
            unique_name='unrelated', profile_json={'type': 'cert_profile'}
        )

        domain.set_allowed_cert_profiles({str(other.id): ''})

        assert domain.certificate_profiles.filter(certificate_profile=profile).exists()

    def test_lookup_by_alias_and_unique_name(
        self, domain: DomainModel, profile: CertificateProfileModel
    ) -> None:
        """Profiles resolve by alias first and then by unique name."""
        domain.set_allowed_cert_profiles({str(profile.id): 'web'})

        assert domain.get_allowed_cert_profile('web') == profile
        assert domain.get_allowed_cert_profile('tls_server') == profile

    def test_lookup_of_disallowed_profile_raises(self, domain: DomainModel) -> None:
        """Requesting a profile that is not allowed raises a ValueError."""
        with pytest.raises(ValueError, match='does not exist or not allowed'):
            domain.get_allowed_cert_profile('missing_profile')

    def test_allowed_profiles_can_be_filtered_by_credential_type(
        self,
        domain: DomainModel,
        profile: CertificateProfileModel,
        domain_credential_profile: CertificateProfileModel,
    ) -> None:
        """Allowed profiles can be narrowed to a credential type."""
        domain.set_allowed_cert_profiles({str(profile.id): '', str(domain_credential_profile.id): ''})

        domain_scoped = domain.get_allowed_cert_profiles(
            CertificateProfileModel.ProfileCredentialType.DOMAIN
        )

        assert [entry.certificate_profile for entry in domain_scoped] == [domain_credential_profile]


class TestDomainAllowedCertificateProfileModel:
    """Display helpers for allowed profile entries."""

    def test_str_includes_alias_when_present(
        self, domain: DomainModel, profile: CertificateProfileModel
    ) -> None:
        """The string form mentions the alias only when one is configured."""
        with_alias = DomainAllowedCertificateProfileModel.objects.create(
            domain=domain, certificate_profile=profile, alias='web'
        )
        assert str(with_alias) == 'profile_domain - tls_server (alias: web)'

        with_alias.alias = ''
        assert str(with_alias) == 'profile_domain - tls_server'

    def test_duplicate_display_names_are_disambiguated(self, domain: DomainModel) -> None:
        """Shared display names are suffixed with the profile unique name."""
        first = CertificateProfileModel.objects.create(
            unique_name='profile_a', display_name='Shared', profile_json={'type': 'cert_profile'}
        )
        second = CertificateProfileModel.objects.create(
            unique_name='profile_b', display_name='Shared', profile_json={'type': 'cert_profile'}
        )
        entries = [
            DomainAllowedCertificateProfileModel.objects.create(domain=domain, certificate_profile=first),
            DomainAllowedCertificateProfileModel.objects.create(domain=domain, certificate_profile=second),
        ]

        titles = [title for _id, title, _name in
                  DomainAllowedCertificateProfileModel.get_list_of_display_names(entries)]

        assert titles == ['Shared - profile_a', 'Shared - profile_b']

    def test_unique_display_name_and_alias_are_preserved(self, domain: DomainModel) -> None:
        """A unique display name is used as-is and the alias becomes the name."""
        unique = CertificateProfileModel.objects.create(
            unique_name='profile_unique', display_name='Unique', profile_json={'type': 'cert_profile'}
        )
        entry = DomainAllowedCertificateProfileModel.objects.create(
            domain=domain, certificate_profile=unique, alias='alias-name'
        )

        result = DomainAllowedCertificateProfileModel.get_list_of_display_names([entry])

        assert result == [(unique.id, 'Unique', 'alias-name')]

    def test_profile_without_display_name_falls_back_to_name(self, domain: DomainModel) -> None:
        """Profiles lacking a display name fall back to their identifier."""
        plain = CertificateProfileModel.objects.create(
            unique_name='plain_profile', profile_json={'type': 'cert_profile'}
        )
        entry = DomainAllowedCertificateProfileModel.objects.create(
            domain=domain, certificate_profile=plain
        )

        result = DomainAllowedCertificateProfileModel.get_list_of_display_names([entry])

        assert result == [(plain.id, 'plain_profile', 'plain_profile')]
