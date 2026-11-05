# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""PKI, CA, RA, domain and truststore Behave steps."""

from __future__ import annotations

from pathlib import Path

from behave import given, runner, then, when

from management.models.security import SecurityConfig
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import CaModel, CertificateProfileModel, DomainModel


def _create_remote_ra(context: runner.Context, *, name: str, protocol: str) -> CaModel:
    """Create a model-valid remote RA fixture for EST or CMP."""
    from features.support.pki_fixtures import create_local_ca

    upstream_ca = create_local_ca(f'{name}-upstream')
    certificate = upstream_ca.credential.certificate
    assert certificate is not None

    config = NoOnboardingConfigModel()
    if protocol == 'EST':
        config.set_pki_protocols([NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD])
        config.est_password = 'behave-est-password'
        ca_type = CaModel.CaTypeChoice.REMOTE_EST_RA
        remote_path = '/.well-known/est/behave/tls_server/simpleenroll'
    else:
        config.set_pki_protocols([NoOnboardingPkiProtocol.CMP_SHARED_SECRET])
        config.cmp_shared_secret = 'behave-cmp-shared-secret'
        ca_type = CaModel.CaTypeChoice.REMOTE_CMP_RA
        remote_path = '/.well-known/cmp/p/behave/certification'

    config.full_clean()
    config.save()

    ra = CaModel(
        unique_name=name,
        ca_type=ca_type,
        remote_host='localhost',
        remote_port=443,
        remote_path=remote_path,
        certificate=certificate,
        no_onboarding_config=config,
    )
    ra.full_clean()
    ra.save()
    context.upstream_ca = upstream_ca
    return ra


@given('a local issuing CA named "{name}" exists')
def step_local_ca(context: runner.Context, name: str) -> None:
    from features.support.pki_fixtures import create_local_ca
    context.issuing_ca = create_local_ca(name)


@given('a remote EST RA named "{name}" exists')
def step_est_ra(context: runner.Context, name: str) -> None:
    context.issuing_ca = _create_remote_ra(context, name=name, protocol='EST')


@given('a remote CMP RA named "{name}" exists')
def step_cmp_ra(context: runner.Context, name: str) -> None:
    context.issuing_ca = _create_remote_ra(context, name=name, protocol='CMP')


@then('the CA mode is "{mode}"')
def step_ca_mode(context: runner.Context, mode: str) -> None:
    expected = getattr(CaModel.CaTypeChoice, mode)
    context.issuing_ca.refresh_from_db()
    assert context.issuing_ca.ca_type == expected


@given('that authority is assigned to domain "{domain_name}"')
@when('that authority is assigned to domain "{domain_name}"')
def step_assign_domain(context: runner.Context, domain_name: str) -> None:
    context.domain = DomainModel.objects.create(
        unique_name=domain_name,
        issuing_ca=context.issuing_ca,
    )


@then('domain "{domain_name}" uses that authority')
def step_domain_uses_authority(context: runner.Context, domain_name: str) -> None:
    domain = DomainModel.objects.get(unique_name=domain_name)
    assert domain.issuing_ca_id == context.issuing_ca.pk


@when('the admin opens the issuing CA list')
def step_ca_list(context: runner.Context) -> None:
    context.response = context.authenticated_client.get('/pki/issuing-cas/')


@when('the admin opens the Add Issuing CA method selection')
def step_open_add_ca_methods(context: runner.Context) -> None:
    """Open the issuing-CA workflow selection page."""
    context.response = context.authenticated_client.get('/pki/issuing-cas/add/method-select/')


@then('the issuing CA list contains "{name}"')
def step_ca_list_contains(context: runner.Context, name: str) -> None:
    assert name in context.response.content.decode('utf-8')


@when('the admin creates domain "{domain_name}" using authority "{ca_name}"')
def step_create_domain_via_ui(context: runner.Context, domain_name: str, ca_name: str) -> None:
    ca = CaModel.objects.get(unique_name=ca_name)
    context.response = context.authenticated_client.post(
        '/pki/domains/add/',
        {
            'unique_name': domain_name,
            'issuing_ca': ca.pk,
        },
        follow=True,
    )


@then('only one domain named "{domain_name}" exists')
def step_only_one_domain(context: runner.Context, domain_name: str) -> None:
    """Assert duplicate form submission did not create another domain."""
    assert DomainModel.objects.filter(unique_name=domain_name).count() == 1


@then('domain "{domain_name}" exists')
def step_domain_created(context: runner.Context, domain_name: str) -> None:
    context.domain = DomainModel.objects.get(unique_name=domain_name)


@given('certificate profile "{profile_name}" exists')
def step_certificate_profile(context: runner.Context, profile_name: str) -> None:
    """Create a domain credential profile for the Domain configuration workflow."""
    context.certificate_profile = CertificateProfileModel.objects.create(
        unique_name=profile_name,
        display_name=profile_name,
        credential_type=CertificateProfileModel.ProfileCredentialType.DOMAIN,
        profile_json='{}',
    )


@when(
    'the admin allows profile "{profile_name}" with alias "{alias}" in domain "{domain_name}"'
)
def step_allow_profile_in_domain(
    context: runner.Context,
    profile_name: str,
    alias: str,
    domain_name: str,
) -> None:
    """Submit the Domain configuration form with one allowed profile and alias."""
    domain = DomainModel.objects.get(unique_name=domain_name)
    profile = CertificateProfileModel.objects.get(unique_name=profile_name)
    context.response = context.authenticated_client.post(
        f'/pki/domains/config/{domain.pk}/',
        {
            f'cert_p_allowed_{profile.pk}': 'on',
            f'cert_p_alias_{profile.pk}': alias,
        },
        follow=True,
    )


@then('domain "{domain_name}" allows profile "{profile_name}" with alias "{alias}"')
def step_domain_allows_profile(context: runner.Context, domain_name: str, profile_name: str, alias: str) -> None:
    """Assert the allowed profile and its Domain-specific alias were persisted."""
    domain = DomainModel.objects.get(unique_name=domain_name)
    profile = CertificateProfileModel.objects.get(unique_name=profile_name)
    assert domain.certificate_profiles.filter(certificate_profile=profile, alias=alias).exists()


@when('the admin deletes domain "{domain_name}"')
def step_delete_domain(context: runner.Context, domain_name: str) -> None:
    domain = DomainModel.objects.get(unique_name=domain_name)
    context.response = context.authenticated_client.post(
        f'/pki/domains/delete/{domain.pk}/',
        data={'selected_items': [domain.pk]},
        follow=True,
    )


@then('domain "{domain_name}" no longer exists')
def step_domain_deleted(context: runner.Context, domain_name: str) -> None:
    assert not DomainModel.objects.filter(unique_name=domain_name).exists()


@given('a truststore file named "{filename}" from the test data')
def step_truststore_file(context: runner.Context, filename: str) -> None:
    context.truststore_file = Path(__file__).resolve().parents[3] / 'tests' / 'data' / 'trust-store' / filename
    assert context.truststore_file.is_file(), f'Missing test data: {context.truststore_file}'


@when('the admin creates truststore "{name}" for intended usage "{usage}"')
def step_create_truststore(context: runner.Context, name: str, usage: str) -> None:
    from pki.models import TruststoreModel
    intended_usage = getattr(TruststoreModel.IntendedUsage, usage)
    with context.truststore_file.open('rb') as handle:
        context.response = context.authenticated_client.post(
            '/pki/truststores/add/',
            {'unique_name': name, 'intended_usage': intended_usage.value, 'trust_store_file': handle},
            follow=True,
        )


@then('truststore "{name}" exists')
def step_truststore_exists(context: runner.Context, name: str) -> None:
    from pki.models import TruststoreModel
    context.truststore = TruststoreModel.objects.get(unique_name=name)


@when('the admin deletes truststore "{name}"')
def step_delete_truststore(context: runner.Context, name: str) -> None:
    from pki.models import TruststoreModel
    truststore = TruststoreModel.objects.get(unique_name=name)
    context.response = context.authenticated_client.post(
        f'/pki/truststores/delete/{truststore.pk}/',
        data={'selected_items': [truststore.pk]},
        follow=True,
    )


@then('truststore "{name}" no longer exists')
def step_truststore_deleted(context: runner.Context, name: str) -> None:
    from pki.models import TruststoreModel
    assert not TruststoreModel.objects.filter(unique_name=name).exists()


@when('the admin opens the certificate profile list')
def step_profile_list(context: runner.Context) -> None:
    context.response = context.authenticated_client.get('/pki/cert-profiles/')


@when('the admin imports PKCS12 issuing CA "{ca_name}" from the test data')
def step_import_pkcs12_ca(context: runner.Context, ca_name: str) -> None:
    """Import a PKCS#12 CA with permissive test policy configured explicitly."""
    security, _ = SecurityConfig.objects.get_or_create(pk=1)
    security.security_mode = SecurityConfig.SecurityModeChoices.LAB
    security.apply_security_settings(save=False)
    security.allow_imported_private_keys = True
    security.save()

    path = Path(__file__).resolve().parents[3] / 'tests' / 'data' / 'issuing_cas' / 'issuing_ca.p12'
    assert path.is_file(), f'Missing test data: {path}'
    with path.open('rb') as handle:
        context.response = context.authenticated_client.post(
            '/pki/issuing-cas/add/file-import/pkcs12',
            {
                'unique_name': ca_name,
                'pkcs12_password': 'testing321',
                'pkcs12_file': handle,
            },
            follow=True,
        )

    if not CaModel.objects.filter(unique_name=ca_name).exists():
        body = context.response.content.decode('utf-8', errors='replace')
        raise AssertionError(
            f'PKCS#12 CA import did not create {ca_name!r}. '
            f'HTTP {context.response.status_code}. Response excerpt: {body[:1200]}'
        )
    context.issuing_ca = CaModel.objects.get(unique_name=ca_name)


@then('issuing CA "{ca_name}" exists')
def step_issuing_ca_exists(context: runner.Context, ca_name: str) -> None:
    assert CaModel.objects.filter(unique_name=ca_name).exists()
