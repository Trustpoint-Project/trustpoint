# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Behave steps for security configuration scenarios."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from behave import given, runner, then, when
from django.contrib.auth.models import Group, Permission
from django.test import Client

from management.models import SecurityConfig
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol
from pki.models import CertificateProfileModel
from users.models import TrustpointUser


SECURITY_SETTINGS_URL = "/management/settings/security/"
CAPABILITIES_API_URL = "/api/capabilities/"


@then('the service account has REST API permission')
def step_service_permission(context: runner.Context) -> None:
    """Verify the service account can use the REST API."""
    assert context.service_account.has_perm('users.use_rest_api')


@given('a non-privileged human user named "{username}" exists')
def step_non_privileged_user(context: runner.Context, username: str) -> None:
    """Create a human user with an isolated empty role and a protected profile."""
    role = Group.objects.create(name=f'{username}-unprivileged-role')
    context.low_privilege_user = TrustpointUser.objects.create_user(username=username, role=role)
    context.protected_profile = CertificateProfileModel.objects.create(
        unique_name=f'{username}-protected-profile',
        display_name='Behave protected profile',
        credential_type=CertificateProfileModel.ProfileCredentialType.APPLICATION,
        profile_json={
            'type': 'cert_profile',
            'credential_type': 'application',
            'subj': {},
            'ext': {},
        },
    )


@when('that user attempts to manage a certificate profile')
def step_manage_profile(context: runner.Context) -> None:
    """Attempt profile deletion through the real protected web endpoint."""
    client = Client()
    client.force_login(context.low_privilege_user)
    context.response = client.post(
        f'/pki/cert-profiles/delete/{context.protected_profile.pk}/',
        data={},
        follow=False,
    )


@then('access to the protected page is denied')
def step_access_denied(context: runner.Context) -> None:
    """Verify access was denied and the attempted mutation did not persist."""
    assert context.response.status_code == HTTPStatus.FORBIDDEN
    assert CertificateProfileModel.objects.filter(pk=context.protected_profile.pk).exists()


def _security_config() -> SecurityConfig:
    """Return the singleton security configuration, creating its defaults if required."""
    config, created = SecurityConfig.objects.get_or_create(pk=1)
    if created:
        config.security_mode = SecurityConfig.SecurityModeChoices.BROWNFIELD
        config.apply_security_settings()
    return config


def _mode_from_name(mode_name: str) -> str:
    """Map a Gherkin security-mode name to the model value."""
    normalized = mode_name.strip().upper()
    mapping = {
        "LAB": SecurityConfig.SecurityModeChoices.LAB,
        "BROWNFIELD": SecurityConfig.SecurityModeChoices.BROWNFIELD,
        "INDUSTRIAL": SecurityConfig.SecurityModeChoices.INDUSTRIAL,
        "HARDENED": SecurityConfig.SecurityModeChoices.HARDENED,
        "CRITICAL": SecurityConfig.SecurityModeChoices.CRITICAL,
    }
    try:
        return str(mapping[normalized])
    except KeyError as exc:
        raise AssertionError(f"Unknown security mode: {mode_name}") from exc


def _no_onboarding_protocol(protocol_name: str) -> NoOnboardingPkiProtocol:
    """Resolve a no-onboarding protocol from its enum name."""
    try:
        return NoOnboardingPkiProtocol[protocol_name.strip().upper()]
    except KeyError as exc:
        raise AssertionError(f"Unknown no-onboarding PKI protocol: {protocol_name}") from exc


def _onboarding_protocol(protocol_name: str) -> OnboardingProtocol:
    """Resolve an onboarding protocol from its enum name."""
    try:
        return OnboardingProtocol[protocol_name.strip().upper()]
    except KeyError as exc:
        raise AssertionError(f"Unknown onboarding protocol: {protocol_name}") from exc


def _post_compatible_preset(mode: str, config: SecurityConfig | None = None) -> dict[str, Any]:
    """Build form data matching the selected security preset.

    The security form cannot submit the LAB model value ``rsa_minimum_key_size=0``
    because its select widget starts at 1024. For LAB mode we therefore use
    1024 for the form submission while preserving the rest of the LAB policy.

    For stricter modes Trustpoint's SecuritySettingsView additionally invokes
    SecurityManager.reset_settings(), which applies the authoritative preset.
    """
    config = config or _security_config()
    defaults = SecurityConfig._MODE_DEFAULTS[mode]  # noqa: SLF001

    rsa_minimum = defaults["rsa_minimum_key_size"]
    if rsa_minimum == 0:
        rsa_minimum = 1024

    data: dict[str, Any] = {
        "security_mode": mode,
        "rsa_minimum_key_size": "" if rsa_minimum is None else str(rsa_minimum),
        "max_cert_validity_days": (
            "" if defaults["max_cert_validity_days"] is None else str(defaults["max_cert_validity_days"])
        ),
        "max_crl_validity_days": (
            "" if defaults["max_crl_validity_days"] is None else str(defaults["max_crl_validity_days"])
        ),
        "credential_ttl_seconds": (
            "" if defaults["credential_ttl_seconds"] is None else str(defaults["credential_ttl_seconds"])
        ),
        "permitted_no_onboarding_pki_protocols": [
            str(value) for value in defaults["permitted_no_onboarding_pki_protocols"]
        ],
        "permitted_onboarding_protocols": [
            str(value) for value in defaults["permitted_onboarding_protocols"]
        ],
    }

    if defaults["allow_ca_issuance"]:
        data["allow_ca_issuance"] = "on"
    if defaults["allow_self_signed_ca"]:
        data["allow_self_signed_ca"] = "on"
    if defaults["allow_imported_private_keys"]:
        data["allow_imported_private_keys"] = "on"

    # ``auto_gen_pki`` means "currently enabled", not "permitted".
    # Keep the feature disabled in Behave tests to avoid creating/deleting a PKI
    # while still testing ``allow_auto_gen_pki`` through the selected preset.
    if config.auto_gen_pki:
        data["auto_gen_pki"] = "on"

    return data


def _extract_security_form(response: Any) -> Any | None:
    """Return the bound security form from a Django test response.

    ``SecuritySettingsView.form_invalid()`` explicitly places the rejected,
    bound form in ``response.context_data['security_form']``. Prefer that
    authoritative context before walking template contexts, which may contain
    an unbound form rendered by nested templates.
    """
    context_data = getattr(response, "context_data", None)
    if context_data:
        for key in ("security_form", "form"):
            try:
                form = context_data[key]
            except (KeyError, TypeError):
                continue
            if form is not None:
                return form

    response_context = getattr(response, "context", None)
    if response_context:
        if isinstance(response_context, (list, tuple)):
            contexts = response_context
        else:
            contexts = [response_context]

        for item in contexts:
            for key in ("security_form", "form"):
                try:
                    form = item[key]
                except (KeyError, TypeError):
                    continue
                if form is not None and getattr(form, "is_bound", False):
                    return form

        for item in contexts:
            for key in ("security_form", "form"):
                try:
                    form = item[key]
                except (KeyError, TypeError):
                    continue
                if form is not None:
                    return form

    return None


def _submit_security_form(context: runner.Context, data: dict[str, Any]) -> None:
    """Submit the security configuration through the real Django view."""
    context.response = context.authenticated_client.post(
        SECURITY_SETTINGS_URL,
        data=data,
        follow=False,
    )
    context.security_form = _extract_security_form(context.response)


def _table_protocol_names(context: runner.Context) -> list[str]:
    """Return protocol values from a one-column Behave table."""
    assert context.table is not None, "This step requires a Gherkin table."
    assert "protocol" in context.table.headings, 'The table must contain a "protocol" column.'
    return [row["protocol"].strip() for row in context.table]


@given("a security configuration exists")
def step_security_configuration_exists(context: runner.Context) -> None:  # noqa: ARG001
    """Create the singleton security configuration with Brownfield defaults."""
    config, _created = SecurityConfig.objects.get_or_create(
        pk=1,
        defaults={"security_mode": SecurityConfig.SecurityModeChoices.BROWNFIELD},
    )
    config.security_mode = SecurityConfig.SecurityModeChoices.BROWNFIELD
    config.apply_security_settings()
    config.auto_gen_pki = False
    config.save(update_fields=["auto_gen_pki"])


@when("the admin opens the security configuration")
def step_admin_opens_security_configuration(context: runner.Context) -> None:
    """Open the real security settings endpoint."""
    context.response = context.authenticated_client.get(SECURITY_SETTINGS_URL)

    context.security_form = _extract_security_form(context.response)


@then("the security configuration form is displayed")
def step_security_configuration_form_displayed(context: runner.Context) -> None:
    """Verify that the security form was rendered."""
    form = getattr(context, "security_form", None)
    if form is None:
        form = _extract_security_form(context.response)

    assert form is not None, "Security configuration form was not present in the response."
    assert "security_mode" in form.fields


@when('the admin selects security mode "{mode_name}"')
def step_admin_selects_security_mode(context: runner.Context, mode_name: str) -> None:
    """Change the security mode via the real security settings form."""
    mode = _mode_from_name(mode_name)
    config = _security_config()
    _submit_security_form(context, _post_compatible_preset(mode, config))


@then('the security mode is "{mode_name}"')
def step_security_mode_is(context: runner.Context, mode_name: str) -> None:  # noqa: ARG001
    """Assert the persisted security mode."""
    config = _security_config()
    assert config.security_mode == _mode_from_name(mode_name)


@then('the minimum RSA key size is "{expected}"')
def step_minimum_rsa_key_size(context: runner.Context, expected: str) -> None:  # noqa: ARG001
    """Assert the configured RSA minimum key size."""
    config = _security_config()
    expected_value = None if expected.strip().upper() == "NONE" else int(expected)
    assert config.rsa_minimum_key_size == expected_value, (
        f"Expected RSA minimum key size {expected_value}, got {config.rsa_minimum_key_size}."
    )


@then("RSA is not permitted")
def step_rsa_not_permitted(context: runner.Context) -> None:  # noqa: ARG001
    """Assert that RSA is disabled by policy."""
    assert _security_config().rsa_minimum_key_size is None


@then('the maximum certificate validity is "{days:d}" days')
def step_max_certificate_validity(context: runner.Context, days: int) -> None:  # noqa: ARG001
    """Assert maximum certificate validity."""
    assert _security_config().max_cert_validity_days == days


@then('the maximum CRL validity is "{days:d}" days')
def step_max_crl_validity(context: runner.Context, days: int) -> None:  # noqa: ARG001
    """Assert maximum CRL validity."""
    assert _security_config().max_crl_validity_days == days


@then("no maximum certificate validity is configured")
def step_no_max_certificate_validity(context: runner.Context) -> None:  # noqa: ARG001
    """Assert that certificate validity is unlimited."""
    assert _security_config().max_cert_validity_days is None


@then("no maximum CRL validity is configured")
def step_no_max_crl_validity(context: runner.Context) -> None:  # noqa: ARG001
    """Assert that CRL validity is unlimited."""
    assert _security_config().max_crl_validity_days is None


@then("imported private keys are permitted")
def step_imported_private_keys_permitted(context: runner.Context) -> None:  # noqa: ARG001
    """Assert imported private keys are allowed."""
    assert _security_config().allow_imported_private_keys is True


@then("imported private keys are not permitted")
def step_imported_private_keys_not_permitted(context: runner.Context) -> None:  # noqa: ARG001
    """Assert imported private keys are forbidden."""
    assert _security_config().allow_imported_private_keys is False


@then("self-signed certificate authorities are permitted")
def step_self_signed_ca_permitted(context: runner.Context) -> None:  # noqa: ARG001
    """Assert self-signed CAs are allowed."""
    assert _security_config().allow_self_signed_ca is True


@then("self-signed certificate authorities are not permitted")
def step_self_signed_ca_not_permitted(context: runner.Context) -> None:  # noqa: ARG001
    """Assert self-signed CAs are forbidden."""
    assert _security_config().allow_self_signed_ca is False


@then("automatic PKI creation is permitted")
def step_auto_gen_pki_permitted(context: runner.Context) -> None:  # noqa: ARG001
    """Assert that policy permits creation of an auto-generated PKI."""
    assert _security_config().allow_auto_gen_pki is True


@then("automatic PKI creation is not permitted")
def step_auto_gen_pki_not_permitted(context: runner.Context) -> None:  # noqa: ARG001
    """Assert that policy forbids creation of an auto-generated PKI."""
    assert _security_config().allow_auto_gen_pki is False


@then('hash algorithm "{algorithm_name}" is not permitted')
def step_hash_algorithm_not_permitted(context: runner.Context, algorithm_name: str) -> None:  # noqa: ARG001
    """Assert that the selected hash/signature algorithm is blocked."""
    normalized = algorithm_name.strip().upper().replace("-", "")
    mapping = {
        "MD5": SecurityConfig.HashAlgorithmChoices.MD5.value,
        "SHA1": SecurityConfig.HashAlgorithmChoices.SHA1.value,
        "SHA224": SecurityConfig.HashAlgorithmChoices.SHA224.value,
        "SHA256": SecurityConfig.HashAlgorithmChoices.SHA256.value,
        "SHA384": SecurityConfig.HashAlgorithmChoices.SHA384.value,
        "SHA512": SecurityConfig.HashAlgorithmChoices.SHA512.value,
    }
    try:
        oid = mapping[normalized]
    except KeyError as exc:
        raise AssertionError(f"Unknown hash algorithm: {algorithm_name}") from exc

    assert oid in _security_config().not_permitted_signature_algorithm_oids, (
        f"{algorithm_name} ({oid}) is not blocked by the current security configuration."
    )


@then("the onboarding credential TTL is {seconds:d} seconds")
def step_onboarding_credential_ttl(context: runner.Context, seconds: int) -> None:  # noqa: ARG001
    """Assert the onboarding credential lifetime."""
    assert _security_config().credential_ttl_seconds == seconds


@given('security mode "{mode_name}" is active')
def step_security_mode_active(context: runner.Context, mode_name: str) -> None:  # noqa: ARG001
    """Set up a security mode as fixture state.

    ORM setup is intentional for a Given-step; actions under test still go through
    the public security-settings endpoint.
    """
    config = _security_config()
    config.security_mode = _mode_from_name(mode_name)
    config.save(update_fields=["security_mode"])
    config.apply_security_settings()
    config.auto_gen_pki = False
    config.save(update_fields=["auto_gen_pki"])


@when("the admin sets the onboarding credential TTL to {seconds:d} seconds")
def step_admin_sets_credential_ttl(context: runner.Context, seconds: int) -> None:
    """Submit a custom credential TTL through the real security form."""
    config = _security_config()
    data = _post_compatible_preset(config.security_mode, config)
    data["credential_ttl_seconds"] = str(seconds)
    _submit_security_form(context, data)


@then("the security configuration is rejected")
def step_security_configuration_rejected(context: runner.Context) -> None:
    """Assert that a security form submission was rejected."""
    form = getattr(context, "security_form", None)
    assert form is not None, (
        'No bound security form was found after the rejected submission. '
        f'Response status: {context.response.status_code}.'
    )
    assert form.errors, (
        "Expected security configuration errors, but none were found. "
        f"bound={form.is_bound}, mode={form.data.get('security_mode')}, "
        f"credential_ttl_seconds={form.data.get('credential_ttl_seconds')}, "
        f"response_status={context.response.status_code}, "
        f"response_url={getattr(context.response, 'url', None)!r}."
    )


@then('the security configuration contains an error for "{field_name}"')
def step_security_configuration_error_for(context: runner.Context, field_name: str) -> None:
    """Assert a field-specific validation error."""
    form = getattr(context, "security_form", None)
    assert form is not None, "No bound security form is available."
    assert field_name in form.errors, (
        f'Expected an error for "{field_name}", got errors for: {list(form.errors.keys())}.'
    )


@when("the admin permits the following no-onboarding PKI protocols:")
def step_admin_permits_no_onboarding_protocols(context: runner.Context) -> None:
    """Save the selected no-onboarding protocol allow-list."""
    config = _security_config()
    names = _table_protocol_names(context)
    selected = [_no_onboarding_protocol(name).value for name in names]

    data = _post_compatible_preset(config.security_mode, config)
    data["permitted_no_onboarding_pki_protocols"] = [str(value) for value in selected]
    data["permitted_onboarding_protocols"] = [
        str(value) for value in config.permitted_onboarding_protocols
    ]
    _submit_security_form(context, data)


@when("the admin permits the following onboarding protocols:")
def step_admin_permits_onboarding_protocols(context: runner.Context) -> None:
    """Save the selected onboarding protocol allow-list."""
    config = _security_config()
    names = _table_protocol_names(context)
    selected = [_onboarding_protocol(name).value for name in names]

    data = _post_compatible_preset(config.security_mode, config)
    data["permitted_no_onboarding_pki_protocols"] = [
        str(value) for value in config.permitted_no_onboarding_pki_protocols
    ]
    data["permitted_onboarding_protocols"] = [str(value) for value in selected]
    _submit_security_form(context, data)


@then("the permitted no-onboarding PKI protocols are:")
def step_permitted_no_onboarding_protocols_are(context: runner.Context) -> None:
    """Assert the exact persisted no-onboarding protocol allow-list."""
    expected = {_no_onboarding_protocol(name).value for name in _table_protocol_names(context)}
    actual = set(_security_config().permitted_no_onboarding_pki_protocols)
    assert actual == expected, f"Expected no-onboarding protocols {expected}, got {actual}."


@then("the permitted onboarding protocols are:")
def step_permitted_onboarding_protocols_are(context: runner.Context) -> None:
    """Assert the exact persisted onboarding protocol allow-list."""
    expected = {_onboarding_protocol(name).value for name in _table_protocol_names(context)}
    actual = set(_security_config().permitted_onboarding_protocols)
    assert actual == expected, f"Expected onboarding protocols {expected}, got {actual}."


@given('only no-onboarding PKI protocol "{protocol_name}" is permitted')
def step_only_no_onboarding_protocol_permitted(
    context: runner.Context,
    protocol_name: str,
) -> None:  # noqa: ARG001
    """Set the no-onboarding protocol policy for a capability test."""
    config = _security_config()
    config.permitted_no_onboarding_pki_protocols = [_no_onboarding_protocol(protocol_name).value]
    config.save(update_fields=["permitted_no_onboarding_pki_protocols"])


@given('only onboarding protocol "{protocol_name}" is permitted')
def step_only_onboarding_protocol_permitted(
    context: runner.Context,
    protocol_name: str,
) -> None:  # noqa: ARG001
    """Set the onboarding protocol policy for a capability test."""
    config = _security_config()
    config.permitted_onboarding_protocols = [_onboarding_protocol(protocol_name).value]
    config.save(update_fields=["permitted_onboarding_protocols"])


@when("the capabilities API is requested")
def step_capabilities_api_requested(context: runner.Context) -> None:
    """Request the public capabilities endpoint."""
    context.response = context.authenticated_client.get(CAPABILITIES_API_URL)
    context.capabilities = context.response.json()


@then('no-onboarding capability "{capability}" is enabled')
def step_no_onboarding_capability_enabled(context: runner.Context, capability: str) -> None:
    """Assert an enabled no-onboarding capability."""
    value = context.capabilities["protocols"]["no_onboarding"][capability]
    assert value is True, f'Expected no-onboarding capability "{capability}" to be enabled.'


@then('no-onboarding capability "{capability}" is disabled')
def step_no_onboarding_capability_disabled(context: runner.Context, capability: str) -> None:
    """Assert a disabled no-onboarding capability."""
    value = context.capabilities["protocols"]["no_onboarding"][capability]
    assert value is False, f'Expected no-onboarding capability "{capability}" to be disabled.'


@then('onboarding capability "{capability}" is enabled')
def step_onboarding_capability_enabled(context: runner.Context, capability: str) -> None:
    """Assert an enabled onboarding capability."""
    value = context.capabilities["protocols"]["onboarding"][capability]
    assert value is True, f'Expected onboarding capability "{capability}" to be enabled.'


@then('onboarding capability "{capability}" is disabled')
def step_onboarding_capability_disabled(context: runner.Context, capability: str) -> None:
    """Assert a disabled onboarding capability."""
    value = context.capabilities["protocols"]["onboarding"][capability]
    assert value is False, f'Expected onboarding capability "{capability}" to be disabled.'


@then('onboarding protocol "{protocol_name}" is not offered')
def step_onboarding_protocol_not_offered(context: runner.Context, protocol_name: str) -> None:
    """Assert that an unsupported onboarding protocol is absent from the form."""
    form = getattr(context, "security_form", None)
    assert form is not None, "Security form is not available."

    offered_values = {
        str(value)
        for value, _label in form.fields["permitted_onboarding_protocols"].choices
    }
    protocol = _onboarding_protocol(protocol_name)

    assert str(protocol.value) not in offered_values, (
        f'{protocol_name} ({protocol.value}) is unexpectedly offered by the security form.'
    )


@given('a user without the "{permission_codename}" permission is logged in')
def step_user_without_permission_logged_in(
    context: runner.Context,
    permission_codename: str,
) -> None:
    """Authenticate a normal user whose role lacks the requested permission."""
    permission = Permission.objects.get(
        content_type__app_label="users",
        content_type__model="apppermission",
        codename=permission_codename,
    )

    user = TrustpointUser.objects.create_user(
        username="behave-security-user",
        password="testing321",  # noqa: S106
    )
    user.role.permissions.remove(permission)

    client = Client()
    login_success = client.login(
        username="behave-security-user",
        password="testing321",  # noqa: S106
    )
    assert login_success, "Could not log in the non-privileged Behave user."

    context.authenticated_client = client
    context.non_privileged_user = user


@when('the user attempts to change the security mode to "{mode_name}"')
def step_user_attempts_security_mode_change(context: runner.Context, mode_name: str) -> None:
    """Attempt a protected security-settings mutation."""
    config = _security_config()
    context.security_mode_before_unauthorized_change = config.security_mode

    data = _post_compatible_preset(_mode_from_name(mode_name), config)
    context.response = context.authenticated_client.post(
        SECURITY_SETTINGS_URL,
        data=data,
        follow=False,
    )


@then("the security mode was not changed")
def step_security_mode_not_changed(context: runner.Context) -> None:
    """Assert that an unauthorized change did not persist."""
    config = _security_config()
    assert config.security_mode == context.security_mode_before_unauthorized_change
