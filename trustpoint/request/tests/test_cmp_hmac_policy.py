# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""CMP HMAC policy and security configuration regression tests."""

# ruff: noqa: S106, SLF001

import json
from http import HTTPStatus

import pytest
from django.contrib.messages.storage.fallback import FallbackStorage
from django.urls import reverse
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc4210
from trustpoint_core.oid import HmacAlgorithm

from management.forms import SecurityConfigForm
from management.models import SecurityConfig
from management.security_change_audit import snapshot_security_state
from management.security_env import (
    SecurityConfigurationError,
    effective_security_defaults,
    parse_security_restrictions,
    synchronize_security_config,
)
from management.tests.test_views.test_settings import authorized_request_factory
from management.views.settings import SecuritySettingsView, SettingsTabView
from request.authentication.cmp import CmpSharedSecretAuthentication
from request.clients.cmp_client import CmpClient
from request.message_builder.cmp import CmpPkiHeaderBuilding
from request.message_responder.cmp import CmpMessageResponder
from request.request_context import CmpBaseRequestContext
from request.security_hardening import validate_cmp_pbm_parameters

pytestmark = pytest.mark.django_db


def _context(algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA1) -> CmpBaseRequestContext:
    message = rfc4210.PKIMessage()
    header = message['header']
    header['pvno'] = 2
    header['sender']['rfc822Name'] = 'device@example.test'
    header['recipient']['rfc822Name'] = 'ca@example.test'
    message['header'] = CmpPkiHeaderBuilding._prepare_protection_algorithm_pbm(
        header, hmac_algorithm=algorithm,
    )
    message['body']['pkiconf'] = message['body']['pkiconf'].clone('')
    return CmpBaseRequestContext(
        parsed_message=message, cmp_shared_secret='test-secret', cmp_server_host='example.test',
    )


@pytest.mark.parametrize('algorithm', list(HmacAlgorithm))
def test_each_selectable_hmac_verifies_requests_and_responses(algorithm: HmacAlgorithm) -> None:
    """Every selectable algorithm must work with both sides of CMP protection."""
    SecurityConfig.objects.create(permitted_cmp_hmac_algorithms=[algorithm.dotted_string])
    context = _context(algorithm)
    validate_cmp_pbm_parameters(context)
    CmpClient(context)._add_protection_shared_secret(context.parsed_message)
    CmpSharedSecretAuthentication._verify_protection_shared_secret(context.parsed_message, 'test-secret')
    CmpMessageResponder._add_protection_shared_secret(context.parsed_message, context)
    CmpSharedSecretAuthentication._verify_protection_shared_secret(context.parsed_message, 'test-secret')


def test_settings_page_renders_and_saves_hmac_selection() -> None:
    """The settings page displays the allowlist and its form persists selected algorithms."""
    config = SecurityConfig.objects.create(pk=1, security_mode=SecurityConfig.SecurityModeChoices.LAB)
    factory = authorized_request_factory('manage_system_configuration', 'manage_security_configuration')
    response = SettingsTabView.as_view()(factory.get(reverse('management:settings')))
    response.render()
    assert response.status_code == HTTPStatus.OK
    assert b'name="permitted_cmp_hmac_algorithms"' in response.content
    assert b'HMAC-SHA3-256' in response.content

    for selected in ([HmacAlgorithm.HMAC_SHA384.dotted_string], []):
        request = factory.post(reverse('management:settings-security'), {
            'security_mode': config.security_mode,
            'rsa_minimum_key_size': '2048',
            'permitted_cmp_hmac_algorithms': selected,
        })
        request.session = {}
        request._messages = FallbackStorage(request)
        response = SecuritySettingsView.as_view()(request)
        assert response.status_code == HTTPStatus.FOUND
        config.refresh_from_db()
        assert config.permitted_cmp_hmac_algorithms == selected
        validate = _context(HmacAlgorithm.HMAC_SHA384)
        if selected:
            validate_cmp_pbm_parameters(validate)
        else:
            with pytest.raises(ValueError, match='not permitted'):
                validate_cmp_pbm_parameters(validate)


def test_hmac_environment_allowlist_and_validation() -> None:
    """The environment accepts supported names and prevents weaker preset overrides."""
    variable = 'TP_SECURITY_PERMITTED_CMP_HMAC_ALGORITHMS'
    restrictions = parse_security_restrictions({variable: 'HMAC_SHA384,HMAC_SHA512'})
    assert effective_security_defaults(SecurityConfig.SecurityModeChoices.HARDENED, restrictions)[
        'permitted_cmp_hmac_algorithms'
    ] == [HmacAlgorithm.HMAC_SHA384.dotted_string, HmacAlgorithm.HMAC_SHA512.dotted_string]
    assert effective_security_defaults(
        SecurityConfig.SecurityModeChoices.LAB,
        parse_security_restrictions({variable: 'HMAC_SHA3_256'}),
    )['permitted_cmp_hmac_algorithms'] == [HmacAlgorithm.HMAC_SHA3_256.dotted_string]
    assert effective_security_defaults(
        SecurityConfig.SecurityModeChoices.LAB, parse_security_restrictions({variable: ''}),
    )['permitted_cmp_hmac_algorithms'] == []
    with pytest.raises(SecurityConfigurationError, match='weaken'):
        effective_security_defaults(
            SecurityConfig.SecurityModeChoices.HARDENED,
            parse_security_restrictions({variable: 'HMAC_SHA1'}),
        )
    for invalid in ('HMAC_SHA999', 'HMAC_SHA256,HMAC_SHA256'):
        with pytest.raises(SecurityConfigurationError, match=variable):
            parse_security_restrictions({variable: invalid})


def test_sha1_requires_explicit_policy_and_changes_take_effect_immediately() -> None:
    """Changing persisted policy gates SHA-1 without weakening MAC verification."""
    config = SecurityConfig.objects.create()
    context = _context()
    with pytest.raises(ValueError, match='HMAC_SHA1 is not permitted'):
        validate_cmp_pbm_parameters(context)

    config.permitted_cmp_hmac_algorithms = [HmacAlgorithm.HMAC_SHA1.dotted_string]
    config.save(update_fields=['permitted_cmp_hmac_algorithms'])
    validate_cmp_pbm_parameters(context)
    CmpClient(context)._add_protection_shared_secret(context.parsed_message)
    CmpSharedSecretAuthentication._verify_protection_shared_secret(context.parsed_message, 'test-secret')
    with pytest.raises(ValueError, match='hmac verification failed'):
        CmpSharedSecretAuthentication._verify_protection_shared_secret(context.parsed_message, 'wrong-secret')
    CmpMessageResponder._add_protection_shared_secret(context.parsed_message, context)
    CmpSharedSecretAuthentication._verify_protection_shared_secret(context.parsed_message, 'test-secret')

    config.permitted_cmp_hmac_algorithms = []
    config.save(update_fields=['permitted_cmp_hmac_algorithms'])
    with pytest.raises(ValueError, match='HMAC_SHA1 is not permitted'):
        validate_cmp_pbm_parameters(context)


@pytest.mark.parametrize('algorithm', [
    HmacAlgorithm.HMAC_SHA256, HmacAlgorithm.HMAC_SHA384, HmacAlgorithm.HMAC_SHA512,
])
def test_modern_macs_remain_permitted_with_sha1_disabled(algorithm: HmacAlgorithm) -> None:
    """Disabling compatibility preserves support for modern MAC algorithms."""
    SecurityConfig.objects.create()
    validate_cmp_pbm_parameters(_context(algorithm))


def test_sha1_compatibility_fails_closed_without_an_unambiguous_policy() -> None:
    """Missing or duplicate configuration must never enable the compatibility exception."""
    with pytest.raises(SecurityConfig.DoesNotExist):
        validate_cmp_pbm_parameters(_context())
    SecurityConfig.objects.create(permitted_cmp_hmac_algorithms=[HmacAlgorithm.HMAC_SHA1.dotted_string])
    SecurityConfig.objects.create(permitted_cmp_hmac_algorithms=[HmacAlgorithm.HMAC_SHA1.dotted_string])
    with pytest.raises(SecurityConfig.MultipleObjectsReturned):
        validate_cmp_pbm_parameters(_context())


@pytest.mark.parametrize(('parameter', 'value', 'error'), [
    ('salt', b'x', 'salt length'),
    ('iterationCount', 100_001, 'iterationCount'),
    ('owf', '1.3.14.3.2.26', 'OWF'),
])
def test_sha1_compatibility_preserves_other_pbm_checks(parameter: str, value: bytes | int | str, error: str) -> None:
    """Compatibility must preserve the PBM work bounds and OWF policy."""
    SecurityConfig.objects.create(permitted_cmp_hmac_algorithms=[HmacAlgorithm.HMAC_SHA1.dotted_string])
    context = _context()
    parameters, _ = decoder.decode(
        context.parsed_message['header']['protectionAlg']['parameters'], asn1Spec=rfc4210.PBMParameter(),
    )
    if parameter == 'owf':
        parameters['owf']['algorithm'] = value
    else:
        parameters[parameter] = value
    context.parsed_message['header']['protectionAlg']['parameters'] = encoder.encode(parameters)
    with pytest.raises(ValueError, match=error):
        validate_cmp_pbm_parameters(context)


@pytest.mark.parametrize('mode', SecurityConfig.SecurityModeChoices)
def test_policy_presets_form_and_environment(mode: str) -> None:
    """Form and environment restrictions follow the selected security preset."""
    expected = mode in (SecurityConfig.SecurityModeChoices.LAB, SecurityConfig.SecurityModeChoices.BROWNFIELD)
    config = SecurityConfig.objects.create(security_mode=mode)
    config.apply_security_settings()
    config.refresh_from_db()
    assert (HmacAlgorithm.HMAC_SHA1.dotted_string in config.permitted_cmp_hmac_algorithms) is expected
    preview = json.loads(SecurityConfig.get_settings_preview_json())[mode]
    assert preview['permitted_cmp_hmac_algorithms'] == config.permitted_cmp_hmac_algorithms
    assert snapshot_security_state(config)['permitted_cmp_hmac_algorithms'] == config.permitted_cmp_hmac_algorithms

    form = SecurityConfigForm(data={
        'security_mode': mode,
        'rsa_minimum_key_size': config.rsa_minimum_key_size or '',
        'max_cert_validity_days': config.max_cert_validity_days or '',
        'max_crl_validity_days': config.max_crl_validity_days or '',
        'credential_ttl_seconds': config.credential_ttl_seconds or '',
        'permitted_cmp_hmac_algorithms': [HmacAlgorithm.HMAC_SHA1.dotted_string],
    }, instance=config)
    assert form.is_valid() is expected, form.errors
    assert ('permitted_cmp_hmac_algorithms' in form.errors) is (not expected)
    if expected:
        form.save()
        config.refresh_from_db()
        assert config.permitted_cmp_hmac_algorithms == [HmacAlgorithm.HMAC_SHA1.dotted_string]

    restrictions = parse_security_restrictions({'TP_SECURITY_ALLOW_CMP_HMAC_SHA1': 'false'})
    assert HmacAlgorithm.HMAC_SHA1.dotted_string not in effective_security_defaults(mode, restrictions)[
        'permitted_cmp_hmac_algorithms'
    ]
    restrictions = parse_security_restrictions({'TP_SECURITY_ALLOW_CMP_HMAC_SHA1': 'true'})
    if expected:
        assert HmacAlgorithm.HMAC_SHA1.dotted_string in effective_security_defaults(mode, restrictions)[
            'permitted_cmp_hmac_algorithms'
        ]
    else:
        with pytest.raises(SecurityConfigurationError, match='allow_cmp_hmac_sha1'):
            effective_security_defaults(mode, restrictions)


def test_environment_synchronization_persists_sha1_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Startup policy synchronization persists the environment restriction."""
    monkeypatch.setenv('TP_SECURITY_MODE', 'BROWNFIELD')
    monkeypatch.setenv('TP_SECURITY_ALLOW_CMP_HMAC_SHA1', 'false')
    assert synchronize_security_config()
    assert HmacAlgorithm.HMAC_SHA1.dotted_string not in SecurityConfig.objects.get(pk=1).permitted_cmp_hmac_algorithms
    monkeypatch.setenv('TP_SECURITY_ALLOW_CMP_HMAC_SHA1', 'true')
    assert synchronize_security_config()
    assert HmacAlgorithm.HMAC_SHA1.dotted_string in SecurityConfig.objects.get(pk=1).permitted_cmp_hmac_algorithms
