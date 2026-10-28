# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the profile-driven certificate parameters of the no-onboarding help pages."""

import json
import re
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from help_pages.cert_parameters import CertParameterTemplate, ShellQuoting
from help_pages.commands import (
    CmpSharedSecretCommandBuilder,
    EstUsernamePasswordCommandBuilder,
    RestUsernamePasswordCommandBuilder,
)
from help_pages.devices_help_views import (
    NoOnboardingCmpSharedSecretStrategy,
    NoOnboardingEstUsernamePasswordStrategy,
    NoOnboardingRestUsernamePasswordStrategy,
)
from help_pages.help_section import HelpSection
from help_pages.tests.test_devices_help_views import _device, _domain, _help_context, _profile
from pki.util.cert_profile import JSONProfileVerifier

CN_REQUIRED = {'type': 'cert_profile', 'subj': {'common_name': {'required': True}}, 'validity': {'days': 10}}
URI_REQUIRED = {
    'type': 'cert_profile',
    'ext': {'subject_alternative_name': {'uris': {'required': True}}},
    'validity': {'days': 10},
}
DEV_OWNER_ID = {
    'type': 'cert_profile',
    'display_name': 'DevOwnerID',
    'subj': {'allow': '*', 'common_name': {'required': True}},
    'reject_mods': False,
    'ext': {
        'basic_constraints': {'ca': True, 'critical': True},
        'subject_alternative_name': {'uris': {'required': True}, 'critical': True},
    },
    'validity': {'days': 3650},
}
OPTIONAL = {
    'type': 'cert_profile',
    'subj': {
        'common_name': {'required': True},
        'organization_name': {'default': 'Acme', 'mutable': True},
    },
    'ext': {'subject_alternative_name': {'dns_names': {'required': False}}},
    'validity': {'days': 10},
}
FIXED = {'type': 'cert_profile', 'subj': {'common_name': 'fixed-cn'}, 'validity': {'days': 10}}

BUILDERS: dict[str, Callable[[dict[str, Any]], str]] = {
    'cmp': lambda request: CmpSharedSecretCommandBuilder.get_dynamic_cert_profile_command(
        host='https://tp/cmp', pk=1, shared_secret='secret', cred_number=1, sample_request=request
    ),
    'est': lambda request: EstUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
        cred_number=1, sample_request=request
    ),
    'rest': lambda request: RestUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
        cred_number=1, sample_request=request
    ),
}
SAN_PREFIX = {'cmp': '', 'est': 'URI:', 'rest': 'URI:'}
DNS_PREFIX = {'cmp': '', 'est': 'DNS:', 'rest': 'DNS:'}


def _template(profile: dict[str, Any], protocol: str) -> CertParameterTemplate:
    verifier = JSONProfileVerifier(profile)
    return CertParameterTemplate.build(verifier.get_sample_request(), verifier.get_editable_fields(), BUILDERS[protocol])


def _ids(template: CertParameterTemplate) -> list[str]:
    return [p.id for p in template.parameters]


@pytest.mark.parametrize('protocol', BUILDERS)
def test_required_subject_field(protocol: str) -> None:
    template = _template(CN_REQUIRED, protocol)
    (param,) = template.parameters
    assert param.id == 'subject_common_name'
    assert param.required
    assert param.default == ''
    assert param.placeholder in template.variants['']
    assert 'CHANGEME' not in template.initial_command
    assert '/commonName=<common_name>' in template.initial_command
    assert '/commonName=device-1"' in template.render({'subject_common_name': 'device-1'})


@pytest.mark.parametrize('protocol', BUILDERS)
def test_required_san_uri(protocol: str) -> None:
    template = _template(URI_REQUIRED, protocol)
    assert _ids(template) == ['extensions_subject_alternative_name_uris']
    command = template.render({'extensions_subject_alternative_name_uris': 'urn:example:1'})
    assert f'{SAN_PREFIX[protocol]}urn:example:1' in command
    assert 'CHANGEME' not in command


@pytest.mark.parametrize('protocol', BUILDERS)
def test_multiple_required_fields_update_independently(protocol: str) -> None:
    template = _template(DEV_OWNER_ID, protocol)
    assert _ids(template) == ['subject_common_name', 'extensions_subject_alternative_name_uris']
    assert all(p.required for p in template.parameters)

    only_cn = template.render({'subject_common_name': 'owner'})
    assert '/commonName=owner' in only_cn
    assert f'{SAN_PREFIX[protocol]}<uris>' in only_cn

    both = template.render({'subject_common_name': 'owner', 'extensions_subject_alternative_name_uris': 'urn:x'})
    assert '/commonName=owner' in both
    assert f'critical, {SAN_PREFIX[protocol]}urn:x' in both


@pytest.mark.parametrize('protocol', BUILDERS)
def test_optional_fields_are_omitted_when_empty(protocol: str) -> None:
    template = _template(OPTIONAL, protocol)
    params = {p.id: p for p in template.parameters}
    assert set(params) == {
        'subject_common_name', 'subject_organization_name', 'extensions_subject_alternative_name_dns_names',
    }
    assert not params['subject_organization_name'].required
    assert params['subject_organization_name'].default == 'Acme'
    assert '/organizationName=Acme' in template.initial_command
    assert 'DNS' not in template.initial_command
    assert '-sans' not in template.initial_command
    assert 'subjectAltName' not in template.initial_command

    empty = template.render({'subject_common_name': 'cn'})
    assert 'organizationName' not in empty
    assert '__TP_PARAM_' not in empty

    filled = template.render({
        'subject_common_name': 'cn',
        'subject_organization_name': 'Org',
        'extensions_subject_alternative_name_dns_names': 'dev.example.test',
    })
    assert '/commonName=cn/organizationName=Org' in filled
    assert f'{DNS_PREFIX[protocol]}dev.example.test' in filled


@pytest.mark.parametrize('protocol', BUILDERS)
def test_no_editable_parameters_keeps_command(protocol: str) -> None:
    template = _template(FIXED, protocol)
    assert template.parameters == []
    assert template.initial_command == BUILDERS[protocol](JSONProfileVerifier(FIXED).get_sample_request())


@pytest.mark.parametrize('protocol', BUILDERS)
def test_non_text_fields_are_skipped(protocol: str) -> None:
    profile = {**CN_REQUIRED, 'ext': {'subject_alternative_name': {'required': False}}}
    template = _template(profile, protocol)
    assert _ids(template) == ['subject_common_name']
    assert '__TP_PARAM_' not in template.render({'subject_common_name': 'cn'})


def test_values_are_shell_and_openssl_escaped() -> None:
    template = _template(CN_REQUIRED, 'est')
    assert template.parameters[0].quoting == ShellQuoting.DOUBLE
    command = template.render({'subject_common_name': 'a/b+"c" $(id) `x` \\ !\n'})
    assert '-subj "/commonName=a\\\\/b\\\\+\\"c\\" \\$(id) \\`x\\` \\\\\\\\ "\'!\'""' in command


@pytest.mark.parametrize('quoting', ShellQuoting)
def test_format_value_quoting(quoting: ShellQuoting) -> None:
    template = _template(URI_REQUIRED, 'est')
    param = template.parameters[0].__class__(**{**template.parameters[0].__dict__, 'quoting': quoting})
    expected = {
        ShellQuoting.NONE: "'it'\\''s'",
        ShellQuoting.SINGLE: "it'\\''s",
        ShellQuoting.DOUBLE: "it's",
    }
    assert param.format_value("it's") == expected[quoting]


# ------------------------------------------------- Strategy / page tests ----------------------------------------------

STRATEGIES = [
    NoOnboardingCmpSharedSecretStrategy,
    NoOnboardingEstUsernamePasswordStrategy,
    NoOnboardingRestUsernamePasswordStrategy,
]


def _build(strategy_class: type, profiles: list[Any]) -> list[HelpSection]:
    domain = _domain()
    device = _device(domain, no_onboarding=True)
    with (
        patch('help_pages.devices_help_views.build_tls_trust_store_section', return_value=HelpSection('TLS', [])),
        patch('help_pages.base.DomainAllowedCertificateProfileModel.get_list_of_display_names',
              return_value=[(1, 'A', 'a'), (2, 'B', 'b')]),
    ):
        sections, _heading = strategy_class().build_sections(_help_context(device, domain, profiles))
    return sections


def _profile_with(name: str, profile: dict[str, Any]) -> Any:
    allowed = _profile(name, name.upper())
    allowed.certificate_profile.profile = profile
    return allowed


def _template_data(section: HelpSection, name: str) -> dict[str, Any]:
    html = ''.join(str(row.value) for row in section.rows)
    match = re.search(rf'<script id="cert-params-data-{name}" type="application/json">(.*?)</script>', html)
    assert match
    return json.loads(match.group(1))


@pytest.mark.parametrize('strategy_class', STRATEGIES)
def test_parameters_section_is_placed_between_selection_and_request(strategy_class: type) -> None:
    sections = _build(strategy_class, [_profile_with('a', DEV_OWNER_ID)])
    headings = [s.heading for s in sections]
    index = headings.index('Certificate Parameters')
    assert headings[index - 1] == 'Certificate Profile Selection'
    assert headings[index + 1] == 'Certificate Request for a A Certificate'

    params_section = sections[index]
    keys = [str(row.key) for row in params_section.rows]
    assert any('Common Name' in key and 'text-danger' in key for key in keys)
    assert any('URIs' in key for key in keys)
    assert sum('required aria-required' in str(row.value) for row in params_section.rows) == 2
    assert any('alert-warning' in str(row.value) for row in params_section.rows)

    command_row = sections[index + 1].rows[0]
    assert command_row.css_id == 'cert-params-command-a'
    assert 'CHANGEME' not in command_row.value
    assert '<common_name>' in command_row.value
    data = _template_data(params_section, 'a')
    assert [p['id'] for p in data['parameters']] == ['subject_common_name', 'extensions_subject_alternative_name_uris']


@pytest.mark.parametrize('strategy_class', STRATEGIES)
def test_parameters_change_with_profile(strategy_class: type) -> None:
    sections = _build(strategy_class, [_profile_with('a', CN_REQUIRED), _profile_with('b', URI_REQUIRED)])
    params_section = next(s for s in sections if s.heading == 'Certificate Parameters')
    rows_by_profile: dict[str, list[bool]] = {'a': [], 'b': []}
    for row in params_section.rows:
        name = re.search(r'data-cert-params-profile="(\w+)"', str(row.value))
        assert name
        rows_by_profile[name.group(1)].append(row.hidden)
    assert rows_by_profile['a'] and not any(rows_by_profile['a'])
    assert rows_by_profile['b'] and all(rows_by_profile['b'])

    assert [p['id'] for p in _template_data(params_section, 'a')['parameters']] == ['subject_common_name']
    assert [p['id'] for p in _template_data(params_section, 'b')['parameters']] == [
        'extensions_subject_alternative_name_uris'
    ]
    command_a = next(s for s in sections if s.css_id == 'a').rows[0].value
    command_b = next(s for s in sections if s.css_id == 'b').rows[0].value
    assert '<common_name>' in command_a
    assert '<uris>' in command_b
    assert next(s for s in sections if s.css_id == 'b').hidden


@pytest.mark.parametrize('strategy_class', STRATEGIES)
def test_no_editable_parameters_message(strategy_class: type) -> None:
    sections = _build(strategy_class, [_profile_with('a', FIXED)])
    params_section = next(s for s in sections if s.heading == 'Certificate Parameters')
    assert len(params_section.rows) == 1
    assert 'No additional parameters required.' in str(params_section.rows[0].value)
    assert '/commonName=fixed-cn' in next(s for s in sections if s.css_id == 'a').rows[0].value
