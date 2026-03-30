"""Unit tests for the template variable resolver."""

from __future__ import annotations

import uuid
from unittest.mock import Mock

from request.request_context import BaseRequestContext
from request.template_vars import (
    TemplateVariableResolver,
    resolve_template_variables,
)

_build_variable_map = TemplateVariableResolver._build_variable_map
_resolve_recursively = TemplateVariableResolver._resolve_recursively
_resolve_string = TemplateVariableResolver._resolve_string


def _make_context(
    *,
    device_uuid: uuid.UUID | None = None,
    device_cn: str = 'test-device',
    device_serial: str = 'SN-001',
    domain_name: str = 'test-domain',
    with_device: bool = True,
    with_domain: bool = True,
) -> BaseRequestContext:
    """Create a minimal BaseRequestContext with mocked device / domain."""
    ctx = BaseRequestContext()
    if with_device:
        device = Mock()
        device.rfc_4122_uuid = device_uuid or uuid.UUID('550e8400-e29b-41d4-a716-446655440000')
        device.common_name = device_cn
        device.serial_number = device_serial
        ctx.device = device
    if with_domain:
        domain = Mock()
        domain.unique_name = domain_name
        ctx.domain = domain
    return ctx


class TestBuildVariableMap:
    """Tests for _build_variable_map."""

    def test_full_context(self):
        ctx = _make_context()
        variables = _build_variable_map(ctx)
        assert variables['device.rfc_4122_uuid'] == '550e8400-e29b-41d4-a716-446655440000'
        assert variables['device.common_name'] == 'test-device'
        assert variables['device.serial_number'] == 'SN-001'
        assert variables['domain.unique_name'] == 'test-domain'

    def test_no_device(self):
        ctx = _make_context(with_device=False)
        variables = _build_variable_map(ctx)
        assert 'device.rfc_4122_uuid' not in variables
        assert 'device.common_name' not in variables
        assert 'domain.unique_name' in variables

    def test_no_domain(self):
        ctx = _make_context(with_domain=False)
        variables = _build_variable_map(ctx)
        assert 'device.rfc_4122_uuid' in variables
        assert 'domain.unique_name' not in variables

    def test_empty_context(self):
        ctx = _make_context(with_device=False, with_domain=False)
        variables = _build_variable_map(ctx)
        assert variables == {}


class TestResolveString:
    """Tests for _resolve_string."""

    def test_single_variable(self):
        variables = {'device.rfc_4122_uuid': '550e8400-e29b-41d4-a716-446655440000'}
        result = _resolve_string(
            'spiffe://trustpoint/device/{{ device.rfc_4122_uuid }}', variables
        )
        assert result == 'spiffe://trustpoint/device/550e8400-e29b-41d4-a716-446655440000'

    def test_multiple_variables(self):
        variables = {
            'device.rfc_4122_uuid': 'abc-123',
            'domain.unique_name': 'my-domain',
        }
        result = _resolve_string(
            'spiffe://{{ domain.unique_name }}/device/{{ device.rfc_4122_uuid }}', variables
        )
        assert result == 'spiffe://my-domain/device/abc-123'

    def test_no_variables(self):
        result = _resolve_string('plain-string-without-vars', {})
        assert result == 'plain-string-without-vars'

    def test_unresolved_variable_left_as_is(self):
        result = _resolve_string('{{ unknown.field }}', {})
        assert result == '{{ unknown.field }}'

    def test_whitespace_tolerance(self):
        variables = {'device.rfc_4122_uuid': 'test-uuid'}
        assert _resolve_string('{{device.rfc_4122_uuid}}', variables) == 'test-uuid'
        assert _resolve_string('{{  device.rfc_4122_uuid  }}', variables) == 'test-uuid'
        assert _resolve_string('{{ device.rfc_4122_uuid }}', variables) == 'test-uuid'


class TestResolveRecursively:
    """Tests for _resolve_recursively."""

    def test_nested_dict(self):
        variables = {'device.rfc_4122_uuid': 'test-uuid'}
        data = {
            'ext': {
                'subject_alternative_name': {
                    'uris': ['spiffe://tp/{{ device.rfc_4122_uuid }}'],
                },
            },
        }
        result = _resolve_recursively(data, variables)
        assert result['ext']['subject_alternative_name']['uris'] == [
            'spiffe://tp/test-uuid'
        ]

    def test_list_of_strings(self):
        variables = {'device.rfc_4122_uuid': 'uuid-val'}
        data = ['{{ device.rfc_4122_uuid }}', 'literal']
        result = _resolve_recursively(data, variables)
        assert result == ['uuid-val', 'literal']

    def test_non_string_values_unchanged(self):
        variables = {'device.rfc_4122_uuid': 'test'}
        data = {'number': 42, 'flag': True, 'nothing': None}
        result = _resolve_recursively(data, variables)
        assert result == {'number': 42, 'flag': True, 'nothing': None}

    def test_original_not_mutated(self):
        variables = {'device.rfc_4122_uuid': 'new-val'}
        data = {'uri': '{{ device.rfc_4122_uuid }}'}
        result = _resolve_recursively(data, variables)
        assert result['uri'] == 'new-val'
        assert data['uri'] == '{{ device.rfc_4122_uuid }}'


class TestResolveTemplateVariables:
    """Tests for the public resolve_template_variables entry-point."""

    def test_spiffe_uri_substitution(self):
        ctx = _make_context(
            device_uuid=uuid.UUID('12345678-1234-1234-1234-123456789abc'),
            domain_name='margo',
        )
        data = {
            'subject': {'common_name': 'my-device'},
            'ext': {
                'subject_alternative_name': {
                    'uris': [
                        'spiffe://trustpoint/{{ domain.unique_name }}/device/'
                        '{{ device.rfc_4122_uuid }}',
                    ],
                },
            },
        }
        result = resolve_template_variables(data, ctx)
        assert result['ext']['subject_alternative_name']['uris'] == [
            'spiffe://trustpoint/margo/device/12345678-1234-1234-1234-123456789abc',
        ]
        # subject unchanged
        assert result['subject'] == {'common_name': 'my-device'}

    def test_no_context_returns_data_unchanged(self):
        ctx = _make_context(with_device=False, with_domain=False)
        data = {'uri': '{{ device.rfc_4122_uuid }}'}
        result = resolve_template_variables(data, ctx)
        # No variables available, data returned as-is
        assert result == data

    def test_mixed_literal_and_template(self):
        ctx = _make_context(device_cn='my-device')
        data = {
            'ext': {
                'subject_alternative_name': {
                    'dns_names': ['example.com'],
                    'uris': [
                        'spiffe://tp/{{ device.rfc_4122_uuid }}',
                        'https://literal.example.com',
                    ],
                },
            },
        }
        result = resolve_template_variables(data, ctx)
        assert result['ext']['subject_alternative_name']['dns_names'] == ['example.com']
        assert result['ext']['subject_alternative_name']['uris'][0] == (
            'spiffe://tp/550e8400-e29b-41d4-a716-446655440000'
        )
        assert result['ext']['subject_alternative_name']['uris'][1] == 'https://literal.example.com'

    def test_device_common_name_in_subject(self):
        ctx = _make_context(device_cn='edge-gateway-01')
        data = {
            'subject': {
                'common_name': '{{ device.common_name }}',
            },
        }
        result = resolve_template_variables(data, ctx)
        assert result['subject']['common_name'] == 'edge-gateway-01'

    def test_original_data_not_mutated(self):
        ctx = _make_context()
        data = {
            'ext': {
                'subject_alternative_name': {
                    'uris': ['spiffe://tp/{{ device.rfc_4122_uuid }}'],
                },
            },
        }
        resolve_template_variables(data, ctx)
        # Original must be unchanged
        assert data['ext']['subject_alternative_name']['uris'] == [
            'spiffe://tp/{{ device.rfc_4122_uuid }}'
        ]
