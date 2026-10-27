# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Security and parsing regressions shared by workflow compilation and formatting."""

from unittest.mock import patch

import pytest
import yaml

from workflows2.compiler.errors import CompileError
from workflows2.compiler.yaml_format import format_yaml_text, parse_yaml_text
from workflows2.compiler.yaml_loader import load_yaml_any, load_yaml_text


@pytest.mark.parametrize('parser', [load_yaml_any, parse_yaml_text])
def test_workflow_booleans_preserve_yaml_keys(parser):
    """YAML 1.1 boolean words stay strings while true/false remain booleans."""
    parsed = parser('on: device.created\noff: no\nyes: ON\nenabled: TRUE\ndisabled: false\n')
    assert parsed == {'on': 'device.created', 'off': 'no', 'yes': 'ON', 'enabled': True, 'disabled': False}
    assert yaml.safe_load('on: yes') == {True: True}


@pytest.mark.parametrize(
    'parser,error_type',
    [
        (load_yaml_any, CompileError),
        (load_yaml_text, CompileError),
        (parse_yaml_text, yaml.YAMLError),
        (format_yaml_text, yaml.YAMLError),
    ],
)
@pytest.mark.parametrize(
    'payload',
    [
        '!!python/object/apply:os.system ["echo must-not-execute"]',
        '!!python/object/new:builtins.object {}',
        '!!python/object:builtins.object {}',
        '!!python/name:os.system',
        'nested: !!python/object/apply:os.system ["echo must-not-execute"]',
    ],
)
def test_python_tags_are_rejected_without_execution(parser, error_type, payload):
    """Every YAML entry point rejects Python tags before any callable runs."""
    with patch('os.system') as system:
        with pytest.raises(error_type):
            parser(payload)
        system.assert_not_called()


@pytest.mark.parametrize('parser,error_type', [(load_yaml_any, CompileError), (parse_yaml_text, yaml.YAMLError)])
@pytest.mark.parametrize('payload', ['value: [unterminated', '---\na: 1\n---\nb: 2'])
def test_invalid_or_multiple_documents_preserve_error_contract(parser, error_type, payload):
    """Compiler errors are wrapped, while formatting preserves PyYAML exceptions."""
    with pytest.raises(error_type) as error:
        parser(payload)
    if isinstance(error.value, CompileError):
        assert error.value.message == 'Invalid YAML'
        assert error.value.details
        assert isinstance(error.value.__cause__, yaml.YAMLError)


@pytest.mark.parametrize('payload', ['', 'null', '[one, two]', '42'])
def test_compiler_requires_top_level_mapping(payload):
    with pytest.raises(CompileError, match='Top-level YAML must be a mapping/object'):
        load_yaml_text(payload)


def test_yaml_format_round_trip_preserves_booleans_and_on_keys():
    text = 'trigger:\r\n  on: device.created\r\nenabled: true\r\nvalues: [on, off, yes, no, false]\r\n'
    formatted = format_yaml_text(text)
    assert '\r' not in formatted
    assert formatted.endswith('\n')
    assert load_yaml_text(formatted) == load_yaml_text(text)
    assert format_yaml_text(formatted) == formatted


@pytest.mark.parametrize('parser', [load_yaml_any, parse_yaml_text])
def test_yaml_aliases_and_nested_values_are_preserved(parser):
    assert parser('base: &base {enabled: true}\ncopy: *base\n') == {
        'base': {'enabled': True},
        'copy': {'enabled': True},
    }
