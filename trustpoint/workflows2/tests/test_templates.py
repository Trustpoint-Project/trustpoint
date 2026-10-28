# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for workflow template parsing and adversarial input."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from workflows2.compiler import templates
from workflows2.compiler.errors import CompileError
from workflows2.compiler.templates import compile_template, compile_templates_deep
from workflows2.engine.context import RuntimeContext
from workflows2.engine.eval import render_template


@pytest.mark.parametrize('value', [None, 42, False, [], {}, '', 'plain text', '${}', 'before ${}', '${vars.unclosed'])
def test_values_without_complete_nonempty_placeholders_are_unchanged(value):
    assert compile_template(value, path='body') is value


@pytest.mark.parametrize(
    'value,expected',
    [
        ('${vars.name}', 'Ada'),
        ('Hello ${vars.name}!', 'Hello Ada!'),
        ('${vars.name}${event.id}', 'Ada7'),
        ('${} ${vars.name} ${}', '${} Ada ${}'),
        ('${vars.name} trailing ${unclosed', 'Ada trailing ${unclosed'),
        ('extra } ${vars.name} }}', 'extra } Ada }}'),
        ('${\n vars.name\n}', 'Ada'),
        ('${upper(vars.name)} / ${add(1, 2)}', 'ADA / 3.0'),
        ('${"literal"}', 'literal'),
    ],
)
def test_template_compilation_and_rendering_preserve_delimiter_behavior(value, expected):
    compiled = compile_template(value, path='body')
    assert compiled['kind'] == 'template'
    assert render_template(compiled, RuntimeContext(event={'id': 7}, vars={'name': 'Ada'})) == expected


def test_template_ir_retains_text_and_reference_parts():
    assert compile_template('Hello ${vars.name}!', path='subject') == {
        'kind': 'template',
        'parts': [
            {'kind': 'text', 'value': 'Hello '},
            {'kind': 'expr', 'expr': {'kind': 'ref', 'path': ['vars', 'name']}},
            {'kind': 'text', 'value': '!'},
        ],
    }


@pytest.mark.parametrize('value', ['${unknown.name}', '${not_allowed()}', '${ }', '${vars.}'])
def test_invalid_complete_expressions_still_report_source_path(value):
    with pytest.raises(CompileError) as error:
        compile_template(value, path='workflow.steps.email.body')
    assert error.value.path == 'workflow.steps.email.body'


def test_nested_placeholder_is_not_silently_reinterpreted():
    with pytest.raises(CompileError, match="Unexpected '\\$'"):
        compile_template('${${vars.name}}', path='body')


def test_deep_templates_preserve_literals_and_error_paths():
    value = {'headers': ['Hello ${vars.name}', '${}', 7]}
    compiled = compile_templates_deep(value, path='webhook')
    assert render_template(compiled, RuntimeContext(event={}, vars={'name': 'Ada'})) == {
        'headers': ['Hello Ada', '${}', 7],
    }
    with pytest.raises(CompileError) as error:
        compile_templates_deep({'headers': ['${vars.}']}, path='webhook')
    assert error.value.path == 'webhook.headers[0]'


def test_many_unclosed_placeholders_complete_within_bounded_time():
    """A subprocess timeout bounds the test even if quadratic scanning returns."""
    source = """
from workflows2.compiler.templates import compile_template
for value in ('${|' * 100_000, '${}' * 100_000 + '${unterminated'):
    assert compile_template(value, path='body') == value
"""
    subprocess.run(
        [sys.executable, '-c', source],
        env={**os.environ, 'PYTHONPATH': str(Path(templates.__file__).resolve().parents[2])},
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
