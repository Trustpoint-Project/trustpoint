# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Graph preview errors must not expose internal compiler or adapter exceptions."""

from unittest.mock import Mock, patch

import pytest
from django.urls import reverse
from django.utils import translation

from workflows2.compiler.errors import CompileError


@pytest.fixture
def authenticated_client(client, django_user_model):
    user = django_user_model.objects.create_user(username='graph-preview-user')
    client.force_login(user)
    return client


@pytest.mark.parametrize('failure_stage', ['compiler', 'graph'])
@pytest.mark.parametrize(
    'exception',
    [
        CompileError('sensitive internal message', path='/private/server/path', details='private details'),
        ValueError('sensitive internal message /private/server/path'),
        TypeError('sensitive internal message /private/server/path'),
        KeyError('sensitive internal message /private/server/path'),
    ],
)
def test_internal_graph_errors_return_only_generic_message(authenticated_client, failure_stage, exception):
    compiler = Mock(return_value={'workflow': {}})
    graph = Mock(return_value={})
    if failure_stage == 'compiler':
        compiler.side_effect = exception
    else:
        graph.side_effect = exception
    with (
        patch('workflows2.views.graph_from_yaml_api.compile_workflow_yaml', compiler),
        patch('workflows2.views.graph_from_yaml_api.WorkflowGraphService.graph_from_ir', graph),
        translation.override('en'),
    ):
        response = authenticated_client.post(
            reverse('workflows2:api_graph_from_yaml'),
            {'yaml_text': 'draft'},
            content_type='application/json',
        )
    assert response.status_code == 400
    assert response.json() == {'error': 'Unable to generate a graph from this workflow YAML.'}
    for private_detail in (
        'sensitive internal message',
        '/private/server/path',
        'private details',
        type(exception).__name__,
    ):
        assert private_detail not in response.content.decode()


@pytest.mark.parametrize(
    'body,expected',
    [
        (b'not-json', 'Invalid JSON body'),
        (b'\xff', 'Invalid JSON body'),
        (b'[]', 'JSON body must be an object'),
        (b'null', 'JSON body must be an object'),
        (b'42', 'JSON body must be an object'),
        (b'"string"', 'JSON body must be an object'),
        (b'{}', 'yaml_text missing'),
        (b'{"yaml_text": 42}', 'yaml_text missing'),
        (b'{"yaml_text": "  "}', 'yaml_text missing'),
    ],
)
def test_invalid_graph_requests_fail_before_compilation(authenticated_client, body, expected):
    with patch('workflows2.views.graph_from_yaml_api.compile_workflow_yaml') as compiler, translation.override('en'):
        response = authenticated_client.post(
            reverse('workflows2:api_graph_from_yaml'),
            body,
            content_type='application/json',
        )
    assert response.status_code == 400
    assert response.json() == {'error': expected}
    compiler.assert_not_called()


def test_malformed_yaml_returns_generic_json_error(authenticated_client):
    with translation.override('en'):
        response = authenticated_client.post(
            reverse('workflows2:api_graph_from_yaml'),
            {'yaml_text': 'workflow: [unterminated'},
            content_type='application/json',
        )
    assert response.status_code == 400
    assert response.json() == {'error': 'Unable to generate a graph from this workflow YAML.'}
