# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify enrollment ordering, trust boundaries, workflow stops and failure responses."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.test import RequestFactory

from est.views import EstSimpleEnrollmentView, EstSimpleReEnrollmentView
from request import enrollment
from request.request_context import RestCertificateRequestContext
from request.workflows2_handler import Workflow2HandleResult
from rest_pki.api_views import ApplicationCertificateEnrollView
from rest_pki.views import RestEnrollView, RestReEnrollView
from workflows2.events.request_events import Events

CASES = {
    'est': (EstSimpleEnrollmentView, 'simpleenroll', Events.est_simpleenroll),
    'est-reenroll': (EstSimpleReEnrollmentView, 'simplereenroll', Events.est_simplereenroll),
    'rest': (RestEnrollView, 'enroll', Events.rest_enroll),
    'rest-reenroll': (RestReEnrollView, 'reenroll', Events.rest_reenroll),
    'management-api': (ApplicationCertificateEnrollView, 'enroll', Events.rest_enroll),
}


def _steps(case):
    steps = ['validate', 'parse']
    if case.startswith('est'):
        steps.append('policy')
    if case != 'management-api':
        steps.append('authenticate')
    steps += ['authorize', 'workflow']
    if case.startswith('est'):
        steps.append('atomic')
    return steps + ['issue', 'respond', 'release']


@pytest.fixture
def drive_enrollment(monkeypatch):
    """Run actual views and orchestration with isolated protocol components."""

    def drive(case, *, stop=False, fail_at=None):
        calls = []
        original_contexts = []
        parsed_contexts = []
        error_contexts = []
        device = Mock(name='authenticated-device')

        def record(step):
            calls.append(step)
            if step == fail_at:
                raise ValueError(f'{step} failed')

        def parse(context):
            original_contexts.append(context)
            record('parse')
            parsed = replace(context)
            parsed.device = Mock(name='untrusted-parsed-device')
            parsed_contexts.append(parsed)
            return parsed

        def authenticate(context):
            record('authenticate')
            context.device = device

        def authorize(context):
            record('authorize')
            assert context is parsed_contexts[0]
            assert context.device is device

        def workflow(context):
            record('workflow')
            assert context is parsed_contexts[0]
            return Workflow2HandleResult.stop_processing() if stop else Workflow2HandleResult.continue_processing()

        def issue(context):
            record('issue')
            assert context is parsed_contexts[0]

        def atomic(context, processor):
            record('atomic')
            processor.process_operation(context)

        def respond(context):
            record('respond')
            context.http_response_content = b'{"certificate": "issued"}'
            context.http_response_status = 202 if stop else 200
            context.http_response_content_type = 'application/json'

        def error_response(context):
            calls.append('error')
            error_contexts.append(context)
            context.http_response_content = b'{"detail": "enrollment failed"}'
            context.http_response_status = 418
            context.http_response_content_type = 'application/json'

        constructors = {}
        for prefix in ('Est', 'Rest'):
            components = {
                'HttpRequestValidator': ('validate', lambda ctx: record('validate')),
                'MessageParser': ('parse', parse),
                'Authorization': ('authorize', authorize),
            }
            for suffix, (method, callback) in components.items():
                constructor = Mock(return_value=SimpleNamespace(**{method: callback}))
                constructors[prefix + suffix] = constructor
                monkeypatch.setattr(enrollment, prefix + suffix, constructor)
            monkeypatch.setattr(enrollment, prefix + 'MessageResponder', SimpleNamespace(build_response=respond))
        authenticator = Mock(return_value=SimpleNamespace(authenticate=authenticate))
        monkeypatch.setattr(enrollment, 'RestAuthentication', authenticator)
        monkeypatch.setattr(enrollment, 'authenticate_est_request', authenticate)
        monkeypatch.setattr(enrollment, 'require_single_security_config', lambda ctx: record('policy'))
        monkeypatch.setattr(enrollment, 'process_certificate_operation_atomically', atomic)
        monkeypatch.setattr(enrollment, 'Workflow2Handler', Mock(return_value=SimpleNamespace(handle=workflow)))
        processor = Mock(return_value=SimpleNamespace(process_operation=issue))
        monkeypatch.setattr(enrollment, 'OperationProcessor', processor)
        monkeypatch.setattr(enrollment, 'release_delivered_workflow2_request', lambda ctx: record('release'))
        monkeypatch.setattr('est.views.EstErrorMessageResponder.build_response', error_response)
        monkeypatch.setattr('rest_pki.views.RestErrorMessageResponder.build_response', error_response)

        view_type, operation, event = CASES[case]
        request = RequestFactory().post(
            '/enrollment/test-domain/test-profile', data=b'{}', content_type='application/json'
        )
        if case == 'management-api':
            context = RestCertificateRequestContext(
                raw_message=request,
                protocol='rest',
                operation=operation,
                event=event,
                domain_str='test-domain',
                cert_profile_str='test-profile',
                device=device,
            )
            response = view_type()._run_enrollment_pipeline(context, device, 1)
            authenticator.assert_not_called()
        else:
            response = view_type.as_view()(request, domain='test-domain', cert_profile='test-profile')
        if original_contexts:
            context = original_contexts[0]
            assert context.operation == operation
            assert context.event == event
            assert context.domain_str == 'test-domain'
            assert context.cert_profile_str == 'test-profile'
        if fail_at is None:
            prefix = 'Est' if case.startswith('est') else 'Rest'
            constructors[prefix + 'Authorization'].assert_called_once_with(allowed_operations=[operation])
        if stop or fail_at in ('validate', 'parse', 'policy', 'authenticate', 'authorize', 'workflow'):
            processor.assert_not_called()
        if parsed_contexts and error_contexts:
            assert error_contexts[0] is parsed_contexts[0]
        return response, calls

    return drive


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('stop', [False, True])
def test_enrollment_order_and_workflow_gate(case, stop, drive_enrollment):
    """Every entry point authorizes before workflows and only issues on a continue decision."""
    response, calls = drive_enrollment(case, stop=stop)
    expected = _steps(case)
    if stop:
        expected = [step for step in expected if step not in ('atomic', 'issue')]
    assert calls == expected
    assert response.status_code == (202 if stop else 200)


@pytest.mark.parametrize(('case', 'stage'), [(case, stage) for case in CASES for stage in _steps(case)])
def test_failures_short_circuit_and_render_the_current_context(case, stage, drive_enrollment):
    """A failed prerequisite never reaches later stages, issuance, or delivery release."""
    response, calls = drive_enrollment(case, fail_at=stage)
    steps = _steps(case)
    assert calls == steps[: steps.index(stage) + 1] + ['error']
    assert response.status_code == 418
