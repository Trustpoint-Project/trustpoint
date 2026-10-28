# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Focused tests for explicit workflows2 dispatch in REST PKI views."""

from __future__ import annotations

import json
from unittest.mock import Mock, patch

from django.http import HttpResponse
from django.test import RequestFactory

from request.request_context import RestCertificateRequestContext
from request.workflows2_handler import Workflow2HandleResult
from rest_pki.api_views import ApplicationCertificateEnrollView
from rest_pki.views import RestEnrollView, RestReEnrollView

HTTP_OK = 200


def test_rest_enroll_view_dispatches_workflows2_before_processing() -> None:
    """REST enroll dispatches workflows2 through the shared orchestrator."""
    request = RequestFactory().post(
        '/rest/enroll/test_domain/domain_credential',
        data=b'{}',
        content_type='application/json',
    )
    context = Mock(spec=RestCertificateRequestContext)
    context.event = Mock()
    context.http_response_content = b'{}'
    context.http_response_status = 200
    context.http_response_content_type = 'application/json'
    context.to_http_response.return_value = HttpResponse(
        content=context.http_response_content,
        status=context.http_response_status,
        content_type=context.http_response_content_type,
    )

    with patch('rest_pki.views.RestCertificateRequestContext', return_value=context), patch(
        'request.enrollment.RestHttpRequestValidator'
    ) as mock_validator, patch('request.enrollment.RestMessageParser') as mock_parser, patch(
        'request.enrollment.RestAuthentication'
    ) as mock_authentication, patch('request.enrollment.RestAuthorization') as mock_authorization, patch(
        'request.enrollment.Workflow2Handler'
    ) as mock_workflow2, patch('request.enrollment.OperationProcessor') as mock_processor, patch(
        'request.enrollment.RestMessageResponder'
    ) as mock_responder:
        mock_parser.return_value.parse.return_value = context
        mock_workflow2.return_value.handle.return_value = Workflow2HandleResult.continue_processing()

        response = RestEnrollView.as_view()(request, domain='test_domain', cert_profile='domain_credential')

    assert response.status_code == HTTP_OK
    mock_validator.return_value.validate.assert_called_once_with(context)
    mock_authentication.return_value.authenticate.assert_called_once_with(context)
    mock_authorization.return_value.authorize.assert_called_once_with(context)
    mock_workflow2.return_value.handle.assert_called_once_with(context)
    mock_processor.return_value.process_operation.assert_called_once_with(context)
    mock_responder.build_response.assert_called_once_with(context)


def test_rest_reenroll_view_dispatches_workflows2_before_processing() -> None:
    """REST reenroll dispatches workflows2 through the shared orchestrator."""
    request = RequestFactory().post(
        '/rest/reenroll/test_domain/domain_credential',
        data=b'{}',
        content_type='application/json',
    )
    context = Mock(spec=RestCertificateRequestContext)
    context.event = Mock()
    context.http_response_content = b'{}'
    context.http_response_status = 200
    context.http_response_content_type = 'application/json'
    context.to_http_response.return_value = HttpResponse(
        content=context.http_response_content,
        status=context.http_response_status,
        content_type=context.http_response_content_type,
    )

    with patch('rest_pki.views.RestCertificateRequestContext', return_value=context), patch(
        'request.enrollment.RestHttpRequestValidator'
    ) as mock_validator, patch('request.enrollment.RestMessageParser') as mock_parser, patch(
        'request.enrollment.RestAuthentication'
    ) as mock_authentication, patch('request.enrollment.RestAuthorization') as mock_authorization, patch(
        'request.enrollment.Workflow2Handler'
    ) as mock_workflow2, patch('request.enrollment.OperationProcessor') as mock_processor, patch(
        'request.enrollment.RestMessageResponder'
    ) as mock_responder:
        mock_parser.return_value.parse.return_value = context
        mock_workflow2.return_value.handle.return_value = Workflow2HandleResult.continue_processing()

        response = RestReEnrollView.as_view()(request, domain='test_domain', cert_profile='domain_credential')

    assert response.status_code == HTTP_OK
    mock_validator.return_value.validate.assert_called_once_with(context)
    mock_authentication.return_value.authenticate.assert_called_once_with(context)
    mock_authorization.return_value.authorize.assert_called_once_with(context)
    mock_workflow2.return_value.handle.assert_called_once_with(context)
    mock_processor.return_value.process_operation.assert_called_once_with(context)
    mock_responder.build_response.assert_called_once_with(context)


def test_rest_api_pipeline_dispatches_workflows2_before_processing() -> None:
    """REST API enrollment dispatches workflows2 before issuance processing."""
    context = Mock(spec=RestCertificateRequestContext)
    context.event = Mock()
    context.to_http_response.return_value = HttpResponse(
        content=json.dumps({'certificate': 'pem'}).encode('utf-8'),
        status=200,
        content_type='application/json',
    )

    view = ApplicationCertificateEnrollView()
    device = Mock()
    device.pk = 7

    with patch('request.enrollment.RestHttpRequestValidator') as mock_validator, patch(
        'request.enrollment.RestMessageParser'
    ) as mock_parser, patch('request.enrollment.RestAuthorization') as mock_authorization, patch(
        'request.enrollment.Workflow2Handler'
    ) as mock_workflow2, patch('request.enrollment.OperationProcessor') as mock_processor, patch(
        'request.enrollment.RestMessageResponder'
    ) as mock_responder:
        mock_parser.return_value.parse.return_value = context
        mock_workflow2.return_value.handle.return_value = Workflow2HandleResult.continue_processing()

        response = view._run_enrollment_pipeline(context, device, device.pk)  # noqa: SLF001

    assert response.status_code == HTTP_OK
    mock_validator.return_value.validate.assert_called_once_with(context)
    mock_authorization.return_value.authorize.assert_called_once_with(context)
    mock_workflow2.return_value.handle.assert_called_once_with(context)
    mock_processor.return_value.process_operation.assert_called_once_with(context)
    mock_responder.build_response.assert_called_once_with(context)


def test_rest_enroll_view_skips_processing_when_workflow_blocks() -> None:
    """REST enroll should not issue a certificate when workflows2 blocks the request."""
    request = RequestFactory().post(
        '/rest/enroll/test_domain/domain_credential',
        data=b'{}',
        content_type='application/json',
    )
    context = Mock(spec=RestCertificateRequestContext)
    context.event = Mock()
    context.http_response_content = b'{}'
    context.http_response_status = 202
    context.http_response_content_type = 'application/json'
    context.to_http_response.return_value = HttpResponse(
        content=context.http_response_content,
        status=context.http_response_status,
        content_type=context.http_response_content_type,
    )

    with patch('rest_pki.views.RestCertificateRequestContext', return_value=context), patch(
        'request.enrollment.RestHttpRequestValidator'
    ), patch('request.enrollment.RestMessageParser') as mock_parser, patch(
        'request.enrollment.RestAuthentication'
    ), patch('request.enrollment.RestAuthorization'), patch(
        'request.enrollment.Workflow2Handler'
    ) as mock_workflow2, patch('request.enrollment.OperationProcessor') as mock_processor, patch(
        'request.enrollment.RestMessageResponder'
    ) as mock_responder:
        mock_parser.return_value.parse.return_value = context
        mock_workflow2.return_value.handle.return_value = Workflow2HandleResult.stop_processing()

        response = RestEnrollView.as_view()(request, domain='test_domain', cert_profile='domain_credential')

    assert response.status_code == 202
    mock_processor.return_value.process_operation.assert_not_called()
    mock_responder.build_response.assert_called_once_with(context)
