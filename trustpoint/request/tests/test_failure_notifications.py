# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Final request failures create notifications without changing protocol responses."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.db import DatabaseError, transaction
from django.test import RequestFactory

from cmp.models import CmpTransactionModel
from est.views import EstSimpleEnrollmentMixin
from management.models import NotificationConfig, NotificationModel
from pki.models import DomainModel
from request.message_responder.cmp import CmpErrorMessageResponder, CmpTransactionResponder
from request.request_context import (
    CmpCertificateRequestContext,
    EstCertificateRequestContext,
    RestCertificateRequestContext,
)
from scep.handler import ScepHttpResult, ScepPkiOperationHandler
from scep.protocol.errors import ScepMalformedMessageError, ScepProtocolError
from scep.protocol.oids import FailInfo, MessageType

pytestmark = pytest.mark.django_db


@pytest.fixture
def notifications_enabled():
    config = NotificationConfig.get()
    config.enabled = True
    config.save()


@pytest.mark.parametrize('context_type,protocol', [(EstCertificateRequestContext, 'est'),
                                                  (RestCertificateRequestContext, 'rest')])
@pytest.mark.parametrize('status', [400, 403, 500])
def test_failed_response_creates_one_warning(notifications_enabled, context_type, protocol, status):
    context = context_type(protocol=protocol, operation='enroll', http_response_status=status,
                           http_response_content='secret response body')
    response = context.to_http_response()
    context.to_http_response()
    notification = NotificationModel.objects.get(event='REQUEST_FAILED')
    assert response.status_code == status
    assert response.content == b'secret response body'
    assert notification.notification_type == NotificationModel.NotificationTypes.WARNING
    assert notification.statuses.filter(status='NEW').exists()
    assert notification.message_data == {'protocol': protocol, 'operation': 'enroll'}
    assert protocol in notification.short_translated
    assert 'enroll' in notification.long_translated


@pytest.mark.parametrize('status', [200, 202])
def test_success_and_pending_do_not_notify(notifications_enabled, status):
    EstCertificateRequestContext(http_response_status=status).to_http_response()
    assert not NotificationModel.objects.filter(event='REQUEST_FAILED').exists()


def test_separate_requests_each_notify(notifications_enabled):
    for _ in range(2):
        EstCertificateRequestContext(http_response_status=403).to_http_response()
    assert NotificationModel.objects.filter(event='REQUEST_FAILED').count() == 2


def test_disabled_notifications_are_respected():
    config = NotificationConfig.get()
    config.enabled = False
    config.save()
    EstCertificateRequestContext(http_response_status=500).to_http_response()
    assert not NotificationModel.objects.filter(event='REQUEST_FAILED').exists()


def test_context_secrets_and_unknown_operations_are_not_saved(notifications_enabled):
    context = EstCertificateRequestContext(
        protocol='attacker-controlled-secret', operation='password=secret',
        est_password='secret', raw_message=RequestFactory().post('/', {'secret': 'secret'}),
        http_response_status=403, http_response_content='secret exception',
    )
    context.to_http_response()
    assert NotificationModel.objects.get(event='REQUEST_FAILED').message_data == {
        'protocol': 'unknown', 'operation': 'unknown',
    }


def test_resolved_device_and_domain_are_linked(notifications_enabled, device_instance):
    device = device_instance['device']
    EstCertificateRequestContext(device=device, domain=device.domain, http_response_status=403).to_http_response()
    notification = NotificationModel.objects.get(event='REQUEST_FAILED')
    assert notification.device == device
    assert notification.domain == device.domain
    assert notification.notification_source == NotificationModel.NotificationSource.DEVICE


def test_notification_failure_preserves_response_and_transaction(notifications_enabled):
    with (
        transaction.atomic(),
        patch('request.notifications.NotificationModel.objects.create', side_effect=DatabaseError('storage failed')),
    ):
        response = EstCertificateRequestContext(http_response_status=403).to_http_response()
        assert response.status_code == 403
        assert NotificationConfig.objects.filter(enabled=True).exists()
    assert not NotificationModel.objects.filter(event='REQUEST_FAILED').exists()


def test_est_pipeline_exception_is_notified(notifications_enabled):
    request = RequestFactory().post('/', b'invalid CSR', content_type='application/pkcs10')
    with patch('request.enrollment.EstHttpRequestValidator.validate', side_effect=ValueError('secret error')):
        response = EstSimpleEnrollmentMixin().process_enrollment(request, 'domain', 'tls_server')
    assert response.status_code == 500
    assert NotificationModel.objects.get(event='REQUEST_FAILED').message_data == {
        'protocol': 'est', 'operation': 'simpleenroll',
    }


def test_cmp_error_with_http_200_notifies_once(notifications_enabled):
    context = CmpCertificateRequestContext(protocol='cmp', operation='initialization', http_response_status=200)
    with patch.object(CmpErrorMessageResponder, '_build_response'):
        CmpErrorMessageResponder.build_response(context)
    assert context.to_http_response().status_code == 200
    context.to_http_response()
    assert NotificationModel.objects.filter(event='REQUEST_FAILED').count() == 1


@pytest.mark.parametrize('status,expected', [(CmpTransactionModel.Status.WAITING, 0),
                                           (CmpTransactionModel.Status.REJECTED, 1),
                                           (CmpTransactionModel.Status.FAILED, 1)])
def test_cmp_workflow_terminal_states_notify(notifications_enabled, status, expected):
    context = CmpCertificateRequestContext(
        protocol='cmp', operation='initialization',
        cmp_transaction=SimpleNamespace(status=status, detail=''),
    )
    with (
        patch.object(CmpTransactionResponder, '_build_transaction_result_message', return_value=object()),
        patch.object(CmpTransactionResponder, '_protect_pki_message'),
        patch('request.message_responder.cmp.encoder.encode', return_value=b'cmp response'),
    ):
        assert CmpTransactionResponder.respond_if_needed(context)
    assert context.to_http_response().status_code == 200
    assert NotificationModel.objects.filter(event='REQUEST_FAILED').count() == expected


@pytest.mark.parametrize('malformed', [True, False])
def test_scep_failures_notify(notifications_enabled, malformed):
    handler = object.__new__(ScepPkiOperationHandler)
    handler.domain = DomainModel.objects.create(unique_name='notification-test')
    message = SimpleNamespace(message_type=MessageType.RENEWAL_REQ, transaction_id='test')
    with (
        patch('scep.handler.parse_pki_message', side_effect=ScepMalformedMessageError('bad') if malformed else None,
              return_value=message),
        patch.object(handler, '_process', side_effect=ScepProtocolError(FailInfo.BAD_REQUEST, 'secret failure')),
        patch.object(handler, '_audit_rejection'),
        patch.object(handler, '_failure_response', return_value=ScepHttpResult(b'failure')),
    ):
        result = handler.handle(b'secret request')
    assert result.status == (400 if malformed else 200)
    notification = NotificationModel.objects.get(event='REQUEST_FAILED')
    assert notification.domain == handler.domain
    assert notification.message_data == {'protocol': 'scep', 'operation': 'unknown' if malformed else 'renewalreq'}
