# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Effective certificate snapshots and post-success protocol notifications."""

import json
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from django.db import transaction
from django.test import RequestFactory, TestCase

from management.models.workflows2 import WorkflowExecutionConfig
from pki.models.cert_profile import CertificateProfileModel
from request.enrollment import process_workflow_operation
from request.operation_processor.cmp_certificate_request import CmpCertificateRequestProcessor
from request.operation_processor.cmp_poll import CmpPollProcessor
from request.operation_processor.issue_cert import LocalCaCertificateIssueProcessor
from request.profile_validator import ProfileValidator
from request.request_context import (
    CmpCertificateRequestContext,
    CmpPollRequestContext,
    EstCertificateRequestContext,
    RestCertificateRequestContext,
)
from request.workflows2_handler import Workflow2CertificateRequestHandler, Workflow2HandleResult
from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.compiler.errors import CompileError
from workflows2.engine.adapters import WebhookResponse
from workflows2.engine.executor import WorkflowExecutor
from workflows2.events.payloads import build_enrollment_request_snapshot
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Run
from workflows2.services.dispatch import WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


@pytest.fixture
def certificate_factory():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def make(*, subject=None, sans=None):
        if subject is None:
            subject = [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, 'effective-device'),
                x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, 'SN123456'),
            ]
        name = x509.Name(subject)
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(999)
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        )
        if sans is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return builder.sign(key, hashes.SHA256())

    make.key = key
    return make


def make_context(protocol, operation, certificate, csr):
    context_type = {
        'cmp': CmpCertificateRequestContext,
        'est': EstCertificateRequestContext,
        'rest': RestCertificateRequestContext,
    }[protocol]
    extra = {'cmp_transaction_id': 'abcd'} if protocol == 'cmp' else {}
    return context_type(
        protocol=protocol,
        operation=operation,
        raw_message=RequestFactory().post('/enroll', data=b'original request', content_type='application/octet-stream'),
        device=SimpleNamespace(id=44, common_name='stored-device', serial_number='234567'),
        domain=SimpleNamespace(id=1, get_issuing_ca_or_value_error=lambda: SimpleNamespace(id=4)),
        cert_profile_str='domain_credential',
        cert_requested=csr,
        issued_certificate=certificate,
        **extra,
    )


@pytest.fixture
def enrollment_context(certificate_factory):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, 'raw-client-serial'),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName('raw.example.com'),
                ]
            ),
            critical=False,
        )
        .sign(certificate_factory.key, hashes.SHA256())
    )
    return make_context('cmp', 'initialization', certificate_factory(), csr)


def test_snapshot_absent_attributes_and_repeated_rdns(certificate_factory):
    certificate = certificate_factory(
        subject=[
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'first'),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'second'),
        ]
    )
    snapshot = build_enrollment_request_snapshot(certificate)
    assert snapshot == {
        'subject': {
            'common_name': 'first',
            'serial_number': None,
            'organization': None,
            'organizational_unit': None,
            'country': None,
            'state_or_province': None,
            'locality': None,
        },
        'subject_alternative_names': {'dns_names': [], 'ip_addresses': [], 'uris': [], 'email_addresses': []},
    }
    assert json.loads(json.dumps(snapshot)) == snapshot


def test_snapshot_all_subject_fields_and_sans(certificate_factory):
    subject = [
        x509.NameAttribute(oid, value)
        for oid, value in (
            (x509.NameOID.COMMON_NAME, 'effective-device'),
            (x509.NameOID.SERIAL_NUMBER, 'SN123456'),
            (x509.NameOID.ORGANIZATION_NAME, 'Example'),
            (x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'Devices'),
            (x509.NameOID.COUNTRY_NAME, 'DE'),
            (x509.NameOID.STATE_OR_PROVINCE_NAME, 'BW'),
            (x509.NameOID.LOCALITY_NAME, 'Stuttgart'),
        )
    ]
    snapshot = build_enrollment_request_snapshot(
        certificate_factory(
            subject=subject,
            sans=[
                x509.DNSName('plc.example.com'),
                x509.IPAddress(ip_address('192.168.1.10')),
                x509.IPAddress(ip_address('2001:0db8:0000::1')),
                x509.UniformResourceIdentifier('urn:example:plc'),
                x509.RFC822Name('plc@example.com'),
                x509.RegisteredID(x509.ObjectIdentifier('1.2.3.4')),
            ],
        )
    )
    assert list(snapshot['subject'].values()) == [
        'effective-device',
        'SN123456',
        'Example',
        'Devices',
        'DE',
        'BW',
        'Stuttgart',
    ]
    assert snapshot['subject_alternative_names'] == {
        'dns_names': ['plc.example.com'],
        'ip_addresses': ['192.168.1.10', '2001:db8::1'],
        'uris': ['urn:example:plc'],
        'email_addresses': ['plc@example.com'],
    }


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('protocol', 'operation'),
    [
        ('cmp', 'initialization'),
        ('cmp', 'certification'),
        ('cmp', 'keyupdate'),
        ('est', 'simpleenroll'),
        ('est', 'simplereenroll'),
        ('rest', 'enroll'),
        ('rest', 'reenroll'),
    ],
)
def test_protocol_parity_and_snapshot_before_commit(protocol, operation, enrollment_context):
    context = make_context(
        protocol, operation, enrollment_context.issued_certificate, enrollment_context.cert_requested
    )
    handler = Workflow2CertificateRequestHandler()
    with patch('request.workflows2_handler.WorkflowDispatchService') as service:
        with TestCase.captureOnCommitCallbacks(execute=True):
            handler.handle_issued(context)
            service.return_value.emit_event.assert_not_called()
            context.device.serial_number = 'later-device-value'
            context.issued_certificate = None
        kwargs = service.return_value.emit_event.call_args.kwargs
    event = kwargs['event']
    assert kwargs['on'] == f'{protocol}.{operation}'
    assert kwargs['idempotency_key'].startswith('issued:')
    assert event['device']['serial_number'] == '234567'
    assert event['request']['subject']['serial_number'] == 'SN123456'
    assert event['request']['subject_alternative_names']['dns_names'] == []
    assert event[protocol]['operation'] == operation
    assert event['source'] == {'trustpoint': False, 'ca_id': 4, 'domain_id': 1, 'device_id': 44}
    assert json.loads(json.dumps(event)) == event


@pytest.mark.django_db
def test_failed_or_rolled_back_issuance_never_notifies(enrollment_context):
    with patch('request.workflows2_handler.WorkflowDispatchService') as service:
        with pytest.raises(ValueError, match='rollback'), transaction.atomic():
            Workflow2CertificateRequestHandler().handle_issued(enrollment_context)
            raise ValueError('rollback')
        enrollment_context.issued_certificate = None
        Workflow2CertificateRequestHandler().handle_issued(enrollment_context)
        service.assert_not_called()


@pytest.mark.django_db
def test_processing_failure_and_workflow_stop_never_notify(enrollment_context):
    with (
        patch('request.enrollment.Workflow2Handler') as gate,
        patch.object(
            Workflow2CertificateRequestHandler,
            'handle_issued',
        ) as notify,
    ):
        gate.return_value.handle.return_value = Workflow2HandleResult.stop_processing()
        process = Mock()
        process_workflow_operation(enrollment_context, process)
        process.assert_not_called()
        gate.return_value.handle.return_value = Workflow2HandleResult.continue_processing()
        with pytest.raises(ValueError, match='issuance failed'):
            process_workflow_operation(enrollment_context, Mock(side_effect=ValueError('issuance failed')))
        notify.assert_not_called()


@pytest.mark.django_db
def test_notification_failure_preserves_issuance_and_gate_outcome(enrollment_context):
    original_certificate = enrollment_context.issued_certificate
    original_outcome = enrollment_context.workflow2_outcome = object()
    with patch('request.workflows2_handler.WorkflowDispatchService') as service:
        service.return_value.emit_event.side_effect = RuntimeError('webhook failed')
        with TestCase.captureOnCommitCallbacks(execute=True):
            Workflow2CertificateRequestHandler().handle_issued(enrollment_context)
    assert enrollment_context.issued_certificate is original_certificate
    assert enrollment_context.workflow2_outcome is original_outcome
    assert Workflow2Run.objects.count() == 0


@pytest.mark.django_db
def test_malformed_certificate_snapshot_logs_and_skips_notification(enrollment_context):
    certificate = Mock(spec=x509.Certificate)
    certificate.subject.get_attributes_for_oid.side_effect = ValueError('malformed subject')
    enrollment_context.issued_certificate = certificate
    with patch('request.workflows2_handler.WorkflowDispatchService') as service:
        Workflow2CertificateRequestHandler().handle_issued(enrollment_context)
    service.assert_not_called()


def workflow_yaml(*, phase='after_issuance'):
    phase_line = f'  phase: {phase}\n' if phase else ''
    return f"""schema: trustpoint.workflow.v2
name: CMP Effective Subject Serial Number Webhook
enabled: true
trigger:
  on: cmp.initialization
{phase_line}  sources:
    trustpoint: true
    ca_ids: []
    domain_ids: []
    device_ids: []
workflow:
  start: forward_serial
  steps:
    forward_serial:
      type: webhook
      title: Forward effective certificate subject serial number
      method: POST
      url: https://example.invalid/cmp-audit
      headers:
        Content-Type: application/json
      body:
        effective_subject_serial_number: ${{event.request.subject.serial_number}}
        stored_device_serial_number: ${{event.device.serial_number}}
        missing_organization: ${{event.request.subject.organization}}
        operation: ${{event.cmp.operation}}
  flow: []
"""


@pytest.mark.parametrize('phase', ['unknown', 'null', '[]'])
def test_compiler_rejects_invalid_enrollment_phase(phase):
    with pytest.raises(CompileError, match='trigger.phase'):
        compile_workflow_yaml(workflow_yaml(phase=phase))


def test_compiler_restricts_phase_to_enrollment_and_rejects_post_success_approval():
    with pytest.raises(CompileError, match='only supported'):
        compile_workflow_yaml(workflow_yaml().replace('cmp.initialization', 'device.created'))
    with pytest.raises(CompileError, match='Approval is not available'):
        compile_workflow_yaml(
            workflow_yaml().split('workflow:')[0]
            + """workflow:
  start: approve
  steps:
    approve:
      type: approval
      approved_outcome: approved
      rejected_outcome: rejected
"""
        )


def test_documented_effective_serial_workflow_compiles():
    guide = (Path(__file__).resolve().parents[3] / 'docs/source/features/workflows/index.md').read_text()
    example = next(
        block.split('```')[0]
        for block in guide.split('```yaml\n')[1:]
        if 'name: CMP Effective Subject Serial Number Webhook' in block.split('```')[0]
    )
    ir = compile_workflow_yaml(example)
    assert ir['trigger']['phase'] == 'after_issuance'


@pytest.mark.django_db
def test_inline_webhook_failure_is_recorded_without_changing_issuance(enrollment_context):
    cfg = WorkflowExecutionConfig.load()
    cfg.mode = WorkflowExecutionConfig.Mode.INLINE
    cfg.save()
    text = workflow_yaml()
    ir = compile_workflow_yaml(text)
    Workflow2Definition.objects.create(
        name=ir['name'],
        enabled=True,
        trigger_on=ir['trigger']['on'],
        yaml_text=text,
        ir_json=ir,
        ir_hash=ir['meta']['ir_hash'],
    )
    receiver = Mock()
    receiver.request.side_effect = RuntimeError('receiver unavailable')
    service = WorkflowDispatchService(executor=WorkflowExecutor(webhook=receiver))
    certificate = enrollment_context.issued_certificate
    with patch('request.workflows2_handler.WorkflowDispatchService', return_value=service):
        with TestCase.captureOnCommitCallbacks(execute=True):
            Workflow2CertificateRequestHandler().handle_issued(enrollment_context)
    assert enrollment_context.issued_certificate is certificate
    assert enrollment_context.workflow2_outcome is None
    instance = Workflow2Instance.objects.get()
    assert instance.status == Workflow2Instance.STATUS_ERROR
    assert instance.event_json['request']['subject']['serial_number'] == 'SN123456'


@pytest.mark.django_db
def test_delayed_persisted_event_forwards_original_serial_to_controlled_receiver(enrollment_context):
    cfg = WorkflowExecutionConfig.load()
    cfg.mode = WorkflowExecutionConfig.Mode.WORKER
    cfg.save()
    for phase in (None, 'after_issuance'):
        text = workflow_yaml(phase=phase)
        ir = compile_workflow_yaml(text)
        Workflow2Definition.objects.create(
            name=ir['name'],
            enabled=True,
            trigger_on=ir['trigger']['on'],
            yaml_text=text,
            ir_json=ir,
            ir_hash=ir['meta']['ir_hash'],
        )
    handler = Workflow2CertificateRequestHandler()
    # Select only legacy workflows before issuance, without executing them.
    dispatch = handler._build_dispatch_request(enrollment_context)
    matched = WorkflowDispatchService()._select_definitions(
        on=dispatch.on,
        event=dispatch.event,
        source=dispatch.source,
        initial_vars={},
    )
    assert len(matched) == 1
    assert 'phase' not in matched[0].ir_json['trigger']
    with TestCase.captureOnCommitCallbacks(execute=True):
        handler.handle_issued(enrollment_context)
        handler.handle_issued(enrollment_context)
    instance = Workflow2Instance.objects.get()
    assert instance.status == Workflow2Instance.STATUS_QUEUED
    enrollment_context.device.serial_number = 'changed'
    enrollment_context.issued_certificate = None
    instance.refresh_from_db()
    assert instance.event_json == instance.run.event_json
    assert instance.event_json['request']['subject']['serial_number'] == 'SN123456'
    receiver = Mock()
    receiver.request.return_value = WebhookResponse(status_code=200, body={}, headers={})
    runtime = WorkflowRuntimeService(executor=WorkflowExecutor(webhook=receiver))
    worker = Workflow2DbWorker(runtime=runtime, worker_id='enrollment-test', heartbeat_enabled=False)
    worker.tick()
    assert receiver.request.call_args.kwargs['body'] == {
        'effective_subject_serial_number': 'SN123456',
        'stored_device_serial_number': '234567',
        'missing_organization': '',
        'operation': 'initialization',
    }
    instance.refresh_from_db()
    assert instance.status == Workflow2Instance.STATUS_FINISHED


@pytest.mark.django_db
@pytest.mark.integration
def test_cmp_webhook_delivers_to_local_http_receiver(enrollment_context):
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{}')

        def log_message(self, *_args):
            pass

    with HTTPServer(('127.0.0.1', 0), Receiver) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = WorkflowExecutionConfig.load()
            cfg.mode = WorkflowExecutionConfig.Mode.WORKER
            cfg.save()
            text = workflow_yaml().replace(
                'https://example.invalid/cmp-audit',
                f'http://127.0.0.1:{server.server_port}/cmp-audit',
            )
            ir = compile_workflow_yaml(text)
            Workflow2Definition.objects.create(
                name=ir['name'],
                enabled=True,
                trigger_on=ir['trigger']['on'],
                yaml_text=text,
                ir_json=ir,
                ir_hash=ir['meta']['ir_hash'],
            )
            with TestCase.captureOnCommitCallbacks(execute=True):
                Workflow2CertificateRequestHandler().handle_issued(enrollment_context)
            worker = Workflow2DbWorker(
                runtime=WorkflowRuntimeService(executor=WorkflowExecutor()),
                worker_id='local-http-test',
                heartbeat_enabled=False,
            )
            worker.tick()
            assert received == [
                {
                    'effective_subject_serial_number': 'SN123456',
                    'stored_device_serial_number': '234567',
                    'missing_organization': '',
                    'operation': 'initialization',
                }
            ]
        finally:
            server.shutdown()
            thread.join(timeout=5)


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('protocol', 'operation'),
    [
        ('cmp', 'initialization'),
        ('cmp', 'certification'),
        ('cmp', 'keyupdate'),
        ('est', 'simpleenroll'),
        ('est', 'simplereenroll'),
        ('rest', 'enroll'),
        ('rest', 'reenroll'),
    ],
)
@pytest.mark.parametrize('remove_serial', [False, True])
def test_actual_profile_processing_and_issuance_snapshot(
    protocol,
    operation,
    remove_serial,
    device_instance,
    enrollment_context,
):
    """Real profile validation and signing supply the post-success snapshot."""
    profile = {
        'type': 'cert_profile',
        'subj': {'cn': 'effective-device'},
        'ext': {'san': {'dns_names': ['effective.example.com']}},
        'validity': {'days': 1},
    }
    if not remove_serial:
        profile['subj']['serial_number'] = 'SN123456'
    context = make_context(protocol, operation, None, enrollment_context.cert_requested)
    context.device = device_instance['device']
    context.device.serial_number = '234567'
    context.device.save(update_fields=['serial_number'])
    context.domain = device_instance['domain']
    context.certificate_profile_model = CertificateProfileModel.objects.create(
        unique_name='workflow_effective',
        profile_json=json.dumps(profile),
    )
    ProfileValidator.validate(context)
    with (
        patch('request.enrollment.Workflow2Handler') as gate,
        patch(
            'request.workflows2_handler.WorkflowDispatchService',
        ) as service,
    ):
        gate.return_value.handle.return_value = Workflow2HandleResult.continue_processing()
        with TestCase.captureOnCommitCallbacks(execute=True):
            process_workflow_operation(context, LocalCaCertificateIssueProcessor().process_operation)
        event = service.return_value.emit_event.call_args.kwargs['event']
    assert context.issued_certificate is not None
    assert event['request']['subject']['serial_number'] == (None if remove_serial else 'SN123456')
    assert event['request']['subject_alternative_names']['dns_names'] == ['effective.example.com']
    assert event['device']['serial_number'] == '234567'
    assert event['request'] == build_enrollment_request_snapshot(context.issued_certificate)


@pytest.mark.django_db
def test_cmp_poll_completion_notifies_with_original_replayed_context(enrollment_context):
    """The approval/poll path captures the effective certificate after finalization."""
    context = CmpPollRequestContext(cmp_transaction=SimpleNamespace(pk=1))
    with (
        patch.object(CmpCertificateRequestProcessor, 'build_replay_context', return_value=enrollment_context),
        patch(
            'request.operation_processor.cmp_poll.CertificateIssueProcessor.process_operation',
        ),
        patch.object(CmpCertificateRequestProcessor, 'mark_transaction_issued'),
        patch.object(
            CmpCertificateRequestProcessor,
            'populate_success_context',
        ),
        patch('request.workflows2_handler.WorkflowDispatchService') as service,
    ):
        with TestCase.captureOnCommitCallbacks(execute=True):
            CmpPollProcessor()._finalize_transaction(context)
    event = service.return_value.emit_event.call_args.kwargs['event']
    assert event['request']['subject']['serial_number'] == 'SN123456'
    assert event['cmp']['operation'] == 'initialization'
