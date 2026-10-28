# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify demo installation, editor data, and executable examples."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.management import call_command
from django.test import RequestFactory, TestCase

from management.models.workflows2 import WorkflowExecutionConfig
from request.request_context import CmpCertificateRequestContext
from request.workflows2_handler import Workflow2CertificateRequestHandler
from workflows2.compiler.errors import CompileError
from workflows2.compiler.yaml_format import dump_yaml_text, parse_yaml_text
from workflows2.engine.adapters import WebhookResponse
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import (
    Workflow2Approval, Workflow2Definition, Workflow2DefinitionUiState,
    Workflow2Instance, Workflow2Job, Workflow2Run,
)
from workflows2.services.definitions import WorkflowDefinitionService
from workflows2.services.demo import DEMO_WORKFLOWS_PATH, install_demo_workflows
from workflows2.services.dispatch import EventSource, WorkflowDispatchService
from workflows2.services.graph import WorkflowGraphService
from workflows2.services.runtime import WorkflowRuntimeService

pytestmark = pytest.mark.django_db


@pytest.fixture
def demos():
    assert install_demo_workflows() == 4


def definition(name):
    return Workflow2Definition.objects.get(name=f'[Demo] {name}')


def test_installation_is_create_only_even_after_rename(demos):
    workflow = definition('Enrollment approval')
    source = parse_yaml_text(workflow.yaml_text)
    source['name'] = 'My modified workflow'
    source['workflow']['steps']['review']['timeout_seconds'] = 7200
    _, result = WorkflowDefinitionService().update_definition(
        definition=workflow, enabled=False, yaml_text=dump_yaml_text(source),
    )
    assert result.ok
    before = list(Workflow2Definition.objects.order_by('pk').values())
    layouts_before = list(Workflow2DefinitionUiState.objects.order_by('pk').values())
    assert install_demo_workflows() == 0
    assert list(Workflow2Definition.objects.order_by('pk').values()) == before
    assert list(Workflow2DefinitionUiState.objects.order_by('pk').values()) == layouts_before
    assert Workflow2Run.objects.count() == Workflow2Instance.objects.count() == Workflow2Job.objects.count() == 0
    assert Workflow2Approval.objects.count() == 0


def test_invalid_fixture_rolls_back_entire_installation(tmp_path, monkeypatch):
    valid_yaml = (DEMO_WORKFLOWS_PATH / 'enrollment_approval.yaml').read_text()
    (tmp_path / 'a_valid.yaml').write_text(valid_yaml)
    (tmp_path / 'z_invalid.yaml').write_text('schema: invalid')
    monkeypatch.setattr('workflows2.services.demo.DEMO_WORKFLOWS_PATH', tmp_path)
    with pytest.raises(CompileError, match='Invalid demo workflow z_invalid.yaml'):
        install_demo_workflows()
    assert not Workflow2Definition.objects.exists()
    assert not Workflow2DefinitionUiState.objects.exists()


def test_every_demo_compiles_and_has_description_scope_and_graph(demos):
    for workflow in Workflow2Definition.objects.all():
        compiled = WorkflowDefinitionService().compile_yaml(workflow.yaml_text)
        assert compiled.ok, compiled.error
        assert compiled.ir == workflow.ir_json
        assert workflow.yaml_text.startswith('# ')
        assert compiled.ir['trigger']['on'] == 'cmp.initialization'
        assert compiled.ir['trigger']['sources']['trustpoint']
        assert compiled.ir['trigger']['sources']['domain_ids'] == []
        graph = WorkflowGraphService().definition_graph(definition=workflow)
        step_ids = {node['id'] for node in graph['nodes']}
        assert all(edge['from'] in step_ids and edge['to'] in step_ids for edge in graph['edges'])
        assert bool(graph['edges']) or len(step_ids) == 1
    assert not Workflow2DefinitionUiState.objects.exists()


def test_demo_command_installs_workflows_last():
    # Skip expensive CA generation; all pre-existing demo objects take the skip paths.
    module = 'pki.management.commands.add_domains_and_devices'
    with patch(f'{module}.call_command') as nested_command, patch(
        'workflows2.services.demo.install_demo_workflows', return_value=4,
    ) as install:
        with patch(f'{module}.CaModel') as ca, patch(f'{module}.TruststoreModel'), patch(
            f'{module}.DomainModel',
        ) as domain, patch(f'{module}.DevIdRegistration') as registration, patch(
            f'{module}.SignerModel',
        ), patch(f'{module}.DeviceModel'):
            ca.objects.filter.return_value.exists.return_value = True
            domain.objects.get_or_create.return_value = (Mock(), False)
            registration.objects.get_or_create.return_value = (Mock(), False)
            call_command('add_domains_and_devices', stdout=Mock())
        nested_command.assert_called_once_with('import_idevid_truststores')
        install.assert_called_once_with()


@pytest.mark.parametrize('decision', ['approved', 'rejected'])
def test_manual_approval_gates_real_enrollment_trigger(demos, decision):
    cfg = WorkflowExecutionConfig.load()
    cfg.mode = WorkflowExecutionConfig.Mode.WORKER
    cfg.save()
    service = WorkflowDispatchService()
    source = EventSource(trustpoint=False, domain_id=123)
    instances = service.emit_event(on='cmp.initialization', event={'cmp': {'cert_profile': 'tls_client'}}, source=source)
    assert len(instances) == 2
    instance = next(item for item in instances if item.definition_id == definition('Enrollment approval').pk)
    run = instance.run
    runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
    for item in instances:
        runtime.run_instance(item)
    instance.refresh_from_db()
    assert instance.status == 'awaiting'
    runtime.resolve_approval(approval=instance.approvals.get(), decision=decision, decided_by='demo-operator')
    runtime.run_instance(instance)
    instance.refresh_from_db()
    assert instance.status == decision
    runtime.recompute_run_status(run)
    run.refresh_from_db()
    assert run.status == decision


def test_approval_timeout_fails_enrollment(demos):
    runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
    instance = runtime.create_instance(definition=definition('Enrollment approval'), event={})
    runtime.run_instance(instance)
    approval = instance.approvals.get()
    approval.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    approval.save()
    result = runtime.resolve_approval(approval=approval, decision='approved')
    assert result.expired
    runtime.run_instance(instance)
    instance.refresh_from_db()
    assert instance.status == 'timed_out'


@pytest.mark.parametrize(('profile', 'status'), [('tls_client', 'approved'), ('tls_server', 'awaiting')])
def test_conditional_enrollment_branches(demos, profile, status):
    runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
    instance = runtime.create_instance(
        definition=definition('Conditional enrollment approval'), event={'cmp': {'cert_profile': profile}},
    )
    runtime.run_instance(instance)
    instance.refresh_from_db()
    assert instance.status == status


@pytest.mark.parametrize('domain_id', [123, 456])
def test_cmp_matches_any_domain_and_notifications_start_disabled(demos, domain_id):
    cfg = WorkflowExecutionConfig.load()
    cfg.mode = WorkflowExecutionConfig.Mode.WORKER
    cfg.save()
    service = WorkflowDispatchService()
    source = EventSource(trustpoint=False, domain_id=domain_id)
    instances = service.emit_event(
        on='cmp.initialization', event={'cmp': {'cert_profile': 'tls_client'}}, source=source,
    )
    assert len(instances) == 2
    assert service.emit_event(on='cmp.initialization', event={'phase': 'after_issuance'}, source=source) == []
    assert service.emit_event(on='est.simpleenroll', event={}, source=source) == []
    assert not definition('Final certificate webhook').enabled
    assert not definition('Issued certificate email').enabled


def issued_context(*, serial):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = [x509.NameAttribute(x509.NameOID.COMMON_NAME, 'final-cn')]
    if serial is not None:
        subject.append(x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, serial))
    name = x509.Name(subject)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(123456)
        .not_valid_before(datetime.now(UTC)).not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, 'csr-value'),
    ])).sign(key, hashes.SHA256())
    return CmpCertificateRequestContext(
        protocol='cmp', operation='initialization', cert_requested=csr, issued_certificate=certificate,
        raw_message=RequestFactory().post('/cmp', data=b'cmp-request', content_type='application/pkixcmp'),
        cert_profile_str='tls_client',
        domain=SimpleNamespace(id=123, get_issuing_ca_or_value_error=lambda: SimpleNamespace(id=7)),
        device=SimpleNamespace(id=55, common_name='stored-cn', serial_number='stored-value'),
    )


@pytest.mark.parametrize('serial', ['final-value', None])
@pytest.mark.parametrize(('http_status', 'status'), [(200, 'finished'), (299, 'finished'), (300, 'stopped'), (500, 'stopped')])
def test_webhook_forwards_final_certificate_snapshot_after_commit(demos, serial, http_status, status):
    workflow = definition('Final certificate webhook')
    WorkflowDefinitionService().update_definition(definition=workflow, enabled=True, yaml_text=workflow.yaml_text)
    cfg = WorkflowExecutionConfig.load()
    cfg.mode = WorkflowExecutionConfig.Mode.WORKER
    cfg.save()
    context = issued_context(serial=serial)
    with TestCase.captureOnCommitCallbacks(execute=True):
        Workflow2CertificateRequestHandler().handle_issued(context)
        assert not Workflow2Run.objects.exists()
    run = Workflow2Run.objects.get()
    assert run.event_json['request']['subject']['serial_number'] == serial
    # Changing the context later must not affect delayed execution.
    context.issued_certificate = None
    context.device.serial_number = 'changed'
    webhook = Mock()
    webhook.request.return_value = WebhookResponse(status_code=http_status, body={}, headers={})
    runtime = WorkflowRuntimeService(executor=WorkflowExecutor(webhook=webhook))
    instance = Workflow2Instance.objects.get(run=run)
    runtime.run_instance(instance)
    assert webhook.request.call_args.kwargs['body'] == {
        'common_name': 'final-cn', 'subject_serial_number': serial or '', 'device_id': '55', 'profile': 'tls_client',
    }
    instance.refresh_from_db()
    assert instance.status == status


def test_email_sends_final_certificate_attributes(demos):
    from django.core import mail
    from django.test import override_settings

    context = issued_context(serial='final-email-serial')
    with patch('request.workflows2_handler.WorkflowDispatchService') as dispatch:
        with TestCase.captureOnCommitCallbacks(execute=True):
            Workflow2CertificateRequestHandler().handle_issued(context)
    event = dispatch.return_value.emit_event.call_args.kwargs['event']
    with override_settings(MAILERS={'default': {'BACKEND': 'django.core.mail.backends.locmem.EmailBackend'}}):
        result = WorkflowExecutor().run(definition('Issued certificate email').ir_json, event=event, vars={})
    assert result.status == 'finished'
    assert len(mail.outbox) == 1
    assert 'final-email-serial' in mail.outbox[0].body
    assert 'final-cn' in mail.outbox[0].body
    assert 'csr-value' not in mail.outbox[0].body

