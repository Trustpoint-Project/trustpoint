# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Workflow bundle atomicity and definition stability regressions."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection

from management.models.workflows2 import WorkflowExecutionConfig
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job, Workflow2Run
from workflows2.services.definitions import WorkflowDefinitionService
from workflows2.services.dispatch import EventSource, WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.tests.test_persistence import SIMPLE_YAML


@pytest.fixture
def definition(db):
    definition, result = WorkflowDefinitionService().create_definition(enabled=True, yaml_text=SIMPLE_YAML)
    assert result.ok
    config = WorkflowExecutionConfig.load()
    config.mode = WorkflowExecutionConfig.Mode.WORKER
    config.save()
    return definition


@pytest.mark.parametrize('status', ['queued', 'running', 'awaiting', 'paused', 'error'])
def test_definition_edits_are_rejected_until_instances_are_finished(definition, status):
    runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
    instance = runtime.create_instance(definition=definition, event={})
    instance.status = status
    instance.save(update_fields=['status'])
    changed_yaml = SIMPLE_YAML.replace('stop_now', 'new_step')
    updated, result = WorkflowDefinitionService().update_definition(
        definition=definition, enabled=True, yaml_text=changed_yaml,
    )
    assert updated is None
    assert not result.ok
    assert 'unfinished instances' in result.error
    definition.refresh_from_db()
    assert definition.ir_json['workflow']['start'] == 'stop_now'
    definition.ir_json['workflow']['start'] = 'new_step'
    with pytest.raises(ValidationError, match='unfinished instances'):
        definition.save(update_fields=['ir_json'])
    instance.status = Workflow2Instance.STATUS_CANCELLED
    instance.save(update_fields=['status'])
    updated, result = WorkflowDefinitionService().update_definition(
        definition=definition, enabled=True, yaml_text=changed_yaml,
    )
    assert result.ok
    assert updated.ir_json['workflow']['start'] == 'new_step'


def test_dispatch_rolls_back_the_whole_bundle_if_enqueue_fails(definition):
    service = WorkflowDispatchService()
    with patch.object(service, '_enqueue_job', side_effect=RuntimeError('enqueue failed')):
        with pytest.raises(RuntimeError, match='enqueue failed'):
            service.emit_event(on='device.created', event={}, source=EventSource(), idempotency_key='request')
    assert not Workflow2Run.objects.exists()
    assert not Workflow2Instance.objects.exists()
    assert not Workflow2Job.objects.exists()


@pytest.mark.django_db(transaction=True)
def test_concurrent_dispatch_initializes_a_bundle_once(definition):
    if connection.vendor != 'postgresql':
        pytest.skip('Requires PostgreSQL row locks')
    barrier = Barrier(2)

    def dispatch():
        close_old_connections()
        service = WorkflowDispatchService()
        create_run = service.get_or_create_run

        def simultaneous_start(**kwargs):
            barrier.wait(timeout=10)
            return create_run(**kwargs)

        try:
            with patch.object(service, 'get_or_create_run', side_effect=simultaneous_start):
                instances = service.emit_event(
                    on='device.created', event={}, source=EventSource(), idempotency_key='same-request',
                )
            return [instance.pk for instance in instances]
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: dispatch(), range(2)))
    assert results[0] == results[1]
    assert Workflow2Run.objects.count() == 1
    assert Workflow2Instance.objects.count() == 1
    assert Workflow2Job.objects.count() == 1
