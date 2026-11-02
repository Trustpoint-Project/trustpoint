# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Persisted workflow execution limits apply to every runtime entry point."""

from unittest.mock import Mock

import pytest

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job, Workflow2Run, Workflow2StepRun
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


LOOP_YAML = """
schema: trustpoint.workflow.v2
name: Execution limit
trigger:
  on: device.created
  sources:
    trustpoint: true
workflow:
  start: repeat
  steps:
    repeat:
      type: set
      vars: {}
  flow:
    - from: repeat
      to: repeat
"""


@pytest.fixture
def definition():
    ir = compile_workflow_yaml(LOOP_YAML)
    return Workflow2Definition.objects.create(
        name='Execution limit',
        trigger_on='device.created',
        yaml_text=LOOP_YAML,
        ir_json=ir,
        ir_hash=ir['meta']['ir_hash'],
    )


@pytest.mark.django_db
@pytest.mark.parametrize('mode', ['worker', 'single_step', 'instance'])
@pytest.mark.parametrize('limit', [0, 2])
def test_loop_stops_at_persisted_limit(definition, mode, limit):
    executor = Mock(wraps=WorkflowExecutor())
    runtime = WorkflowRuntimeService(executor=executor, max_steps_per_run=limit)
    run = Workflow2Run.objects.create(trigger_on='device.created', event_json={})
    instance = runtime.create_instance(definition=definition, event={}, run=run)

    if mode == 'worker':
        Workflow2Job.objects.create(instance=instance)
        worker = Workflow2DbWorker(runtime=runtime, worker_id='limit-test', batch_limit=1)
        for _ in range(limit + 3):
            worker.tick()
        assert not Workflow2Job.objects.filter(
            instance=instance,
            status__in=[Workflow2Job.STATUS_QUEUED, Workflow2Job.STATUS_RUNNING],
        ).exists()
        worker.resume_instance(instance=instance)
        worker.tick()
    elif mode == 'single_step':
        for _ in range(limit + 3):
            result = runtime.run_one_step(instance)
        assert result.terminal
        assert result.run.status == 'error'
    else:
        for _ in range(limit):
            runtime.run_one_step(instance)
        returned = runtime.run_instance(instance)
        assert returned.status == Workflow2Instance.STATUS_ERROR

    instance.refresh_from_db()
    run.refresh_from_db()
    assert instance.status == Workflow2Instance.STATUS_ERROR
    assert instance.status_reason == 'max_steps_exceeded'
    assert instance.run_count == limit
    assert run.status == Workflow2Run.STATUS_ERROR
    assert executor.execute_single_step.call_count == limit
    assert Workflow2StepRun.objects.filter(instance=instance).count() == limit


@pytest.mark.django_db
def test_workflow_can_finish_at_limit(definition):
    definition.ir_json['workflow']['transitions'] = {}
    definition.save(update_fields=['ir_json'])
    runtime = WorkflowRuntimeService(executor=WorkflowExecutor(), max_steps_per_run=1)
    instance = runtime.create_instance(definition=definition, event={})

    result = runtime.run_instance(instance)

    assert result.status == Workflow2Instance.STATUS_FINISHED
    assert result.run_count == 1
