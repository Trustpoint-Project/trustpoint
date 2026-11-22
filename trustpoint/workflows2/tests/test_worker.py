# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import MAX_WEBHOOK_TIMEOUT_SECONDS, WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job
from workflows2.services import worker as worker_module
from workflows2.services.dispatch import INLINE_WORKER_LEASE_SECONDS
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import JOB_RETENTION_DAYS, Workflow2DbWorker


YAML_OK = """
schema: trustpoint.workflow.v2
name: Worker test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: done_ok
  steps:
    done_ok:
      type: set
      vars: {}
  flow: []
"""


class WorkerTests(TestCase):
    def test_inline_lease_covers_longest_step(self) -> None:
        """Inline drains cannot renew a heartbeat, so their lease must outlast any step."""
        self.assertGreater(INLINE_WORKER_LEASE_SECONDS, MAX_WEBHOOK_TIMEOUT_SECONDS)

    def test_purges_finished_jobs_past_retention(self) -> None:
        """Only old done jobs are removed; recent history stays available."""
        ir = compile_workflow_yaml(YAML_OK)
        definition = Workflow2Definition.objects.create(
            name='Worker test',
            enabled=True,
            trigger_on=ir['trigger']['on'],
            yaml_text=YAML_OK,
            ir_json=ir,
            ir_hash=ir['meta']['ir_hash'],
        )
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        inst = runtime.create_instance(definition=definition, event={'device': {'common_name': 'dev1'}})
        old_job = Workflow2Job.objects.create(
            instance=inst, kind=Workflow2Job.KIND_RUN, status=Workflow2Job.STATUS_DONE
        )
        new_job = Workflow2Job.objects.create(
            instance=inst, kind=Workflow2Job.KIND_RUN, status=Workflow2Job.STATUS_DONE
        )
        old_failed_job = Workflow2Job.objects.create(
            instance=inst, kind=Workflow2Job.KIND_RUN, status=Workflow2Job.STATUS_FAILED
        )
        Workflow2Job.objects.filter(pk__in=[old_job.pk, old_failed_job.pk]).update(
            updated_at=timezone.now() - timedelta(days=JOB_RETENTION_DAYS + 1)
        )

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id='test-worker')
        with (
            patch.object(worker_module, '_last_purge_at', None),
            patch.object(worker_module.time, 'monotonic', return_value=10.0),
        ):
            worker._purge_old_jobs()
            with patch.object(Workflow2Job.objects, 'filter') as job_filter:
                worker._purge_old_jobs()
            job_filter.assert_not_called()

        self.assertFalse(Workflow2Job.objects.filter(pk=old_job.pk).exists())
        self.assertFalse(Workflow2Job.objects.filter(pk=old_failed_job.pk).exists())
        self.assertTrue(Workflow2Job.objects.filter(pk=new_job.pk).exists())

    def test_worker_claims_and_runs_job(self) -> None:
        ir = compile_workflow_yaml(YAML_OK)
        d = Workflow2Definition.objects.create(
            name='Worker test',
            enabled=True,
            trigger_on=ir['trigger']['on'],
            yaml_text=YAML_OK,
            ir_json=ir,
            ir_hash=ir['meta']['ir_hash'],
        )

        ex = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=ex)
        inst = runtime.create_instance(definition=d, event={'device': {'common_name': 'dev1'}})

        job = Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
            run_after=timezone.now() - timedelta(seconds=1),
        )

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id='test-worker')
        stats = worker.tick()

        job.refresh_from_db()
        inst.refresh_from_db()

        self.assertEqual(stats.claimed, 1)
        self.assertEqual(job.status, Workflow2Job.STATUS_DONE)
        self.assertEqual(inst.status, Workflow2Instance.STATUS_FINISHED)

    def test_worker_skips_terminal_instance(self) -> None:
        ir = compile_workflow_yaml(YAML_OK)
        d = Workflow2Definition.objects.create(
            name='Worker test',
            enabled=True,
            trigger_on=ir['trigger']['on'],
            yaml_text=YAML_OK,
            ir_json=ir,
            ir_hash=ir['meta']['ir_hash'],
        )

        ex = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=ex)
        inst = runtime.create_instance(definition=d, event={'device': {'common_name': 'dev1'}})
        inst.status = Workflow2Instance.STATUS_FINISHED
        inst.save(update_fields=['status', 'updated_at'])

        job = Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
            run_after=timezone.now() - timedelta(seconds=1),
        )

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id='test-worker')
        stats = worker.tick()

        job.refresh_from_db()
        self.assertEqual(stats.claimed, 1)
        self.assertEqual(stats.skipped, 1)
        self.assertEqual(job.status, Workflow2Job.STATUS_DONE)
