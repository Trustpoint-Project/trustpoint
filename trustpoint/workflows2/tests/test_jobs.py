from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job


class JobModelTests(TestCase):
    def setUp(self) -> None:
        self.defn = Workflow2Definition.objects.create(
            name="t",
            enabled=True,
            trigger_on="device.created",
            yaml_text="x",
            ir_json={"dummy": True},
            ir_hash="h",
        )

    def test_instance_defaults_to_queued(self) -> None:
        inst = Workflow2Instance.objects.create(
            definition=self.defn,
            event_json={"device": {"id": "1"}},
            vars_json={},
        )
        self.assertEqual(inst.status, Workflow2Instance.STATUS_QUEUED)

    def test_job_retry_backoff_increases_run_after(self) -> None:
        inst = Workflow2Instance.objects.create(
            definition=self.defn,
            event_json={"device": {"id": "1"}},
            vars_json={},
        )

        job = Workflow2Job.objects.create(instance=inst, kind=Workflow2Job.KIND_RUN)

        before = timezone.now()
        job.schedule_retry(error="boom")
        job.save()

        self.assertEqual(job.attempts, 1)
        self.assertEqual(job.status, Workflow2Job.STATUS_QUEUED)
        self.assertIsNotNone(job.last_error)
        self.assertGreaterEqual(job.run_after, before)

        # second retry should push further out
        first_after = job.run_after
        job.schedule_retry(error="boom2")
        job.save()
        self.assertEqual(job.attempts, 2)
        self.assertGreater(job.run_after, first_after)
