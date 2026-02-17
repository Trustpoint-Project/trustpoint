# trustpoint/workflows2/management/commands/workflows2_worker.py
from __future__ import annotations

import socket
import time
from typing import Any

from django.core.management.base import BaseCommand
from django.db import close_old_connections, connection
from django.utils import timezone

from workflows2.engine.executor import WorkflowExecutor
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker

from workflows2.models import Workflow2WorkerHeartbeat  # uses your model


class Command(BaseCommand):
    help = "Run workflows2 worker (consumes Workflow2Job queue)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--once", action="store_true", help="Run one tick and exit (debug).")
        parser.add_argument(
            "--wait-migrations-seconds",
            type=int,
            default=180,
            help="Wait for required DB tables before starting (0 = forever).",
        )
        parser.add_argument("--sleep", type=float, default=1.0, help="Sleep between ticks.")
        parser.add_argument("--lease-seconds", type=int, default=30, help="Job lease duration.")
        parser.add_argument("--limit", type=int, default=10, help="Batch size per tick.")

    def _wait_for_tables(self, *, tables: list[str], timeout_seconds: int) -> None:
        start = time.time()
        missing = set(tables)

        while missing:
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                existing = set(connection.introspection.table_names())
                missing = set(tables) - existing
            except Exception:  # noqa: BLE001
                missing = set(tables)

            if not missing:
                return

            if timeout_seconds and (time.time() - start) >= timeout_seconds:
                raise RuntimeError(f"Timed out waiting for migrations/tables: {sorted(missing)}")

            time.sleep(1.0)

    def handle(self, *args: Any, **opts: Any) -> None:
        once = bool(opts["once"])
        wait_seconds = int(opts["wait_migrations_seconds"] or 0)
        sleep_seconds = float(opts["sleep"])
        lease_seconds = int(opts["lease_seconds"])
        batch_limit = int(opts["limit"])

        worker_id = socket.gethostname()

        # Critical: wait until migrations created the required tables
        required_tables = [
            "workflows2_workflow2job",
            "workflows2_workflow2instance",
            "workflows2_workflow2workerheartbeat",
        ]
        self.stdout.write(f"[workflows2_worker] waiting for tables: {', '.join(required_tables)} ...")
        self._wait_for_tables(tables=required_tables, timeout_seconds=wait_seconds)
        self.stdout.write(self.style.SUCCESS("[workflows2_worker] migrations ready."))

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)
        worker = Workflow2DbWorker(
            runtime=runtime,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            batch_limit=batch_limit,
        )

        self.stdout.write(self.style.SUCCESS(
            f"[workflows2_worker] starting id={worker_id} lease={lease_seconds}s batch={batch_limit} sleep={sleep_seconds}s"
        ))

        last_beat = timezone.now()

        while True:
            close_old_connections()

            # heartbeat every 5 seconds
            now = timezone.now()
            if (now - last_beat).total_seconds() >= 5:
                Workflow2WorkerHeartbeat.beat(worker_id)
                last_beat = now

            stats = worker.tick()
            if stats.claimed or stats.recovered:
                self.stdout.write(
                    f"[workflows2_worker] claimed={stats.claimed} processed={stats.processed} "
                    f"next_jobs={stats.created_next_jobs} skipped={stats.skipped} recovered={stats.recovered}"
                )

            if once:
                return

            time.sleep(sleep_seconds)
