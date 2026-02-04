# workflows2/management/commands/workflows2_worker.py
from __future__ import annotations

import time
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from workflows2.engine.executor import WorkflowExecutor
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


class Command(BaseCommand):
    help = "Run the DB-backed workflows2 worker (no external infra)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--once", action="store_true", help="Process at most one tick and exit.")
        parser.add_argument("--sleep", type=float, default=1.0, help="Sleep seconds between ticks.")
        parser.add_argument("--lease-seconds", type=int, default=30, help="Job lease duration.")
        parser.add_argument("--limit", type=int, default=10, help="Jobs processed per tick.")

    def handle(self, *args: Any, **opts: Any) -> None:
        once: bool = bool(opts["once"])
        sleep_s: float = float(opts["sleep"])
        lease_seconds: int = int(opts["lease_seconds"])
        limit: int = int(opts["limit"])

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)
        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=lease_seconds, batch_limit=limit)

        self.stdout.write(self.style.SUCCESS("workflows2 worker started"))
        try:
            while True:
                stats = worker.tick()
                if stats.claimed:
                    now = timezone.now().isoformat(timespec="seconds")
                    self.stdout.write(
                        f"[{now}] claimed={stats.claimed} done={stats.done} retried={stats.retried} failed={stats.failed} skipped={stats.skipped}"
                    )

                if once:
                    break

                time.sleep(sleep_s)
        except KeyboardInterrupt:
            self.stdout.write("\nExiting.")
