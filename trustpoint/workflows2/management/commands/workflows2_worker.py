"""Run the Workflow 2 background worker via Django's management command entrypoint."""

from __future__ import annotations

import socket
import time
from typing import Any

from django.core.management.base import BaseCommand
from django.db import close_old_connections, connection
from django.utils import timezone

from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2WorkerHeartbeat
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker

HEARTBEAT_INTERVAL_SECONDS = 5


class Command(BaseCommand):
    """Consume queued Workflow 2 jobs with the dedicated worker loop."""

    help = 'Run workflows2 worker (consumes Workflow2Job queue).'

    def add_arguments(self, parser: Any) -> None:
        """Register CLI arguments for the workflows2 worker."""
        parser.add_argument('--once', action='store_true', help='Run one tick and exit (debug).')
        parser.add_argument('--id', type=str, default='', help='Worker id (default: hostname).')
        parser.add_argument('--lease', type=int, default=30, help='Lease seconds (legacy alias).')
        parser.add_argument('--batch', type=int, default=10, help='Batch size (legacy alias).')
        parser.add_argument('--sleep', type=float, default=1.0, help='Sleep between ticks.')
        parser.add_argument('--lease-seconds', type=int, default=None, help='Job lease duration.')
        parser.add_argument('--limit', type=int, default=None, help='Batch size per tick.')
        parser.add_argument(
            '--wait-migrations-seconds',
            type=int,
            default=180,
            help='Wait for required DB tables before starting (0 = forever).',
        )

    def _wait_for_tables(self, *, tables: list[str], timeout_seconds: int) -> None:
        """Wait until the required workflow tables exist."""
        start = time.time()
        missing = set(tables)

        while missing:
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT 1')
                existing = set(connection.introspection.table_names())
                missing = set(tables) - existing
            except Exception:  # noqa: BLE001
                missing = set(tables)

            if not missing:
                return

            if timeout_seconds and (time.time() - start) >= timeout_seconds:
                msg = f'Timed out waiting for migrations/tables: {sorted(missing)}'
                raise RuntimeError(msg)

            time.sleep(1.0)

    def handle(self, *_args: Any, **opts: Any) -> None:
        """Run the workflows2 worker loop until interrupted or `--once` completes."""
        once = bool(opts['once'])
        wait_seconds = int(opts['wait_migrations_seconds'] or 0)
        lease_seconds = int(opts['lease_seconds'] if opts['lease_seconds'] is not None else opts['lease'])
        batch_limit = int(opts['limit'] if opts['limit'] is not None else opts['batch'])
        sleep_seconds = float(opts['sleep'])
        worker_id = (opts.get('id') or '').strip() or socket.gethostname()

        required_tables = [
            'workflows2_workflow2job',
            'workflows2_workflow2instance',
            'workflows2_workflow2workerheartbeat',
        ]
        self.stdout.write(f'[workflows2_worker] worker_id={worker_id}')
        self.stdout.write(f"[workflows2_worker] waiting for tables: {', '.join(required_tables)} ...")
        self._wait_for_tables(tables=required_tables, timeout_seconds=wait_seconds)
        self.stdout.write(self.style.SUCCESS('[workflows2_worker] migrations ready.'))

        self.stdout.write('[workflows2_worker] writing initial heartbeat ...')
        Workflow2WorkerHeartbeat.beat(worker_id)
        self.stdout.write(self.style.SUCCESS('[workflows2_worker] initial heartbeat written.'))

        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        worker = Workflow2DbWorker(
            runtime=runtime,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            batch_limit=batch_limit,
        )
        self.stdout.write(
            self.style.SUCCESS(
                '[workflows2_worker] '
                f'starting id={worker_id} lease={lease_seconds}s '
                f'batch={batch_limit} sleep={sleep_seconds}s'
            )
        )

        last_beat = timezone.now()
        while True:
            close_old_connections()

            now = timezone.now()
            if (now - last_beat).total_seconds() >= HEARTBEAT_INTERVAL_SECONDS:
                Workflow2WorkerHeartbeat.beat(worker_id)
                last_beat = now

            try:
                stats = worker.tick()
            except Exception as exc:  # noqa: BLE001
                self.stderr.write(
                    self.style.ERROR(
                        f'[workflows2_worker] tick() crashed: {type(exc).__name__}: {exc}'
                    )
                )
                time.sleep(sleep_seconds)
                continue

            if stats.claimed or stats.recovered:
                self.stdout.write(
                    f'[workflows2_worker] claimed={stats.claimed} processed={stats.processed} '
                    f'next_jobs={stats.created_next_jobs} skipped={stats.skipped} '
                    f'recovered={stats.recovered}'
                )

            if once:
                return

            time.sleep(sleep_seconds)
