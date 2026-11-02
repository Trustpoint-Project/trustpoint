# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Coordinate network scans across web and background worker processes."""

from datetime import timedelta
from ipaddress import IPv4Address
from typing import Any
from uuid import uuid4

from django.db import transaction
from django.utils import timezone
from django_q.conf import Conf
from django_q.tasks import async_task

from discovery.models import DiscoveryScan

SCAN_TIMEOUT_SECONDS = Conf.TIMEOUT if Conf.TIMEOUT and Conf.TIMEOUT > 0 else 120


class ScanManager:
    """Manage one active scan using database state and the existing ORM job queue."""

    @staticmethod
    def _expire_crashed_scan() -> None:
        # Django-Q kills timed-out workers; allow its termination buffer before releasing ownership.
        cutoff = timezone.now() - timedelta(seconds=SCAN_TIMEOUT_SECONDS + 10)
        DiscoveryScan.objects.filter(pk=1, is_running=True, started_at__lte=cutoff).update(
            is_running=False,
            stop_pending=False,
            started_at=None,
        )

    @classmethod
    @transaction.atomic
    def begin_scan(cls, start_ip: str, end_ip: str) -> bool:
        """Atomically reserve and enqueue a scan unless another scan is active."""
        start, end = IPv4Address(start_ip), IPv4Address(end_ip)
        if start > end:
            msg = 'The end address must not precede the start address.'
            raise ValueError(msg)
        cls._expire_crashed_scan()
        DiscoveryScan.objects.get_or_create(pk=1)
        scan_id = uuid4()
        claimed = DiscoveryScan.objects.filter(pk=1, is_running=False).update(
            scan_id=scan_id,
            is_running=True,
            stop_pending=False,
            started_at=None,
            start_ip=str(start),
            end_ip=str(end),
        )
        if not claimed:
            return False
        async_task('discovery.tasks.run_scan', str(scan_id), timeout=SCAN_TIMEOUT_SECONDS, ack_failure=True)
        return True

    @staticmethod
    @transaction.atomic
    def request_stop() -> None:
        """Signal a running worker or cancel a scan that has not started yet."""
        DiscoveryScan.objects.filter(pk=1, is_running=True).update(stop_pending=True)
        DiscoveryScan.objects.filter(pk=1, is_running=True, started_at__isnull=True).update(
            is_running=False,
            stop_pending=False,
        )

    @classmethod
    def get_state(cls) -> dict[str, Any]:
        """Read the same scan state from every web process."""
        cls._expire_crashed_scan()
        state, _created = DiscoveryScan.objects.get_or_create(pk=1)
        return {
            'scan_running': state.is_running,
            'stop_pending': state.stop_pending,
            'start_ip': state.start_ip,
            'end_ip': state.end_ip,
        }
