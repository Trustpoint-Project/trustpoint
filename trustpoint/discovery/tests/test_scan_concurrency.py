# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Discovery ownership and cancellation over independent PostgreSQL connections."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest.mock import patch

import pytest
from django.db import connection, connections
from django_q.models import OrmQ

from discovery.models import DiscoveryScan
from discovery.services import ScanManager
from discovery.tasks import run_scan

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(connection.vendor != 'postgresql', reason='Requires PostgreSQL concurrency'),
]


@pytest.mark.parametrize('existing_state', [False, True])
def test_concurrent_starts_enqueue_only_one_scan(existing_state):
    if existing_state:
        DiscoveryScan.objects.create(pk=1)
    ready = Barrier(2)

    def start():
        try:
            ready.wait(timeout=10)
            return ScanManager.begin_scan('192.168.1.1', '192.168.1.10')
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(start) for _ in range(2)]
        assert sum(future.result(timeout=15) for future in futures) == 1
    assert DiscoveryScan.objects.count() == 1
    assert OrmQ.objects.count() == 1
    assert ScanManager.get_state()['scan_running']


def test_another_connection_can_observe_and_cancel_running_worker():
    assert ScanManager.begin_scan('192.168.1.1', '192.168.1.10')
    scan_id = str(DiscoveryScan.objects.get(pk=1).scan_id)
    scanning = Event()
    stopped = Event()

    def scan(_start, _end, *, should_stop):
        scanning.set()
        assert stopped.wait(timeout=10)
        assert should_stop()
        return []

    def work():
        try:
            run_scan(scan_id)
        finally:
            connections.close_all()

    with patch('discovery.tasks.OTScanner') as scanner, ThreadPoolExecutor(max_workers=1) as pool:
        scanner.return_value.scan_network.side_effect = scan
        worker = pool.submit(work)
        try:
            assert scanning.wait(timeout=10)
            assert ScanManager.get_state()['scan_running']
            ScanManager.request_stop()
            assert ScanManager.get_state()['stop_pending']
            assert not ScanManager.begin_scan('192.168.2.1', '192.168.2.10')
        finally:
            stopped.set()
        worker.result(timeout=15)

    assert not ScanManager.get_state()['scan_running']
    assert not ScanManager.get_state()['stop_pending']
