# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared scan reservations, cancellation, and background inventory writes."""

from datetime import timedelta
from unittest.mock import patch, sentinel

import pytest
from django.utils import timezone
from django_q.exceptions import TimeoutException
from django_q.models import OrmQ

from discovery.models import DiscoveredDevice, DiscoveryPort, DiscoveryScan
from discovery.services import SCAN_TIMEOUT_SECONDS, ScanManager
from discovery.tasks import run_scan

pytestmark = pytest.mark.django_db


@pytest.fixture
def queued_scan():
    with patch('discovery.services.async_task'):
        assert ScanManager.begin_scan('192.168.1.1', '192.168.1.100')
    return DiscoveryScan.objects.get(pk=1)


def test_scan_reservation_enqueues_only_once():
    assert ScanManager.begin_scan('192.168.1.1', '192.168.1.100')
    assert not ScanManager.begin_scan('192.168.2.1', '192.168.2.100')
    state = DiscoveryScan.objects.get(pk=1)
    task = OrmQ.objects.get().task
    assert task['func'] == 'discovery.tasks.run_scan'
    assert task['args'] == (str(state.scan_id),)
    assert task['timeout'] == SCAN_TIMEOUT_SECONDS
    assert task['ack_failure']
    assert ScanManager.get_state() == {
        'scan_running': True,
        'stop_pending': False,
        'start_ip': '192.168.1.1',
        'end_ip': '192.168.1.100',
    }


def test_enqueue_failure_rolls_back_reservation():
    with patch('discovery.services.async_task', side_effect=RuntimeError('Queue unavailable')):
        with pytest.raises(RuntimeError, match='Queue unavailable'):
            ScanManager.begin_scan('192.168.1.1', '192.168.1.100')
    assert not DiscoveryScan.objects.filter(is_running=True).exists()


def test_cancel_queued_scan_does_not_cancel_newer_scan(queued_scan):
    ScanManager.request_stop()
    assert not ScanManager.get_state()['scan_running']
    with patch('discovery.services.async_task'):
        assert ScanManager.begin_scan('192.168.2.1', '192.168.2.10')
    with patch('discovery.tasks.OTScanner') as scanner:
        run_scan(str(queued_scan.scan_id))
    scanner.assert_not_called()
    assert ScanManager.get_state()['scan_running']
    assert ScanManager.get_state()['start_ip'] == '192.168.2.1'


def test_scan_task_persists_inventory_and_cannot_run_twice(queued_scan):
    DiscoveryPort.objects.create(port_number=443, description='HTTPS')

    def scan(start, end, *, should_stop):
        assert (start, end) == ('192.168.1.1', '192.168.1.100')
        assert not should_stop()
        run_scan(str(queued_scan.scan_id))
        return [{'ip': '192.168.1.50', 'hostname': 'plc', 'ports': [443], 'ssl_info': {'ssl_open': True}}]

    with patch('discovery.tasks.OTScanner') as scanner:
        scanner.return_value.scan_network.side_effect = scan
        run_scan(str(queued_scan.scan_id))
        run_scan(str(queued_scan.scan_id))
    scanner.assert_called_once_with(target_ports=[443])
    device = DiscoveredDevice.objects.get(ip_address='192.168.1.50')
    assert device.hostname == 'plc'
    assert device.open_ports == [443]
    assert device.ssl_info == {'ssl_open': True}
    assert not ScanManager.get_state()['scan_running']


def test_running_scan_observes_shared_cancellation_and_skips_results(queued_scan):
    def scan(_start, _end, *, should_stop):
        ScanManager.request_stop()
        assert ScanManager.get_state()['stop_pending']
        assert should_stop()
        return [{'ip': '192.168.1.50', 'ports': [443], 'ssl_info': {}}]

    with patch('discovery.tasks.OTScanner') as scanner:
        scanner.return_value.scan_network.side_effect = scan
        run_scan(str(queued_scan.scan_id))
    assert not DiscoveredDevice.objects.exists()
    assert not ScanManager.get_state()['scan_running']
    assert not ScanManager.get_state()['stop_pending']


def test_certificate_object_is_saved_and_removed_from_json(queued_scan):
    result = {
        'ip': '192.168.1.60',
        'ports': [443],
        'ssl_info': {'ssl_open': True, 'cert_object': sentinel.cert},
    }
    with (
        patch('discovery.tasks.OTScanner') as scanner,
        patch('discovery.tasks.CertificateModel.save_certificate', return_value=sentinel.saved) as save,
        patch('discovery.tasks.DiscoveredDevice.objects.update_or_create') as update,
    ):
        scanner.return_value.scan_network.return_value = [result]
        run_scan(str(queued_scan.scan_id))
    save.assert_called_once_with(sentinel.cert)
    assert update.call_args.kwargs['defaults']['certificate_record'] is sentinel.saved
    assert update.call_args.kwargs['defaults']['ssl_info'] == {'ssl_open': True}


def test_certificate_save_failure_does_not_lose_discovered_device(queued_scan):
    def fail(_certificate):
        DiscoveryPort.objects.create(port_number=443, description='duplicate')

    DiscoveryPort.objects.create(port_number=443, description='HTTPS')
    with (
        patch('discovery.tasks.OTScanner') as scanner,
        patch('discovery.tasks.CertificateModel.save_certificate', side_effect=fail),
    ):
        scanner.return_value.scan_network.return_value = [
            {
                'ip': '192.168.1.60',
                'ports': [443],
                'ssl_info': {'ssl_open': True, 'cert_object': sentinel.cert},
            }
        ]
        run_scan(str(queued_scan.scan_id))
    device = DiscoveredDevice.objects.get(ip_address='192.168.1.60')
    assert device.certificate_record is None
    assert device.ssl_info == {'ssl_open': True}
    assert not ScanManager.get_state()['scan_running']


@pytest.mark.parametrize('error', [RuntimeError('Scanner failed'), TimeoutException('Task timed out')])
def test_task_failure_releases_scan_state(queued_scan, error):
    with patch('discovery.tasks.OTScanner') as scanner:
        scanner.return_value.scan_network.side_effect = error
        with pytest.raises(type(error)):
            run_scan(str(queued_scan.scan_id))
    assert not ScanManager.get_state()['scan_running']


def test_dead_worker_state_expires_and_stale_job_cannot_release_new_scan(queued_scan):
    DiscoveryScan.objects.filter(pk=1).update(
        started_at=timezone.now() - timedelta(seconds=SCAN_TIMEOUT_SECONDS + 11),
    )
    assert not ScanManager.get_state()['scan_running']
    with patch('discovery.services.async_task'):
        assert ScanManager.begin_scan('192.168.2.1', '192.168.2.10')
    run_scan(str(queued_scan.scan_id))
    assert ScanManager.get_state()['scan_running']


def test_stop_when_idle_does_not_leave_stopping_status():
    ScanManager.request_stop()
    assert not ScanManager.get_state()['stop_pending']
