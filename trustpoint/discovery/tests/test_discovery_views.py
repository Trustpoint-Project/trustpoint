"""Tests for discovery views and scan management."""

from __future__ import annotations

import csv
from io import StringIO
from threading import Event
from unittest.mock import Mock, patch, sentinel

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from discovery.models import DiscoveredDevice, DiscoveryPort
from discovery.scanner import OTScanner
from discovery.views import ScanManager


@pytest.fixture(autouse=True)
def reset_scan_manager() -> None:
    """Reset singleton scan state around each test."""
    ScanManager.is_running = False
    ScanManager.stop_pending = False
    ScanManager.start_ip = '10.100.13.1'
    ScanManager.end_ip = '10.100.13.254'
    ScanManager.scanner_instance = None
    yield
    ScanManager.is_running = False
    ScanManager.stop_pending = False
    ScanManager.start_ip = '10.100.13.1'
    ScanManager.end_ip = '10.100.13.254'
    ScanManager.scanner_instance = None


@pytest.fixture
def authenticated_client(client):
    """Provide an authenticated client for views protected by login."""
    user_model = get_user_model()
    user = user_model.objects.create_user(username='discovery-tester', password='testpass123')
    client.force_login(user)
    return client


class TestScanManager:
    """Tests for the discovery scan state manager."""

    def test_begin_scan_initializes_state_and_scanner(self) -> None:
        """Starting a scan should capture IPs and create a scanner instance."""
        assert ScanManager.begin_scan('192.168.1.10', '192.168.1.20') is True

        state = ScanManager.get_state()
        assert state == {
            'scan_running': True,
            'stop_pending': False,
            'start_ip': '192.168.1.10',
            'end_ip': '192.168.1.20',
        }
        assert isinstance(ScanManager.scanner_instance, OTScanner)
        assert ScanManager.scanner_instance.target_ports == []

    def test_begin_scan_rejects_second_concurrent_request(self) -> None:
        """Only one scan may be active at a time."""
        assert ScanManager.begin_scan('192.168.1.10', '192.168.1.20') is True
        assert ScanManager.begin_scan('192.168.1.30', '192.168.1.40') is False

        state = ScanManager.get_state()
        assert state['start_ip'] == '192.168.1.10'
        assert state['end_ip'] == '192.168.1.20'

    def test_request_stop_marks_pending_and_sets_scanner_event(self) -> None:
        """Stopping a scan should flip state and signal the active scanner."""
        scanner = OTScanner(target_ports=[])
        ScanManager.is_running = True
        ScanManager.scanner_instance = scanner

        ScanManager.request_stop()

        state = ScanManager.get_state()
        assert state['stop_pending'] is True
        assert scanner.stop_requested.is_set() is True

    def test_end_scan_resets_state(self) -> None:
        """Ending a scan should clear all shared state."""
        ScanManager.is_running = True
        ScanManager.stop_pending = True
        ScanManager.scanner_instance = OTScanner(target_ports=[443])

        ScanManager.end_scan()

        assert ScanManager.get_state() == {
            'scan_running': False,
            'stop_pending': False,
            'start_ip': '10.100.13.1',
            'end_ip': '10.100.13.254',
        }
        assert ScanManager.scanner_instance is None


class TestRunScanInBackground:
    """Tests for the background scan orchestration."""

    def test_run_scan_in_background_persists_discovered_devices(self) -> None:
        """Background scans should update the discovery inventory from scanner results."""
        DiscoveryPort.objects.create(port_number=443, description='HTTPS')
        DiscoveryPort.objects.create(port_number=502, description='Modbus')
        scanner = Mock()
        scanner.stop_requested = Event()
        scanner.target_ports = []
        scanner.scan_network.return_value = [
            {
                'ip': '192.168.1.50',
                'hostname': 'plc-50.local',
                'ports': [443, 502],
                'ssl_info': {'ssl_open': True, 'is_self_signed': False},
            }
        ]
        ScanManager.is_running = True
        ScanManager.scanner_instance = scanner

        ScanManager.run_scan_in_background('192.168.1.1', '192.168.1.100')

        scanner.scan_network.assert_called_once_with('192.168.1.1', '192.168.1.100')
        assert scanner.target_ports == [443, 502]
        device = DiscoveredDevice.objects.get(ip_address='192.168.1.50')
        assert device.hostname == 'plc-50.local'
        assert device.open_ports == [443, 502]
        assert device.ssl_info == {'ssl_open': True, 'is_self_signed': False}
        assert ScanManager.get_state()['scan_running'] is False

    def test_run_scan_in_background_saves_certificate_and_removes_raw_cert_object(self) -> None:
        """Certificate-bearing results should save the certificate and drop the raw object."""
        DiscoveryPort.objects.create(port_number=443, description='HTTPS')
        scanner = Mock()
        scanner.stop_requested = Event()
        scanner.target_ports = []
        scanner.scan_network.return_value = [
            {
                'ip': '192.168.1.60',
                'hostname': 'plc-60.local',
                'ports': [443],
                'ssl_info': {
                    'ssl_open': True,
                    'issuer': 'CN=issuer',
                    'subject': 'CN=subject',
                    'cert_object': sentinel.cert_object,
                },
            }
        ]
        ScanManager.scanner_instance = scanner

        with (
            patch('discovery.views.CertificateModel.save_certificate', return_value=sentinel.saved_certificate) as mock_save_certificate,
            patch('discovery.views.DiscoveredDevice.objects.update_or_create') as mock_update_or_create,
        ):
            ScanManager.run_scan_in_background('192.168.1.1', '192.168.1.100')

        mock_save_certificate.assert_called_once_with(sentinel.cert_object)
        mock_update_or_create.assert_called_once_with(
            ip_address='192.168.1.60',
            defaults={
                'hostname': 'plc-60.local',
                'open_ports': [443],
                'ssl_info': {
                    'ssl_open': True,
                    'issuer': 'CN=issuer',
                    'subject': 'CN=subject',
                },
                'certificate_record': sentinel.saved_certificate,
            },
        )

    def test_run_scan_in_background_skips_database_writes_when_stop_is_requested(self) -> None:
        """No inventory updates should occur after a stop request is observed."""
        DiscoveryPort.objects.create(port_number=443, description='HTTPS')
        scanner = Mock()
        scanner.stop_requested = Event()
        scanner.stop_requested.set()
        scanner.scan_network.return_value = [
            {'ip': '192.168.1.61', 'hostname': 'ignored', 'ports': [443], 'ssl_info': {'ssl_open': True}}
        ]
        ScanManager.scanner_instance = scanner

        with patch('discovery.views.DiscoveredDevice.objects.update_or_create') as mock_update_or_create:
            ScanManager.run_scan_in_background('192.168.1.1', '192.168.1.100')

        mock_update_or_create.assert_not_called()

    def test_run_scan_in_background_resets_state_when_scanner_raises(self) -> None:
        """Shared scan state should be cleared even if scanning crashes."""
        scanner = Mock()
        scanner.stop_requested = Event()
        scanner.scan_network.side_effect = RuntimeError('scanner failed')
        ScanManager.is_running = True
        ScanManager.stop_pending = True
        ScanManager.scanner_instance = scanner

        with pytest.raises(RuntimeError, match='scanner failed'):
            ScanManager.run_scan_in_background('192.168.1.1', '192.168.1.100')

        assert ScanManager.get_state() == {
            'scan_running': False,
            'stop_pending': False,
            'start_ip': '10.100.13.1',
            'end_ip': '10.100.13.254',
        }
        assert ScanManager.scanner_instance is None


class TestDiscoveryViews:
    """Tests for discovery request handlers."""

    def test_device_list_renders_stats_and_scan_state(self, authenticated_client) -> None:
        """The dashboard should expose device risk totals, OT totals, and scan state."""
        DiscoveryPort.objects.create(port_number=1883, description='MQTT broker')
        DiscoveryPort.objects.create(port_number=22, description='SSH')
        DiscoveredDevice.objects.create(
            ip_address='192.168.1.70',
            hostname='sensor-70',
            open_ports=[1883, 22],
            ssl_info={'is_self_signed': True},
        )
        DiscoveredDevice.objects.create(
            ip_address='192.168.1.71',
            hostname='sensor-71',
            open_ports=[22],
            ssl_info={},
        )
        ScanManager.is_running = True
        ScanManager.stop_pending = True
        ScanManager.start_ip = '192.168.1.1'
        ScanManager.end_ip = '192.168.1.254'

        response = authenticated_client.get(reverse('discovery:device_list'))

        assert response.status_code == 200
        assert response.context['stats'] == {'total': 2, 'risks': 1, 'industrial': 1}
        assert response.context['scan_running'] is True
        assert response.context['stop_pending'] is True
        assert response.context['start_ip'] == '192.168.1.1'
        assert response.context['end_ip'] == '192.168.1.254'
        assert response.context['page_category'] == 'tools'
        assert response.context['page_name'] == 'discovery'

    def test_start_scan_launches_background_thread_when_not_running(self, authenticated_client) -> None:
        """Posting to start should spawn the background worker when the manager accepts it."""
        with (
            patch('discovery.views.ScanManager.begin_scan', return_value=True) as mock_begin_scan,
            patch('discovery.views.threading.Thread') as mock_thread_cls,
        ):
            response = authenticated_client.post(
                reverse('discovery:start_scan'),
                {'start_ip': '192.168.1.1', 'end_ip': '192.168.1.254'},
            )

        assert response.status_code == 302
        assert response.url == reverse('discovery:device_list')
        mock_begin_scan.assert_called_once_with('192.168.1.1', '192.168.1.254')
        mock_thread_cls.assert_called_once_with(
            target=ScanManager.run_scan_in_background,
            args=('192.168.1.1', '192.168.1.254'),
        )
        assert mock_thread_cls.return_value.daemon is True
        mock_thread_cls.return_value.start.assert_called_once_with()

    def test_start_scan_does_not_launch_thread_when_scan_is_already_running(self, authenticated_client) -> None:
        """Posting to start should not create another worker if one is already running."""
        with (
            patch('discovery.views.ScanManager.begin_scan', return_value=False) as mock_begin_scan,
            patch('discovery.views.threading.Thread') as mock_thread_cls,
        ):
            response = authenticated_client.post(reverse('discovery:start_scan'))

        assert response.status_code == 302
        assert response.url == reverse('discovery:device_list')
        mock_begin_scan.assert_called_once_with('10.100.13.1', '10.100.13.254')
        mock_thread_cls.assert_not_called()

    def test_stop_scan_requests_shutdown_and_redirects(self, authenticated_client) -> None:
        """Stopping a scan should delegate to the manager and redirect back to the dashboard."""
        with patch('discovery.views.ScanManager.request_stop') as mock_request_stop:
            response = authenticated_client.post(reverse('discovery:stop_scan'))

        assert response.status_code == 302
        assert response.url == reverse('discovery:device_list')
        mock_request_stop.assert_called_once_with()

    def test_add_port_creates_new_port(self, authenticated_client) -> None:
        """A valid port submission should be stored."""
        response = authenticated_client.post(
            reverse('discovery:add_port'),
            {'port_number': '8883', 'description': 'MQTT over TLS'},
        )

        assert response.status_code == 302
        assert DiscoveryPort.objects.filter(port_number=8883, description='MQTT over TLS').exists() is True

    def test_add_port_rejects_invalid_port_number(self, authenticated_client) -> None:
        """Invalid port numbers should not create records."""
        response = authenticated_client.post(
            reverse('discovery:add_port'),
            {'port_number': 'not-a-number', 'description': 'bad'},
        )

        assert response.status_code == 302
        assert DiscoveryPort.objects.count() == 0

    def test_delete_port_removes_existing_port(self, authenticated_client) -> None:
        """Deleting a configured port should remove it from storage."""
        port = DiscoveryPort.objects.create(port_number=4840, description='OPC UA')

        response = authenticated_client.post(reverse('discovery:delete_port', args=[port.id]))

        assert response.status_code == 302
        assert DiscoveryPort.objects.filter(id=port.id).exists() is False

    def test_clear_devices_removes_inventory(self, authenticated_client) -> None:
        """Clearing the inventory should delete all discovered devices."""
        DiscoveredDevice.objects.create(ip_address='192.168.1.80', hostname='sensor-80', open_ports=[443])
        DiscoveredDevice.objects.create(ip_address='192.168.1.81', hostname='sensor-81', open_ports=[502])

        response = authenticated_client.post(reverse('discovery:clear_devices'))

        assert response.status_code == 302
        assert DiscoveredDevice.objects.count() == 0

    def test_device_detail_renders_selected_device(self, authenticated_client) -> None:
        """The detail page should expose the requested discovered device."""
        device = DiscoveredDevice.objects.create(
            ip_address='192.168.1.90',
            hostname='sensor-90',
            open_ports=[443],
            ssl_info={'issuer': 'CN=test'},
        )

        response = authenticated_client.get(reverse('discovery:device_detail', args=[device.id]))

        assert response.status_code == 200
        assert response.context['device'].id == device.id
        assert response.context['page_category'] == 'tools'
        assert response.context['page_name'] == 'discovery'

    def test_export_csv_writes_inventory_rows(self, authenticated_client) -> None:
        """CSV exports should include one row per discovered device."""
        DiscoveredDevice.objects.create(ip_address='192.168.1.100', hostname='sensor-a', open_ports=[443, 502])
        DiscoveredDevice.objects.create(ip_address='192.168.1.101', hostname='sensor-b', open_ports=[])

        response = authenticated_client.get(reverse('discovery:export_csv'))

        assert response.status_code == 200
        assert response['Content-Disposition'] == 'attachment; filename="inventory.csv"'

        rows = list(csv.reader(StringIO(response.content.decode('utf-8'))))
        assert rows == [
            ['IP', 'Hostname', 'Ports'],
            ['192.168.1.100', 'sensor-a', '443, 502'],
            ['192.168.1.101', 'sensor-b', ''],
        ]
