# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for discovery views and scan management."""

from __future__ import annotations

import csv
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.urls import reverse

from discovery.models import DiscoveredDevice, DiscoveryPort, DiscoveryScan

pytestmark = pytest.mark.django_db


@pytest.fixture
def authenticated_client(client):
    """Provide an authenticated client for views protected by login."""
    user_model = get_user_model()
    user = user_model.objects.create_user(username='discovery-tester', password='testpass123')
    manage_discovery_perm = Permission.objects.get(codename='manage_certificate_discovery')
    user.role.permissions.add(manage_discovery_perm)
    client.force_login(user)
    return client


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
        DiscoveryScan.objects.create(
            pk=1,
            is_running=True,
            stop_pending=True,
            start_ip='192.168.1.1',
            end_ip='192.168.1.254',
        )

        response = authenticated_client.get(reverse('discovery:device_list'))

        assert response.status_code == 200
        assert response.context['stats'] == {'total': 2, 'risks': 1, 'industrial': 1}
        assert response.context['scan_running'] is True
        assert response.context['stop_pending'] is True
        assert response.context['start_ip'] == '192.168.1.1'
        assert response.context['end_ip'] == '192.168.1.254'
        assert response.context['page_category'] == 'tools'
        assert response.context['page_name'] == 'discovery'

    def test_start_scan_enqueues_background_job(self, authenticated_client) -> None:
        """The web process reserves a shared scan and queues work without starting a thread."""
        with patch('discovery.services.async_task') as enqueue:
            response = authenticated_client.post(
                reverse('discovery:start_scan'),
                {'start_ip': '192.168.1.1', 'end_ip': '192.168.1.254'},
            )
        assert response.status_code == 302
        state = DiscoveryScan.objects.get(pk=1)
        assert state.is_running
        assert state.started_at is None
        assert state.start_ip == '192.168.1.1'
        assert state.end_ip == '192.168.1.254'
        assert enqueue.call_args.args == ('discovery.tasks.run_scan', str(state.scan_id))

    def test_start_scan_does_not_enqueue_another_running_scan(self, authenticated_client) -> None:
        """A scan started by another web process blocks a second enqueue."""
        DiscoveryScan.objects.create(pk=1, is_running=True)
        with patch('discovery.services.async_task') as enqueue:
            response = authenticated_client.post(reverse('discovery:start_scan'))
        assert response.status_code == 302
        enqueue.assert_not_called()

    @pytest.mark.parametrize('start,end', [('invalid', '192.168.1.2'), ('192.168.1.2', '192.168.1.1')])
    def test_invalid_scan_range_is_not_queued(self, authenticated_client, start, end) -> None:
        """Invalid addresses and reversed ranges fail before reserving a scan."""
        with patch('discovery.services.async_task') as enqueue:
            response = authenticated_client.post(reverse('discovery:start_scan'), {'start_ip': start, 'end_ip': end})
        assert response.status_code == 302
        assert not DiscoveryScan.objects.filter(is_running=True).exists()
        enqueue.assert_not_called()

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

    @pytest.mark.parametrize('existing_port', [True, False])
    def test_delete_port_requires_discovery_permission(self, client, existing_port) -> None:
        """Unauthorized users receive 403 before lookup and cannot change scan coverage."""
        user = get_user_model().objects.create_user(username='discovery-viewer', password='testpass123')
        assert not user.has_perm('users.manage_certificate_discovery')
        client.force_login(user)
        port = DiscoveryPort.objects.create(port_number=4840, description='OPC UA')
        port_id = port.pk if existing_port else port.pk + 1

        response = client.post(reverse('discovery:delete_port', args=[port_id]))

        assert response.status_code == 403
        port.refresh_from_db()
        assert port.port_number == 4840
        assert port.description == 'OPC UA'

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
