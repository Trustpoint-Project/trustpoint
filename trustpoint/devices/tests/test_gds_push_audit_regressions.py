# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Permission and scheduling regressions for GDS Push."""

from datetime import timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest
from django.contrib.auth.models import Permission
from django.urls import reverse
from django.utils import timezone
from django_q.models import Schedule

from devices.models import DeviceModel
from devices.tasks import perform_gds_push_update


@pytest.mark.parametrize(
    ('action', 'permission', 'method', 'result'),
    [
        ('devices_update_trustlist', 'manage_devices', 'update_trustlist', (True, 'updated')),
        ('devices_update_server_certificate', 'issue_certificates', 'update_server_certificate', (True, 'updated', b'cert')),
    ],
)
def test_gds_action_requires_permission(client, django_user_model, gds_device, action, permission, method, result):
    user = django_user_model.objects.create_user(username='gds-reader', password='test-password')
    user.role.permissions.clear()
    client.force_login(user)
    url = reverse(f'devices:{action}', kwargs={'pk': gds_device.pk})
    with patch('devices.views.gds_push.GdsPushService') as service:
        setattr(service.return_value, method, AsyncMock(return_value=result))
        assert client.post(url).status_code == 403
        service.assert_not_called()
        user.role.permissions.add(Permission.objects.get(codename=permission))
        assert client.post(url).status_code == 302
        service.assert_called_once()


@pytest.fixture
def gds_device(mock_models):
    device = mock_models['device']
    device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
    device.save(update_fields=['device_type'])
    return device


def test_saving_settings_replaces_legacy_schedules_and_disable_cancels(gds_device):
    config = gds_device.opc_ua_gds_push_config
    task_name = f'gds_push_update_{gds_device.pk}'
    Schedule.objects.create(name=f'{task_name}_12345', func='devices.tasks.perform_gds_push_update')
    config.opc_gds_push_enable_periodic_update = True
    config.save(update_fields=['opc_gds_push_enable_periodic_update'])
    first = Schedule.objects.get(name=task_name)
    config.opc_gds_push_renewal_interval = 24
    config.save(update_fields=['opc_gds_push_renewal_interval'])
    replacement = Schedule.objects.get(name=task_name)
    assert replacement.pk != first.pk
    assert Schedule.objects.filter(name__startswith=task_name).count() == 1
    assert timezone.now() + timedelta(hours=23) < replacement.next_run < timezone.now() + timedelta(hours=25)
    config.opc_gds_push_enable_periodic_update = False
    config.save(update_fields=['opc_gds_push_enable_periodic_update'])
    assert not Schedule.objects.filter(name__startswith=task_name).exists()
    config.refresh_from_db()
    assert config.opc_gds_push_last_update_scheduled_at is None


def test_obsolete_jobs_skip_and_a_due_job_reserves_one_successor(gds_device):
    config = gds_device.opc_ua_gds_push_config
    config.opc_gds_push_enable_periodic_update = True
    config.save(update_fields=['opc_gds_push_enable_periodic_update'])
    service = Mock(
        update_trustlist=AsyncMock(return_value=(True, 'updated')),
        update_server_certificate=AsyncMock(return_value=(True, 'updated', b'certificate')),
    )
    with patch('devices.tasks.GdsPushService', return_value=service) as constructor:
        perform_gds_push_update(gds_device.pk)
        constructor.assert_not_called()
        type(config).objects.filter(pk=config.pk).update(
            opc_gds_push_last_update_scheduled_at=timezone.now() - timedelta(seconds=1),
        )
        perform_gds_push_update(gds_device.pk)
        perform_gds_push_update(gds_device.pk)
    service.update_trustlist.assert_awaited_once()
    service.update_server_certificate.assert_awaited_once()
    assert Schedule.objects.filter(name=f'gds_push_update_{gds_device.pk}').count() == 1


def test_failed_update_remains_retryable(gds_device):
    config = gds_device.opc_ua_gds_push_config
    config.opc_gds_push_enable_periodic_update = True
    config.save()
    service = Mock(
        update_trustlist=AsyncMock(side_effect=RuntimeError('temporary failure')),
        update_server_certificate=AsyncMock(return_value=(True, 'updated', b'certificate')),
    )
    with patch('devices.tasks.GdsPushService', return_value=service):
        with pytest.raises(RuntimeError, match='temporary failure'):
            perform_gds_push_update(gds_device.pk)
        config.refresh_from_db()
        assert config.opc_gds_push_last_update_scheduled_at is None
        service.update_trustlist.side_effect = None
        service.update_trustlist.return_value = (True, 'updated')
        perform_gds_push_update(gds_device.pk)
    assert service.update_trustlist.await_count == 2
    service.update_server_certificate.assert_awaited_once()
    assert Schedule.objects.filter(name=f'gds_push_update_{gds_device.pk}').count() == 1
