# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Persistence, API and migration coverage for dedicated GDS Push settings."""

from unittest.mock import patch
from datetime import timedelta
from django.utils import timezone

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django_q.models import Schedule

from devices.models import DeviceModel, OpcUaGdsPushConfig
from devices.serializers import DeviceSerializer
from onboarding.models import OnboardingPkiProtocol, OnboardingProtocol


@pytest.fixture
def opc_device(device_instance_onboarding):
    device = device_instance_onboarding['device']
    device.device_type = DeviceModel.DeviceType.OPC_UA_GDS_PUSH
    device.onboarding_config.onboarding_protocol = OnboardingProtocol.OPC_GDS_PUSH
    device.onboarding_config.set_pki_protocols([OnboardingPkiProtocol.OPC_GDS_PUSH])
    device.onboarding_config.save()
    device.save()
    return device


def test_config_only_created_for_gds_devices(opc_device):
    generic = DeviceModel.objects.create(common_name='generic-config-test')
    assert not OpcUaGdsPushConfig.objects.filter(device=generic).exists()
    assert OpcUaGdsPushConfig.objects.filter(device=opc_device).count() == 1
    opc_device.save()
    assert OpcUaGdsPushConfig.objects.filter(device=opc_device).count() == 1
    device_id = opc_device.pk
    opc_device.delete()
    assert not OpcUaGdsPushConfig.objects.filter(device_id=device_id).exists()


def test_password_is_encrypted_and_not_returned_by_api(opc_device):
    config = opc_device.opc_ua_gds_push_config
    config.opc_password = 'optional-secret'
    config.save(update_fields=['opc_password'])
    config.refresh_from_db()
    assert config.opc_password == 'optional-secret'
    with connection.cursor() as cursor:
        cursor.execute('SELECT opc_password FROM devices_opcuagdspushconfig WHERE id = %s', [config.pk])
        stored = cursor.fetchone()[0]
    assert stored and stored != 'optional-secret'
    result = DeviceSerializer(opc_device).data
    assert 'opc_password' not in result['opc_ua_gds_push_config']
    assert 'opc_password' not in result['onboarding_config']


@pytest.mark.parametrize('legacy', [False, True])
def test_api_accepts_nested_and_legacy_locations(opc_device, legacy):
    values = {'opc_user': 'admin', 'opc_password': 'secret', 'opc_server_port': 4841}
    if legacy:
        payload = {'opc_server_port': values.pop('opc_server_port'), 'onboarding_config': values}
    else:
        payload = {'opc_ua_gds_push_config': values}
    serializer = DeviceSerializer(opc_device, data=payload, partial=True)
    assert serializer.is_valid(), serializer.errors
    serializer.save()
    config = OpcUaGdsPushConfig.objects.get(device=opc_device)
    assert config.opc_server_port == 4841
    assert config.opc_user == 'admin'
    assert config.opc_password == 'secret'
    assert serializer.data['opc_ua_gds_push_config']['opc_user'] == 'admin'
    assert serializer.data['opc_ua_gds_push_config']['opc_server_port'] == 4841


def test_config_change_preserves_workflow_device_event(opc_device):
    with patch('workflows2.integrations.devices.Workflow2Handler.handle') as handle:
        config = opc_device.opc_ua_gds_push_config
        config.opc_server_port = 4841
        config.save(update_fields=['opc_server_port'])
    context = handle.call_args.args[0]
    assert context.device.pk == opc_device.pk
    assert context.operation == 'updated'
    assert context.event_payload['device']['changes']['opc_server_port'] == {'before': 4840, 'after': 4841}


@pytest.mark.django_db(transaction=True)
def test_data_migration_preserves_ciphertext_settings_and_scheduled_jobs():
    """Round-trip legacy settings without decrypting stored password data."""
    executor = MigrationExecutor(connection)
    latest = executor.loader.graph.leaf_nodes()
    previous = [('devices', '0004_tp_v1_0_dev0'), ('onboarding', '0003_tp_v1_0_dev0')]
    try:
        executor.migrate(previous)
        old = executor.loader.project_state(previous).apps
        Device = old.get_model('devices', 'DeviceModel')
        Onboarding = old.get_model('onboarding', 'OnboardingConfigModel')
        Truststore = old.get_model('pki', 'TruststoreModel')
        truststore = Truststore.objects.create(unique_name='migration-truststore', intended_usage=4)
        onboarding = Onboarding.objects.create(
            onboarding_protocol=7, opc_user='migration-admin', opc_trust_store=truststore
        )
        next_run = timezone.now() + timedelta(hours=12)
        device = Device.objects.create(
            common_name='migration-device',
            device_type=2,
            onboarding_config=onboarding,
            opc_server_port=4850,
            opc_gds_push_enable_periodic_update=True,
            opc_gds_push_renewal_interval=12,
            opc_gds_push_enable_domain_credential_renewal=True,
            opc_gds_push_domain_credential_renewal_interval=24,
            opc_gds_push_last_update_scheduled_at=next_run,
            opc_gds_push_domain_credential_next_renewal_at=next_run,
        )
        ciphertext = 'opaque-encrypted-password-preserved-without-secret-backend'
        with connection.cursor() as cursor:
            cursor.execute(
                'UPDATE onboarding_onboardingconfigmodel SET opc_password = %s WHERE id = %s',
                [ciphertext, onboarding.pk],
            )
        scheduled = Schedule.objects.create(
            name='existing-gds-job', func='devices.tasks.perform_gds_push_update', args=str(device.pk)
        )
        executor = MigrationExecutor(connection)
        with patch('util.encrypted_fields.decrypt_app_secret', side_effect=AssertionError('must not decrypt')):
            executor.migrate(latest)
        config = OpcUaGdsPushConfig.objects.defer('opc_password').get(device_id=device.pk)
        assert config.opc_server_port == 4850
        assert config.opc_user == 'migration-admin'
        assert config.opc_trust_store_id == truststore.pk
        assert config.opc_gds_push_enable_periodic_update
        assert config.opc_gds_push_renewal_interval == 12
        assert config.opc_gds_push_enable_domain_credential_renewal
        assert config.opc_gds_push_domain_credential_renewal_interval == 24
        assert config.opc_gds_push_last_update_scheduled_at == next_run
        assert config.opc_gds_push_domain_credential_next_renewal_at == next_run
        assert Schedule.objects.filter(pk=scheduled.pk).exists()
        with connection.cursor() as cursor:
            cursor.execute('SELECT opc_password FROM devices_opcuagdspushconfig WHERE id = %s', [config.pk])
            assert cursor.fetchone()[0] == ciphertext
        executor = MigrationExecutor(connection)
        with patch('util.encrypted_fields.decrypt_app_secret', side_effect=AssertionError('must not decrypt')):
            executor.migrate(previous)
        with connection.cursor() as cursor:
            cursor.execute('SELECT opc_password FROM onboarding_onboardingconfigmodel WHERE id = %s', [onboarding.pk])
            assert cursor.fetchone()[0] == ciphertext
    finally:
        MigrationExecutor(connection).migrate(latest)


@pytest.mark.parametrize('legacy', [False, True])
def test_api_creates_device_with_dedicated_config(device_instance_onboarding, legacy):
    domain = device_instance_onboarding['device'].domain
    payload = {
        'common_name': 'created-opc-config', 'device_type': 2, 'domain': domain.pk,
        'ip_address': '127.0.0.1',
        'onboarding_config': {'onboarding_protocol': 7, 'pki_protocols': ['OPC_GDS_PUSH']},
    }
    if legacy:
        payload['opc_server_port'] = 4842
        payload['onboarding_config'].update({'opc_user': 'admin', 'opc_password': 'secret'})
    else:
        payload['opc_ua_gds_push_config'] = {
            'opc_server_port': 4842, 'opc_user': 'admin', 'opc_password': 'secret',
        }
    serializer = DeviceSerializer(data=payload)
    assert serializer.is_valid(), serializer.errors
    device = serializer.save()
    assert device.opc_ua_gds_push_config.opc_server_port == 4842
    assert device.opc_ua_gds_push_config.opc_user == 'admin'
    assert device.opc_ua_gds_push_config.opc_password == 'secret'
    assert serializer.data['opc_ua_gds_push_config']['opc_user'] == 'admin'
    assert 'opc_password' not in serializer.data['opc_ua_gds_push_config']
