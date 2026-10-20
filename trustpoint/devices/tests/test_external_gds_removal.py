# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression coverage for consolidating external GDS instances into generic devices."""

from importlib import import_module

import pytest
from django.core.exceptions import ValidationError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.urls import NoReverseMatch, Resolver404, resolve, reverse

from devices import urls, views
from devices.models import DeviceModel
from devices.serializers import DeviceSerializer
from help_pages.devices_help_views import DeviceApplicationCertificateWithEstDomainCredentialHelpView
from onboarding.models import OnboardingConfigModel, OnboardingProtocol
from trustpoint.page_context import PageContextMixin


def test_remaining_device_types_and_api_choices():
    assert DeviceModel.DeviceType.__members__ == {
        'GENERIC_DEVICE': 0,
        'OPC_UA_GDS_PUSH': 2,
        'AGENT_ONE_TO_ONE': 3,
    }
    assert set(DeviceSerializer().fields['device_type'].choices) == {0, 2, 3}
    with pytest.raises(ValidationError):
        DeviceModel._meta.get_field('device_type').clean(1, DeviceModel())
    assert 'DEVICES_PAGE_OPC_UA_SUBCATEGORY' not in PageContextMixin().get_context_data()


def test_obsolete_views_and_routes_are_removed():
    assert not any(name.startswith('OpcUaGds') and not name.startswith('OpcUaGdsPush') for name in vars(views))
    assert not any(
        route.name.startswith('opc_ua_gds') and not route.name.startswith('opc_ua_gds_push')
        for route in urls.urlpatterns
    )
    with pytest.raises(NoReverseMatch):
        reverse('devices:opc_ua_gds')
    for path in (
        '/devices/opc-ua-gds/',
        '/devices/opc-ua-gds/create/',
        '/devices/opc-ua-gds/certificate-lifecycle-management/1/',
    ):
        with pytest.raises(Resolver404):
            resolve(path)


def test_devices_sidebar_has_standard_navigation(admin_client):
    response = admin_client.get(reverse('devices:devices'))
    assert response.status_code == 200
    html = response.content.decode()
    assert '/devices/opc-ua-gds/' not in html
    for name in ('devices:devices', 'devices:zero_touch_credentials', 'devices:agents'):
        assert f'href="{reverse(name)}"' in html


def test_push_est_help_uses_shared_device_view():
    url = '/devices/opc-ua-gds-push/certificate-lifecycle-management/1/onboarding/issue-application-credential/est-domain-credential/'
    assert resolve(url).func.view_class is DeviceApplicationCertificateWithEstDomainCredentialHelpView


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize('with_onboarding', [False, True])
def test_external_gds_migration_preserves_associations(mock_models, with_onboarding):
    before = [('devices', '0003_tp_v0_6_0')]
    after = [('devices', '0004_remove_external_gds_device_type')]
    executor = MigrationExecutor(connection)
    executor.migrate(before)
    try:
        old_apps = executor.loader.project_state(before).apps
        old_device_model = old_apps.get_model('devices', 'DeviceModel')
        device = mock_models['device']
        if with_onboarding:
            config = OnboardingConfigModel.objects.create(
                onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
                est_password='preserved-est-password',
            )
            old_device_model.objects.filter(pk=device.pk).update(
                onboarding_config_id=config.pk,
                no_onboarding_config_id=None,
            )
        old_device_model.objects.filter(pk=device.pk).update(device_type=1)
        snapshots = {}
        for device_type in (0, 2, 3):
            other = old_device_model.objects.create(common_name=f'unchanged-{device_type}', device_type=device_type)
            snapshots[other.pk] = old_device_model.objects.filter(pk=other.pk).values().get()
        original = old_device_model.objects.filter(pk=device.pk).values().get()
        credentials = list(old_apps.get_model('pki', 'IssuedCredentialModel').objects.values())
        onboarding = list(old_apps.get_model('onboarding', 'OnboardingConfigModel').objects.values())
        no_onboarding = list(old_apps.get_model('onboarding', 'NoOnboardingConfigModel').objects.values())

        executor = MigrationExecutor(connection)
        executor.migrate(after)
        new_apps = executor.loader.project_state(after).apps
        new_device_model = new_apps.get_model('devices', 'DeviceModel')
        assert new_device_model.objects.filter(pk=device.pk).values().get() == {**original, 'device_type': 0}
        for pk, snapshot in snapshots.items():
            assert new_device_model.objects.filter(pk=pk).values().get() == snapshot
        assert list(new_apps.get_model('pki', 'IssuedCredentialModel').objects.values()) == credentials
        assert list(new_apps.get_model('onboarding', 'OnboardingConfigModel').objects.values()) == onboarding
        assert list(new_apps.get_model('onboarding', 'NoOnboardingConfigModel').objects.values()) == no_onboarding
        # Reapplying the data operation is harmless.
        migration = import_module('devices.migrations.0004_remove_external_gds_device_type')
        with connection.schema_editor() as schema_editor:
            migration.convert_external_gds_devices(new_apps, schema_editor)
        assert new_device_model.objects.filter(pk=device.pk).values().get() == {**original, 'device_type': 0}
    finally:
        MigrationExecutor(connection).migrate(after)
