# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression coverage for consolidating external GDS instances into generic devices."""

import pytest
from django.core.exceptions import ValidationError
from django.urls import NoReverseMatch, Resolver404, resolve, reverse

from devices import urls, views
from devices.models import DeviceModel
from devices.serializers import DeviceSerializer
from help_pages.devices_help_views import DeviceApplicationCertificateWithEstDomainCredentialHelpView
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
