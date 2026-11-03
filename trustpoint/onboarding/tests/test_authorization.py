# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Protocol policy must exist unambiguously before configurations are accepted."""

from types import SimpleNamespace

import pytest
from django.urls import reverse
from rest_framework.exceptions import ValidationError

from devices.models import DeviceModel
from devices.serializers import DeviceSerializer
from management.models import SecurityConfig
from onboarding.authorization import PermittedProtocolsAuthorization
from onboarding.models import NoOnboardingConfigModel, OnboardingConfigModel
from onboarding.enums import OnboardingProtocol

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize('onboarding', [False, True])
@pytest.mark.parametrize('state', ['missing', 'ambiguous', 'allowed', 'denied'])
def test_protocol_policy_requires_one_policy_and_checks_permission(onboarding, state):
    if state != 'missing':
        SecurityConfig.objects.create(
            pk=1,
            permitted_onboarding_protocols=[] if state == 'denied' else [0],
            permitted_no_onboarding_pki_protocols=[] if state == 'denied' else [16],
        )
    if state == 'ambiguous':
        SecurityConfig.objects.create(pk=2)
    subject = SimpleNamespace(
        onboarding_config=OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.MANUAL) if onboarding else None,
        no_onboarding_config=None if onboarding else NoOnboardingConfigModel(pki_protocols=16),
    )

    if state == 'allowed':
        PermittedProtocolsAuthorization().check(subject)
    else:
        with pytest.raises(ValueError):
            PermittedProtocolsAuthorization().check(subject)


@pytest.mark.parametrize('ambiguous', [False, True])
def test_device_creation_rolls_back_when_policy_is_unavailable(ambiguous):
    if ambiguous:
        SecurityConfig.objects.create(pk=1, permitted_no_onboarding_pki_protocols=[4])
        SecurityConfig.objects.create(pk=2)
    serializer = DeviceSerializer(
        data={
            'common_name': 'no-policy-device',
            'no_onboarding_config': {'pki_protocols': 4},
        }
    )
    assert serializer.is_valid(), serializer.errors

    with pytest.raises(ValidationError, match='not permitted'):
        serializer.save()

    assert not DeviceModel.objects.exists()
    assert not NoOnboardingConfigModel.objects.exists()


@pytest.mark.parametrize('ambiguous', [False, True])
@pytest.mark.parametrize(
    'route,values',
    [
        ('devices_create_no_onboarding', {'no_onboarding_pki_protocols': [16]}),
        ('devices_create_onboarding', {'onboarding_protocol': 2, 'onboarding_pki_protocols': [1]}),
        ('devices_create_opc_ua_gds_push', {'ip_address': '192.0.2.1', 'opc_server_port': 4840}),
    ],
)
def test_creation_pages_show_policy_errors_without_creating_records(admin_client, ambiguous, route, values):
    if ambiguous:
        policy = SecurityConfig.objects.create()
        policy.apply_security_settings()
        SecurityConfig.objects.create(pk=2)
    response = admin_client.post(reverse(f'devices:{route}'), {'common_name': 'no-policy-device', **values})
    assert response.status_code == 200
    assert 'Exactly one security policy' in str(response.context['form'].non_field_errors())
    assert not DeviceModel.objects.exists()
    assert not NoOnboardingConfigModel.objects.exists()
    assert not OnboardingConfigModel.objects.exists()
