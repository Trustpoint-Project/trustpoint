# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Keep SCEP configuration download links consistent with enrollment authorization."""

from datetime import timedelta
from http import HTTPStatus
from unittest.mock import Mock

import pytest
from django.contrib.auth.models import Permission
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from devices.models import DeviceModel
from devices.secrets import assign_secret
from help_pages.devices_help_views import NoOnboardingScepStrategy
from help_pages.help_section import ValueRenderType
from onboarding.enums import NoOnboardingPkiProtocol
from onboarding.models import NoOnboardingConfigModel
from users.models import TrustpointUser


@pytest.mark.parametrize('state', ['none', 'expired', 'consumed', 'active'])
def test_profile_download_link_requires_active_challenge(state: str) -> None:
    """Unavailable enrollment configurations show guidance instead of a broken link."""
    section = NoOnboardingScepStrategy._build_profile_section(  # noqa: SLF001
        device=Mock(pk=1, common_name='test-device'),
        profile_url='http://testserver/scep/profile/',
        name='profile',
        index=0,
        challenge_state=state,
    )
    row = section.rows[0]
    if state == 'active':
        assert row.value_render_type == ValueRenderType.HTML
        assert reverse('devices:scep_config_download', kwargs={'pk': 1}) in row.value
    else:
        assert row.value_render_type == ValueRenderType.PLAIN
        assert '<a ' not in row.value
        assert 'renewal' in row.value if state == 'consumed' else 'challengePassword' in row.value


@pytest.mark.django_db
@pytest.mark.parametrize('state', ['none', 'expired', 'consumed', 'active'])
def test_download_enforces_challenge_state(
    client: Client,
    admin_user: TrustpointUser,
    state: str,
) -> None:
    """Missing/expired/consumed secrets stay refused; active downloads stay usable."""
    admin_user.role.permissions.add(Permission.objects.get(codename='manage_devices'))
    client.force_login(admin_user)
    config = NoOnboardingConfigModel.objects.create(pki_protocols=NoOnboardingPkiProtocol.SCEP)
    device = DeviceModel.objects.create(common_name='scep-download-device', no_onboarding_config=config)
    if state != 'none':
        assign_secret(config, 'scep_challenge')
        if state == 'expired':
            NoOnboardingConfigModel.objects.filter(pk=config.pk).update(
                scep_challenge_expires_at=timezone.now() - timedelta(seconds=1),
            )
        elif state == 'consumed':
            assert config.consume_scep_challenge()
    response = client.get(reverse('devices:scep_config_download', kwargs={'pk': device.pk}))
    config.refresh_from_db()
    assert config.scep_challenge_state() == state
    if state == 'active':
        assert response.status_code == HTTPStatus.OK
        assert response['Content-Disposition'] == 'attachment; filename="scep.cnf"'
        assert 'no-store' in response['Cache-Control']
        assert f'challengePassword = {config.scep_challenge}' in response.content.decode()
    else:
        assert response.status_code == HTTPStatus.NOT_FOUND
