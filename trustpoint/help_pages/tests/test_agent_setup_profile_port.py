# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Agent setup downloads must use the same HTTPS port as the help page."""

import json
from unittest.mock import Mock, patch

import pytest
from django.test import RequestFactory, override_settings

from help_pages.devices_help_views import AgentSetupProfileDownloadView


@pytest.mark.parametrize('configured_port, forwarded_port, expected_url', [
    ('8443', None, 'https://192.0.2.10:8443'),
    ('8443', '9443', 'https://192.0.2.10:9443'),
    ('443', None, 'https://192.0.2.10'),
    (443, None, 'https://192.0.2.10'),
    ('8443', '443', 'https://192.0.2.10'),
])
def test_agent_setup_profile_uses_https_port(
    configured_port: str | int, forwarded_port: str | None, expected_url: str,
) -> None:
    request = RequestFactory().get('/', {'host_ip': '192.0.2.10'})
    request.user = Mock()
    if forwarded_port is not None:
        request.META['HTTP_X_FORWARDED_PORT'] = forwarded_port
    device = Mock(common_name='agent', domain=Mock(unique_name='test-domain'))
    device.onboarding_config.est_password = 'test-password'
    tls = Mock()
    root = tls.credential.get_last_in_chain.return_value
    root.get_certificate_serializer.return_value.as_pem.return_value = b'TLS CERTIFICATE'

    with (
        override_settings(TP_HTTPS_PORT=configured_port),
        patch.object(AgentSetupProfileDownloadView, 'get_object', return_value=device),
        patch('agents.models.TrustpointAgent.objects.filter') as agents,
        patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.first', return_value=tls),
    ):
        agents.return_value.first.return_value.os_path = '/etc/trustpoint'
        response = AgentSetupProfileDownloadView.as_view()(request, pk=1)
        profile = json.loads(b''.join(response.streaming_content))['profile']
        response.close()

    assert profile['certificate_request']['url'] == expected_url
    assert profile['certificate_request']['path'] == '/rest/test-domain/domain_credential/enroll/'
