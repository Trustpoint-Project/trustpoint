# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for expired onboarding credentials on device help pages."""

from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from django.test import RequestFactory
from django.utils import timezone
from django.views.generic.detail import DetailView

from help_pages.devices_help_views import (
    AgentSetupProfileStrategy,
    ApplicationCertificateWithCmpDomainCredentialStrategy,
    BaseHelpView,
    NoOnboardingCmpSharedSecretStrategy,
    OnboardingDomainCredentialCmpSharedSecretStrategy,
    OnboardingDomainCredentialEstUsernamePasswordStrategy,
    OnboardingDomainCredentialRestUsernamePasswordStrategy,
)
from onboarding.models import OnboardingConfigModel


@pytest.mark.parametrize('strategy_class', [
    OnboardingDomainCredentialCmpSharedSecretStrategy,
    OnboardingDomainCredentialEstUsernamePasswordStrategy,
    OnboardingDomainCredentialRestUsernamePasswordStrategy,
    AgentSetupProfileStrategy,
    ApplicationCertificateWithCmpDomainCredentialStrategy,
    NoOnboardingCmpSharedSecretStrategy,
])
@pytest.mark.parametrize('expiry_offset', [None, -1, 0, 1])
def test_help_warns_only_for_expired_onboarding_credentials(strategy_class, expiry_offset) -> None:
    now = timezone.now()
    config = OnboardingConfigModel(
        credential_expires_at=None if expiry_offset is None else now + timedelta(seconds=expiry_offset)
    )
    view = BaseHelpView()
    view.object = Mock(onboarding_config=config)
    view.strategy = strategy_class()
    view.page_name = 'devices'
    view.request = RequestFactory().get('/')
    view.request.user = Mock()
    with patch.object(DetailView, 'get_context_data', return_value={}), \
            patch.object(view, '_make_context'), \
            patch.object(view.strategy, 'build_sections', return_value=([], 'Help')), \
            patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.get'), \
            patch('onboarding.models.timezone.now', return_value=now):
        context = view.get_context_data()

    password_strategy = strategy_class not in (
        ApplicationCertificateWithCmpDomainCredentialStrategy, NoOnboardingCmpSharedSecretStrategy
    )
    assert context['credential_expired'] is (
        password_strategy and expiry_offset is not None and expiry_offset <= 0
    )