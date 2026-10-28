# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for protocol-independent credential expiry API inputs."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from devices.serializers import OnboardingConfigSerializer
from management.models import SecurityConfig
from onboarding.models import OnboardingConfigModel, OnboardingProtocol


@pytest.mark.django_db
@pytest.mark.parametrize('protocol', [
    OnboardingProtocol.CMP_SHARED_SECRET,
    OnboardingProtocol.EST_USERNAME_PASSWORD,
    OnboardingProtocol.REST_USERNAME_PASSWORD,
])
def test_credential_ttl_create_and_update(protocol: OnboardingProtocol) -> None:
    """The same TTL input applies to CMP, EST, and REST and survives database storage."""
    now = datetime(2026, 10, 2, tzinfo=timezone.utc)
    serializer = OnboardingConfigSerializer(data={
        'onboarding_protocol': protocol,
        'credential_ttl_seconds': 120,
    })
    assert serializer.is_valid(), serializer.errors
    with patch('devices.serializers.timezone.now', return_value=now):
        config = serializer.save()
    config.refresh_from_db()
    assert config.credential_expires_at == now + timedelta(seconds=120)
    assert 'credential_ttl_seconds' not in serializer.data

    update = OnboardingConfigSerializer(config, data={'credential_ttl_seconds': 240}, partial=True)
    assert update.is_valid(), update.errors
    with patch('devices.serializers.timezone.now', return_value=now):
        update.save()
    config.refresh_from_db()
    assert config.credential_expires_at == now + timedelta(seconds=240)


@pytest.mark.django_db
@pytest.mark.parametrize('protocol', [
    OnboardingProtocol.CMP_SHARED_SECRET,
    OnboardingProtocol.EST_USERNAME_PASSWORD,
    OnboardingProtocol.REST_USERNAME_PASSWORD,
])
def test_explicit_credential_expiry(protocol: OnboardingProtocol) -> None:
    """All protocols accept an explicit timestamp and allow clearing the expiry."""
    expiry = datetime(2026, 10, 2, tzinfo=timezone.utc)
    serializer = OnboardingConfigSerializer(data={
        'onboarding_protocol': protocol,
        'credential_expires_at': expiry.isoformat(),
    })
    assert serializer.is_valid(), serializer.errors
    config = serializer.save()
    config.refresh_from_db()
    assert config.credential_expires_at == expiry
    assert 'credential_expires_at' in serializer.data

    update = OnboardingConfigSerializer(config, data={'credential_expires_at': None}, partial=True)
    assert update.is_valid(), update.errors
    update.save()
    config.refresh_from_db()
    assert config.credential_expires_at is None


@pytest.mark.django_db
@pytest.mark.parametrize('mode', list(SecurityConfig.SecurityModeChoices))
@pytest.mark.parametrize('protocol', [
    OnboardingProtocol.CMP_SHARED_SECRET,
    OnboardingProtocol.EST_USERNAME_PASSWORD,
    OnboardingProtocol.REST_USERNAME_PASSWORD,
])
def test_security_mode_credential_ttl(mode: str, protocol: OnboardingProtocol) -> None:
    """Both API and direct model creation use the configured mode's credential TTL."""
    security = SecurityConfig.objects.create(pk=1, security_mode=mode)
    security.apply_security_settings()
    now = datetime(2026, 10, 2, tzinfo=timezone.utc)
    expected = now + timedelta(seconds=600) if mode in (
        SecurityConfig.SecurityModeChoices.HARDENED,
        SecurityConfig.SecurityModeChoices.CRITICAL,
    ) else None
    serializer = OnboardingConfigSerializer(data={'onboarding_protocol': protocol})
    assert serializer.is_valid(), serializer.errors
    credential_field = 'cmp_shared_secret' if protocol == OnboardingProtocol.CMP_SHARED_SECRET else 'est_password'
    with patch('onboarding.models.timezone.now', return_value=now):
        api_config = serializer.save()
        model_config = OnboardingConfigModel.objects.create(
            onboarding_protocol=protocol, **{credential_field: 'test-secret'},
        )
    for config in (api_config, model_config):
        config.refresh_from_db()
        assert config.credential_expires_at == expected
        with patch('onboarding.models.timezone.now', return_value=now + timedelta(seconds=900)):
            config.save()
        config.refresh_from_db()
        assert config.credential_expires_at == expected


@pytest.mark.django_db
@pytest.mark.parametrize('ttl_seconds', [None, 300])
@pytest.mark.parametrize('protocol', [
    OnboardingProtocol.CMP_SHARED_SECRET,
    OnboardingProtocol.EST_USERNAME_PASSWORD,
    OnboardingProtocol.REST_USERNAME_PASSWORD,
])
def test_custom_security_credential_ttl(ttl_seconds: int | None, protocol: OnboardingProtocol) -> None:
    """A custom security TTL applies to all three shared-credential protocols."""
    SecurityConfig.objects.create(pk=1, credential_ttl_seconds=ttl_seconds)
    now = datetime(2026, 10, 2, tzinfo=timezone.utc)
    serializer = OnboardingConfigSerializer(data={'onboarding_protocol': protocol})
    assert serializer.is_valid(), serializer.errors
    with patch('onboarding.models.timezone.now', return_value=now):
        config = serializer.save()
    assert config.credential_expires_at == (
        None if ttl_seconds is None else now + timedelta(seconds=ttl_seconds)
    )