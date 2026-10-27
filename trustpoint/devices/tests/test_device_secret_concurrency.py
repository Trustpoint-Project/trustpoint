# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Real database concurrency checks; run these on PostgreSQL, where row locks apply."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, transaction

from devices.secrets import assign_secret
from onboarding.enums import OnboardingProtocol, OnboardingStatus
from onboarding.models import DeviceSecretAssignmentLock, NoOnboardingConfigModel, OnboardingConfigModel

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(not connection.features.has_select_for_update, reason='Requires real database row locks'),
]


def test_same_challenge_concurrently_saved_across_configuration_tables():
    DeviceSecretAssignmentLock.objects.get_or_create(pk=1)
    barrier = Barrier(2)

    def save(onboarding):
        close_old_connections()
        try:
            if onboarding:
                config = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.MANUAL)
            else:
                config = NoOnboardingConfigModel(pki_protocols=64)
            config.scep_challenge = 'concurrent-challenge'
            config.scep_challenge_digest = config.scep_digest_for(config.scep_challenge)
            barrier.wait(timeout=10)
            try:
                config.save()
            except ValidationError:
                return False
            return True
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(save, onboarding) for onboarding in (False, True)]
        assert sum(future.result(timeout=20) for future in futures) == 1
    assert OnboardingConfigModel.objects.count() + NoOnboardingConfigModel.objects.count() == 1


@pytest.mark.parametrize('scep', [False, True])
def test_completion_wins_against_waiting_replacement(scep):
    DeviceSecretAssignmentLock.objects.get_or_create(pk=1)
    if scep:
        config = NoOnboardingConfigModel.objects.create(pki_protocols=64)
        assign_secret(config, 'scep_challenge')
        field = 'scep_challenge'
    else:
        config = OnboardingConfigModel.objects.create(
            onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD, est_password='bootstrap'
        )
        field = 'est_password'
    model = type(config)
    completed = Event()
    replacement_started = Event()

    def complete():
        close_old_connections()
        try:
            with transaction.atomic():
                locked = model.objects.select_for_update().get(pk=config.pk)
                if scep:
                    assert locked.consume_scep_challenge()
                else:
                    locked.est_password = ''
                    locked.onboarding_status = OnboardingStatus.ONBOARDED
                    locked.save(update_fields=['est_password', 'onboarding_status'])
                completed.set()
                assert replacement_started.wait(timeout=10)
        finally:
            close_old_connections()

    def replace():
        close_old_connections()
        try:
            assert completed.wait(timeout=10)
            fresh = model.objects.get(pk=config.pk)
            replacement_started.set()
            with pytest.raises(ValidationError):
                assign_secret(fresh, field)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(complete), pool.submit(replace)]
        for future in futures:
            future.result(timeout=20)
    config.refresh_from_db()
    if scep:
        assert config.scep_challenge_state() == 'consumed'
    else:
        assert config.onboarding_status == OnboardingStatus.ONBOARDED
        assert not config.est_password
