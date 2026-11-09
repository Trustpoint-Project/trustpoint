# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for traceability signing lifecycle boundaries."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import OperationalError, connection, connections, transaction
from django.urls import reverse

from crypto.application.private_keys import ManagedECPrivateKey
from management.models.traceability import TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCredentialService, VerificationFailureReason
from management.views.traceability_signing import TraceabilityCredentialSettingsForm

pytestmark = pytest.mark.django_db


@pytest.fixture
def credential(settings: Any) -> TraceabilityCredentialModel:
    """Create a real signing credential using the development software backend."""
    settings.DEVELOPMENT_ENV = True
    settings.TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND = True
    settings.TRUSTPOINT_IS_OPERATIONAL = True
    settings.DOCKER_CONTAINER = False
    call_command('create_default_cert_profiles')
    return TraceabilityCredentialService.create(
        name='audit-evidence',
        curve=TraceabilityCredentialModel.Curve.SECP256R1,
    )


def test_settings_form_accepts_credential_without_purposes() -> None:
    """Creating a signing identity requires no predefined consumer assignment."""
    form = TraceabilityCredentialSettingsForm(
        data={
            'name': 'shared-evidence',
            'curve': TraceabilityCredentialModel.Curve.SECP256R1,
        }
    )
    assert form.is_valid(), form.errors


def test_same_credential_signs_consumer_defined_payloads(credential: TraceabilityCredentialModel) -> None:
    """One identity signs multiple consumers' payloads, including their usage context."""
    assert credential.current_generation is not None
    for data in (b'audit:v1:event', b'issuance:v1:certificate', b'custom-consumer:v1:record'):
        signed = TraceabilityCredentialService.sign(traceability_credential=credential, data=data)
        assert TraceabilityCredentialService.verify(
            generation=credential.current_generation,
            data=data,
            signature=signed.signature,
        ).valid
        assert not TraceabilityCredentialService.verify(
            generation=credential.current_generation,
            data=b'other-context:' + data,
            signature=signed.signature,
        ).valid


def test_retirement_rejects_signing_with_cached_credential(credential: TraceabilityCredentialModel) -> None:
    """Retirement must take effect even when callers retain an active model instance."""
    TraceabilityCredentialService.retire(credential)

    with pytest.raises(ValidationError, match='not currently usable'):
        TraceabilityCredentialService.sign(
            traceability_credential=credential,
            data=b'event',
        )


@pytest.mark.django_db(transaction=True)
def test_retirement_waits_for_in_progress_signature(
    credential: TraceabilityCredentialModel,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retirement cannot acquire the credential lock while its key is signing."""
    if connection.vendor != 'postgresql':
        pytest.skip('Row-lock concurrency requires PostgreSQL')

    signing_started, finish_signing = Event(), Event()
    original_sign = ManagedECPrivateKey.sign

    def paused_sign(self: ManagedECPrivateKey, *args: Any, **kwargs: Any) -> bytes:
        signing_started.set()
        assert finish_signing.wait(timeout=10)
        return original_sign(self, *args, **kwargs)

    def sign() -> None:
        try:
            TraceabilityCredentialService.sign(
                traceability_credential=credential,
                data=b'event',
            )
        finally:
            connections.close_all()

    monkeypatch.setattr(ManagedECPrivateKey, 'sign', paused_sign)
    with ThreadPoolExecutor(max_workers=1) as pool:
        signing = pool.submit(sign)
        try:
            assert signing_started.wait(timeout=10)
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL lock_timeout = '500ms'")
                with pytest.raises(OperationalError) as error:
                    TraceabilityCredentialService.retire(credential)
            assert error.value.__cause__.sqlstate == '55P03'
        finally:
            finish_signing.set()
        signing.result(timeout=10)

    TraceabilityCredentialService.retire(credential)
    credential.refresh_from_db()
    assert credential.status == TraceabilityCredentialModel.Status.RETIRED


def test_rotation_uses_current_generation_and_preserves_verification(credential: TraceabilityCredentialModel) -> None:
    """A cached caller must sign with the new key while old signatures still verify."""
    old_generation = credential.current_generation
    before = TraceabilityCredentialService.sign(
        traceability_credential=credential,
        data=b'event',
    )
    new_generation = TraceabilityCredentialService.rotate(traceability_credential=credential)
    after = TraceabilityCredentialService.sign(
        traceability_credential=credential,
        data=b'event',
    )

    assert before.generation_id != after.generation_id == new_generation.pk
    assert old_generation is not None
    assert TraceabilityCredentialService.verify(
        generation=old_generation,
        data=b'event',
        signature=before.signature,
    ).valid
    assert TraceabilityCredentialService.verify(
        generation=new_generation,
        data=b'event',
        signature=after.signature,
    ).valid


def test_verification_rejects_invalid_signature(credential: TraceabilityCredentialModel) -> None:
    """Invalid signature bytes return a structured verification failure."""
    assert credential.current_generation is not None
    result = TraceabilityCredentialService.verify(
        generation=credential.current_generation,
        data=b'event',
        signature=b'invalid',
    )

    assert not result.valid
    assert result.failure_reason == VerificationFailureReason.INVALID_SIGNATURE


def test_retirement_view_confirms_without_certificate_fields(credential, client):
    """Retirement needs only confirmation, preserves history, and reports repeated retirement."""
    user = get_user_model().objects.create_superuser(username='retirement-admin', password='test-password')
    client.force_login(user)
    url = reverse('management:traceability_credential_retire', kwargs={'pk': credential.pk})
    generation_id = credential.current_generation_id
    generation_count = credential.generations.count()

    response = client.get(url)
    assert response.status_code == 200
    assert not response.context['form'].fields
    assert 'Retire credential' in response.content.decode()
    assert 'permanently stops signing' in response.content.decode()
    credential.refresh_from_db()
    assert credential.status == TraceabilityCredentialModel.Status.ACTIVE

    rotation = client.get(reverse('management:traceability_credential_rotate', kwargs={'pk': credential.pk}))
    assert rotation.status_code == 200
    assert rotation.context['form'].fields
    assert rotation.context['form_title'] == 'Rotate key and certificate'

    response = client.post(url, {})
    assert response.status_code == 302
    assert response.url == reverse('management:traceability_credential_detail', kwargs={'pk': credential.pk})
    credential.refresh_from_db()
    assert credential.status == TraceabilityCredentialModel.Status.RETIRED
    assert credential.current_generation_id == generation_id
    assert credential.generations.count() == generation_count
    assert credential.current_generation.status == 'RETIRED'

    repeated = client.post(url, {})
    assert repeated.status_code == 200
    assert 'already retired' in repeated.content.decode()


def test_retirement_view_requires_management_permission(credential, client):
    """The confirmation and mutation both require permission to manage credentials."""
    user = get_user_model().objects.create_user(username='retirement-reader')
    client.force_login(user)
    url = reverse('management:traceability_credential_retire', kwargs={'pk': credential.pk})
    assert client.get(url).status_code == 403
    assert client.post(url, {}).status_code == 403
    credential.refresh_from_db()
    assert credential.status == TraceabilityCredentialModel.Status.ACTIVE
