# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for traceability signing lifecycle boundaries."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from typing import Any

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import OperationalError, connection, connections, transaction

from crypto.application.private_keys import ManagedECPrivateKey
from management.models.traceability import TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCredentialService, VerificationFailureReason

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
        purposes=[TraceabilityCredentialModel.Purpose.AUDIT_LOG],
    )


def test_retirement_rejects_signing_with_cached_credential(credential: TraceabilityCredentialModel) -> None:
    """Retirement must take effect even when callers retain an active model instance."""
    TraceabilityCredentialService.retire(credential)

    with pytest.raises(ValidationError, match='not currently usable'):
        TraceabilityCredentialService.sign(
            traceability_credential=credential,
            data=b'event',
            purpose=TraceabilityCredentialModel.Purpose.AUDIT_LOG,
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
                purpose=TraceabilityCredentialModel.Purpose.AUDIT_LOG,
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
        purpose=TraceabilityCredentialModel.Purpose.AUDIT_LOG,
    )
    new_generation = TraceabilityCredentialService.rotate(traceability_credential=credential)
    after = TraceabilityCredentialService.sign(
        traceability_credential=credential,
        data=b'event',
        purpose=TraceabilityCredentialModel.Purpose.AUDIT_LOG,
    )

    assert before.generation_id != after.generation_id == new_generation.pk
    assert old_generation is not None
    assert TraceabilityCredentialService.verify(
        generation=old_generation,
        data=b'event',
        signature=before.signature,
        purpose=TraceabilityCredentialModel.Purpose.AUDIT_LOG,
    ).valid
    assert TraceabilityCredentialService.verify(
        generation=new_generation,
        data=b'event',
        signature=after.signature,
        purpose=TraceabilityCredentialModel.Purpose.AUDIT_LOG,
    ).valid


def test_verification_returns_purpose_mismatch(credential: TraceabilityCredentialModel) -> None:
    """An unassigned purpose returns a failure instead of crashing."""
    assert credential.current_generation is not None
    result = TraceabilityCredentialService.verify(
        generation=credential.current_generation,
        data=b'event',
        signature=b'invalid',
        purpose=TraceabilityCredentialModel.Purpose.CT_LOG,
    )

    assert not result.valid
    assert result.failure_reason == VerificationFailureReason.PURPOSE_MISMATCH
