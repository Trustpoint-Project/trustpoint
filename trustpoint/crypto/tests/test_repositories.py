"""Tests for provider profile repositories."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from crypto.models import (
    CryptoProviderCapabilitySnapshotModel,
    CryptoProviderProfileModel,
    ProviderAuthSource,
    ProbeStatus,
)
from crypto.repositories import CryptoProviderProfileRepository


@dataclass(frozen=True, slots=True)
class DummyTokenIdentity:
    slot_id: int
    label: str | None
    serial: str | None
    model: str | None
    manufacturer: str | None
    hardware_version: str | None = None
    firmware_version: str | None = None


@dataclass(frozen=True, slots=True)
class DummyCapabilities:
    token: DummyTokenIdentity

    def to_json_dict(self) -> dict[str, object]:
        return {
            'token': {
                'slot_id': self.token.slot_id,
                'label': self.token.label,
                'serial': self.token.serial,
                'model': self.token.model,
                'manufacturer': self.token.manufacturer,
            },
            'mechanisms': {},
            'derived_features': {},
        }

    def fingerprint(self) -> str:
        return 'abc123'


@pytest.mark.django_db
def test_record_probe_failure_clears_current_snapshot() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='test-profile',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )
    success_snapshot = CryptoProviderCapabilitySnapshotModel.objects.create(
        profile=profile,
        status=ProbeStatus.SUCCESS,
        probe_hash='abc123',
        token_label='Token',
        token_serial='1234',
        token_model='Model',
        token_manufacturer='Vendor',
        slot_id=1,
        snapshot={'token': {}, 'mechanisms': {}, 'derived_features': {}},
        error_summary=None,
    )
    profile.current_capability_snapshot = success_snapshot
    profile.last_probe_status = ProbeStatus.SUCCESS
    profile.save(update_fields=['current_capability_snapshot', 'last_probe_status', 'updated_at'])

    repo = CryptoProviderProfileRepository()
    repo.record_probe_failure(profile=profile, error_summary='provider offline')

    profile.refresh_from_db()
    assert profile.current_capability_snapshot is None
    assert profile.last_probe_status == ProbeStatus.FAILURE
    assert profile.last_probe_error == 'provider offline'


@pytest.mark.django_db
def test_load_current_capabilities_returns_none_after_failure() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='test-profile',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
        last_probe_status=ProbeStatus.FAILURE,
    )

    repo = CryptoProviderProfileRepository()
    assert repo.load_current_capabilities(profile=profile) is None


@pytest.mark.django_db
def test_record_probe_success_sets_current_snapshot() -> None:
    profile = CryptoProviderProfileModel.objects.create(
        name='test-profile',
        module_path='/usr/lib/test-pkcs11.so',
        token_serial='1234',
        auth_source=ProviderAuthSource.FILE,
        auth_source_ref='/tmp/user-pin.txt',
        active=True,
    )

    capabilities = DummyCapabilities(
        token=DummyTokenIdentity(
            slot_id=7,
            label='Trustpoint-SoftHSM',
            serial='1234',
            model='SoftHSM v2',
            manufacturer='SoftHSM project',
        )
    )

    repo = CryptoProviderProfileRepository()
    result = repo.record_probe_success(profile=profile, capabilities=capabilities)  # type: ignore[arg-type]

    profile.refresh_from_db()
    assert result.profile_id == profile.pk
    assert profile.current_capability_snapshot is not None
    assert profile.last_probe_status == ProbeStatus.SUCCESS
    assert profile.last_probe_error is None
    