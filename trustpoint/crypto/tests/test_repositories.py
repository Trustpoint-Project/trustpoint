"""Tests for provider profile repositories."""

from __future__ import annotations

import pytest

from crypto.adapters.software.capabilities import SoftwareCapabilities
from crypto.models import (
    BackendKind,
    CryptoProviderCapabilitySnapshotModel,
    CryptoProviderCapabilitySoftwareDetailModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    ProbeStatus,
    SoftwareKeyEncryptionSource,
)
from crypto.repositories import CryptoProviderProfileRepository


def _create_software_profile(*, name: str, active: bool = True) -> CryptoProviderProfileModel:
    """Create a generic provider profile plus software config."""
    profile = CryptoProviderProfileModel.objects.create(
        name=name,
        backend_kind=BackendKind.SOFTWARE,
        active=active,
    )
    CryptoProviderSoftwareConfigModel.objects.create(
        profile=profile,
        encryption_source=SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
        encryption_source_ref=None,
        allow_exportable_private_keys=False,
    )
    return profile


@pytest.mark.django_db
def test_record_probe_failure_clears_current_snapshot() -> None:
    profile = _create_software_profile(name='test-profile', active=True)

    success_snapshot = CryptoProviderCapabilitySnapshotModel.objects.create(
        profile=profile,
        status=ProbeStatus.SUCCESS,
        probe_hash='abc123',
        error_summary=None,
    )
    CryptoProviderCapabilitySoftwareDetailModel.objects.create(
        snapshot=success_snapshot,
        snapshot_payload={
            'supported_key_algorithms': ['rsa', 'ec'],
            'supported_signature_algorithms': ['rsa_pkcs1v15', 'ecdsa'],
            'supported_signing_execution_modes': ['complete_backend', 'allow_application_hash'],
        },
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
    profile = _create_software_profile(name='test-profile', active=True)
    profile.last_probe_status = ProbeStatus.FAILURE
    profile.save(update_fields=['last_probe_status', 'updated_at'])

    repo = CryptoProviderProfileRepository()
    assert repo.load_current_capabilities(profile=profile) is None


@pytest.mark.django_db
def test_record_probe_success_sets_current_snapshot() -> None:
    profile = _create_software_profile(name='test-profile', active=True)

    capabilities = SoftwareCapabilities(
        supported_key_algorithms=('rsa', 'ec'),
        supported_signature_algorithms=('rsa_pkcs1v15', 'ecdsa'),
        supported_signing_execution_modes=('complete_backend', 'allow_application_hash'),
    )

    repo = CryptoProviderProfileRepository()
    result = repo.record_probe_success(profile=profile, capabilities=capabilities)

    profile.refresh_from_db()
    snapshot = profile.current_capability_snapshot

    assert result.profile_id == profile.pk
    assert snapshot is not None
    assert profile.last_probe_status == ProbeStatus.SUCCESS
    assert profile.last_probe_error is None
    assert snapshot.software_detail.snapshot_payload == capabilities.to_json_dict()


@pytest.mark.django_db
def test_load_current_capabilities_round_trips_software_snapshot() -> None:
    profile = _create_software_profile(name='test-profile', active=True)

    capabilities = SoftwareCapabilities(
        supported_key_algorithms=('rsa', 'ec'),
        supported_signature_algorithms=('rsa_pkcs1v15', 'ecdsa'),
        supported_signing_execution_modes=('complete_backend', 'allow_application_hash'),
    )

    repo = CryptoProviderProfileRepository()
    repo.record_probe_success(profile=profile, capabilities=capabilities)

    loaded = repo.load_current_capabilities(profile=profile)

    assert isinstance(loaded, SoftwareCapabilities)
    assert loaded.to_json_dict() == capabilities.to_json_dict()
