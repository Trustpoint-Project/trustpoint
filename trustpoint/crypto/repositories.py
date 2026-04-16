"""Repositories for provider profiles and capability snapshots."""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
from crypto.models import (
    CryptoProviderCapabilitySnapshotModel,
    CryptoProviderProfileModel,
    ProbeStatus,
)


@dataclass(frozen=True, slots=True)
class ProbeRefreshResult:
    """Result of persisting a capability probe refresh."""

    profile_id: int
    snapshot_id: int
    probe_hash: str
    changed: bool


class CryptoProviderProfileRepository:
    """Persistence helpers for provider profiles and capability snapshots."""

    def get_active_profile(self) -> CryptoProviderProfileModel:
        """Return the one active provider profile."""
        return CryptoProviderProfileModel.objects.get(active=True)

    def get_profile(self, *, profile_id: int) -> CryptoProviderProfileModel:
        """Return a provider profile by primary key."""
        return CryptoProviderProfileModel.objects.get(pk=profile_id)

    @transaction.atomic
    def record_probe_success(
        self,
        *,
        profile: CryptoProviderProfileModel,
        capabilities: Pkcs11Capabilities,
    ) -> ProbeRefreshResult:
        """Persist a successful capability probe as a new snapshot."""
        snapshot_payload = capabilities.to_json_dict()
        probe_hash = capabilities.fingerprint()

        previous_hash = None
        if profile.current_capability_snapshot is not None:
            previous_hash = profile.current_capability_snapshot.probe_hash

        snapshot = CryptoProviderCapabilitySnapshotModel.objects.create(
            profile=profile,
            status=ProbeStatus.SUCCESS,
            probe_hash=probe_hash,
            token_label=capabilities.token.label,
            token_serial=capabilities.token.serial,
            token_model=capabilities.token.model,
            token_manufacturer=capabilities.token.manufacturer,
            slot_id=capabilities.token.slot_id,
            snapshot=snapshot_payload,
            error_summary=None,
        )

        profile.current_capability_snapshot = snapshot
        profile.last_probe_status = ProbeStatus.SUCCESS
        profile.last_probe_at = timezone.now()
        profile.last_probe_error = None
        profile.save(
            update_fields=[
                'current_capability_snapshot',
                'last_probe_status',
                'last_probe_at',
                'last_probe_error',
                'updated_at',
            ]
        )

        return ProbeRefreshResult(
            profile_id=profile.pk,
            snapshot_id=snapshot.pk,
            probe_hash=probe_hash,
            changed=previous_hash != probe_hash,
        )

    @transaction.atomic
    def record_probe_failure(
        self,
        *,
        profile: CryptoProviderProfileModel,
        error_summary: str,
    ) -> CryptoProviderCapabilitySnapshotModel:
        """Persist a failed capability probe attempt."""
        snapshot = CryptoProviderCapabilitySnapshotModel.objects.create(
            profile=profile,
            status=ProbeStatus.FAILURE,
            probe_hash='',
            token_label=None,
            token_serial=None,
            token_model=None,
            token_manufacturer=None,
            slot_id=None,
            snapshot={},
            error_summary=error_summary,
        )

        profile.current_capability_snapshot = None
        profile.last_probe_status = ProbeStatus.FAILURE
        profile.last_probe_at = timezone.now()
        profile.last_probe_error = error_summary
        profile.save(
            update_fields=[
                'current_capability_snapshot',
                'last_probe_status',
                'last_probe_at',
                'last_probe_error',
                'updated_at',
            ]
        )
        return snapshot

    def load_current_capabilities(self, *, profile: CryptoProviderProfileModel) -> Pkcs11Capabilities | None:
        """Load the current effective capability snapshot for a profile."""
        if profile.last_probe_status != ProbeStatus.SUCCESS:
            return None

        snapshot = profile.current_capability_snapshot
        if snapshot is None or snapshot.status != ProbeStatus.SUCCESS:
            return None

        return Pkcs11Capabilities.from_json_dict(snapshot.snapshot)
