"""Repositories for provider profiles, managed keys, and capability snapshots."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from django.db import transaction
from django.utils import timezone

from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding
from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.models import (
    CryptoManagedKeyModel,
    CryptoProviderCapabilitySnapshotModel,
    CryptoProviderProfileModel,
    ManagedKeyStatus,
    ProbeStatus,
)

if TYPE_CHECKING:
    from uuid import UUID

    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.refs import ManagedKeyRef


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


class CryptoManagedKeyRepository:
    """Persistence helpers for managed PKCS#11-backed key references."""

    def get_by_id(self, *, managed_key_id: UUID) -> CryptoManagedKeyModel:
        """Return a managed-key record by UUID."""
        return CryptoManagedKeyModel.objects.select_related('provider_profile').get(pk=managed_key_id)

    def get_by_alias(self, *, alias: str) -> CryptoManagedKeyModel:
        """Return a managed-key record by stable application alias."""
        return CryptoManagedKeyModel.objects.select_related('provider_profile').get(alias=alias)

    def list_for_profile(self, *, profile: CryptoProviderProfileModel) -> list[CryptoManagedKeyModel]:
        """List managed keys bound to a provider profile."""
        return list(
            CryptoManagedKeyModel.objects.select_related('provider_profile')
            .filter(provider_profile=profile)
            .order_by('alias')
        )

    @transaction.atomic
    def create_managed_key(
        self,
        *,
        profile: CryptoProviderProfileModel,
        alias: str,
        binding: Pkcs11ManagedKeyBinding,
        public_key: SupportedPublicKey,
        policy: KeyPolicy,
    ) -> CryptoManagedKeyModel:
        """Persist a newly created managed-key binding."""
        public_key_fingerprint = self.public_key_fingerprint_sha256(public_key)
        if (
            binding.public_key_fingerprint_sha256 is not None
            and binding.public_key_fingerprint_sha256 != public_key_fingerprint
        ):
            msg = 'Generated managed-key fingerprint does not match the PKCS#11 binding fingerprint.'
            raise ValueError(msg)

        return CryptoManagedKeyModel.objects.create(
            alias=alias,
            provider_profile=profile,
            key_id_hex=binding.key_id_hex,
            label=alias,
            algorithm=binding.algorithm.value,
            public_key_fingerprint_sha256=public_key_fingerprint,
            signing_execution_mode=binding.signing_execution_mode.value,
            policy_snapshot=self.policy_snapshot(policy),
            status=ManagedKeyStatus.ACTIVE,
            last_verified_at=timezone.now(),
            last_verification_error=None,
        )

    @transaction.atomic
    def mark_verification_success(
        self,
        *,
        managed_key: CryptoManagedKeyModel,
    ) -> CryptoManagedKeyModel:
        """Mark a managed key as successfully verified against the provider."""
        managed_key.status = ManagedKeyStatus.ACTIVE
        managed_key.last_verified_at = timezone.now()
        managed_key.last_verification_error = None
        managed_key.save(update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'])
        return managed_key

    @transaction.atomic
    def mark_missing(
        self,
        *,
        managed_key: CryptoManagedKeyModel,
        error_summary: str,
    ) -> CryptoManagedKeyModel:
        """Mark a managed key as missing from the provider."""
        managed_key.status = ManagedKeyStatus.MISSING
        managed_key.last_verified_at = timezone.now()
        managed_key.last_verification_error = error_summary
        managed_key.save(update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'])
        return managed_key

    @transaction.atomic
    def mark_mismatch(
        self,
        *,
        managed_key: CryptoManagedKeyModel,
        error_summary: str,
    ) -> CryptoManagedKeyModel:
        """Mark a managed key as present but bound to the wrong public key."""
        managed_key.status = ManagedKeyStatus.MISMATCH
        managed_key.last_verified_at = timezone.now()
        managed_key.last_verification_error = error_summary
        managed_key.save(update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'])
        return managed_key

    @transaction.atomic
    def mark_error(
        self,
        *,
        managed_key: CryptoManagedKeyModel,
        error_summary: str,
    ) -> CryptoManagedKeyModel:
        """Mark a managed key as having failed verification for a non-classified reason."""
        managed_key.status = ManagedKeyStatus.ERROR
        managed_key.last_verified_at = timezone.now()
        managed_key.last_verification_error = error_summary
        managed_key.save(update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'])
        return managed_key

    @staticmethod
    def build_managed_key_ref(managed_key: CryptoManagedKeyModel) -> ManagedKeyRef:
        """Convert a persisted managed-key record back into a domain ref."""
        return managed_key.to_managed_key_ref()

    @staticmethod
    def build_pkcs11_binding(managed_key: CryptoManagedKeyModel) -> Pkcs11ManagedKeyBinding:
        """Convert a persisted managed-key record into the PKCS#11 adapter binding."""
        return Pkcs11ManagedKeyBinding(
            key_id=bytes.fromhex(managed_key.key_id_hex),
            algorithm=KeyAlgorithm(managed_key.algorithm),
            public_key_fingerprint_sha256=managed_key.public_key_fingerprint_sha256,
            signing_execution_mode=SigningExecutionMode(managed_key.signing_execution_mode),
        )

    @staticmethod
    def policy_snapshot(policy: KeyPolicy) -> dict[str, object]:
        """Serialize the durable policy summary stored with a managed key."""
        return {
            'extractable': policy.extractable,
            'ephemeral': policy.ephemeral,
            'signing_execution_mode': policy.signing_execution_mode.value,
            'usages': sorted(usage.value for usage in policy.usages),
        }

    @staticmethod
    def public_key_fingerprint_sha256(public_key: SupportedPublicKey) -> str:
        """Return the SHA-256 fingerprint of SubjectPublicKeyInfo DER."""
        spki_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(spki_der).hexdigest()
