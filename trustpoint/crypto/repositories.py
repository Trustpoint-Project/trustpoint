"""Repositories for provider profiles, managed keys, and capability snapshots."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from django.db import transaction
from django.utils import timezone

from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding
from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
from crypto.adapters.protected_import.bindings import ProtectedImportManagedKeyBinding
from crypto.adapters.rest.bindings import RestManagedKeyBinding
from crypto.adapters.rest.capabilities import RestCapabilities
from crypto.adapters.software.bindings import SoftwareManagedKeyBinding
from crypto.adapters.software.capabilities import SoftwareCapabilities
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.errors import InternalConsistencyError, UnsupportedBackendKindError
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.local_development import ensure_local_software_backends
from crypto.models import (
    BackendKind,
    CryptoManagedKeyModel,
    CryptoManagedKeyPkcs11BindingModel,
    CryptoManagedKeyProtectedImportBindingModel,
    CryptoManagedKeyRestBindingModel,
    CryptoManagedKeySoftwareBindingModel,
    CryptoProviderCapabilityPkcs11DetailModel,
    CryptoProviderCapabilityRestDetailModel,
    CryptoProviderCapabilitySnapshotModel,
    CryptoProviderCapabilitySoftwareDetailModel,
    CryptoProviderProfileModel,
    ManagedKeyStatus,
    ProbeStatus,
)

if TYPE_CHECKING:
    from uuid import UUID

    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.refs import ManagedKeyRef

ProviderCapabilities = Pkcs11Capabilities | SoftwareCapabilities | RestCapabilities
ManagedKeyBinding = (
    Pkcs11ManagedKeyBinding | SoftwareManagedKeyBinding | RestManagedKeyBinding | ProtectedImportManagedKeyBinding
)


@dataclass(frozen=True, slots=True)
class ProbeRefreshResult:
    """Result of persisting a capability probe refresh."""

    profile_id: int
    snapshot_id: int
    probe_hash: str
    changed: bool


def _save_untyped_model(instance: Any, *, update_fields: list[str] | None = None) -> None:
    """Save a Django model whose save method is not typed for mypy."""
    if update_fields is None:
        instance.save()
        return

    instance.save(update_fields=update_fields)


def _optional_db_text(value: str | None) -> str:
    """Normalize optional string values for Django string fields."""
    return value or ''


def _optional_domain_text(value: str) -> str | None:
    """Restore optional domain string values from Django string fields."""
    return value or None


class CryptoProviderProfileRepository:
    """Persistence helpers for provider profiles and capability snapshots."""

    def get_configured_profile(self) -> CryptoProviderProfileModel:
        """Return the configured backend profile for this Trustpoint instance."""
        ensure_local_software_backends()
        return CryptoProviderProfileModel.objects.get(active=True)

    def get_active_profile(self) -> CryptoProviderProfileModel:
        """Backward-compatible alias for the configured instance backend profile."""
        return self.get_configured_profile()

    def get_profile(self, *, profile_id: int) -> CryptoProviderProfileModel:
        """Return a provider profile by primary key."""
        return CryptoProviderProfileModel.objects.get(pk=profile_id)

    @transaction.atomic
    def record_probe_success(
        self,
        *,
        profile: CryptoProviderProfileModel,
        capabilities: ProviderCapabilities,
    ) -> ProbeRefreshResult:
        """Persist a successful capability probe as a new snapshot."""
        probe_hash = capabilities.fingerprint()

        previous_hash = None
        if profile.current_capability_snapshot is not None:
            previous_hash = profile.current_capability_snapshot.probe_hash

        snapshot = CryptoProviderCapabilitySnapshotModel.objects.create(
            profile=profile,
            status=ProbeStatus.SUCCESS,
            probe_hash=probe_hash,
            error_summary='',
        )

        if profile.backend_kind == BackendKind.PKCS11:
            if not isinstance(capabilities, Pkcs11Capabilities):
                msg = 'PKCS#11 provider profile cannot persist non-PKCS#11 capabilities.'
                raise InternalConsistencyError(msg)
            CryptoProviderCapabilityPkcs11DetailModel.objects.create(
                snapshot=snapshot,
                token_label=_optional_db_text(capabilities.token.label),
                token_serial=_optional_db_text(capabilities.token.serial),
                token_model=_optional_db_text(capabilities.token.model),
                token_manufacturer=_optional_db_text(capabilities.token.manufacturer),
                slot_id=capabilities.token.slot_id,
                snapshot_payload=capabilities.to_json_dict(),
            )

        elif profile.backend_kind == BackendKind.SOFTWARE:
            if not isinstance(capabilities, SoftwareCapabilities):
                msg = 'Software provider profile cannot persist non-software capabilities.'
                raise InternalConsistencyError(msg)
            CryptoProviderCapabilitySoftwareDetailModel.objects.create(
                snapshot=snapshot,
                snapshot_payload=capabilities.to_json_dict(),
            )

        elif profile.backend_kind == BackendKind.REST:
            if not isinstance(capabilities, RestCapabilities):
                msg = 'REST provider profile cannot persist non-REST capabilities.'
                raise InternalConsistencyError(msg)
            CryptoProviderCapabilityRestDetailModel.objects.create(
                snapshot=snapshot,
                snapshot_payload=capabilities.to_json_dict(),
            )

        else:
            msg = f'Unsupported backend kind {profile.backend_kind!r}.'
            raise UnsupportedBackendKindError(msg)

        profile.current_capability_snapshot = snapshot
        profile.last_probe_status = ProbeStatus.SUCCESS
        profile.last_probe_at = timezone.now()
        profile.last_probe_error = ''
        _save_untyped_model(
            profile,
            update_fields=[
                'current_capability_snapshot',
                'last_probe_status',
                'last_probe_at',
                'last_probe_error',
                'updated_at',
            ],
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
            error_summary=error_summary,
        )

        profile.current_capability_snapshot = None
        profile.last_probe_status = ProbeStatus.FAILURE
        profile.last_probe_at = timezone.now()
        profile.last_probe_error = error_summary
        _save_untyped_model(
            profile,
            update_fields=[
                'current_capability_snapshot',
                'last_probe_status',
                'last_probe_at',
                'last_probe_error',
                'updated_at',
            ],
        )
        return snapshot

    def load_current_capabilities(self, *, profile: CryptoProviderProfileModel) -> ProviderCapabilities | None:
        """Load the current effective capability snapshot for a profile."""
        if profile.last_probe_status != ProbeStatus.SUCCESS:
            return None

        snapshot = profile.current_capability_snapshot
        if snapshot is None or snapshot.status != ProbeStatus.SUCCESS:
            return None

        if profile.backend_kind == BackendKind.PKCS11:
            return Pkcs11Capabilities.from_json_dict(snapshot.pkcs11_detail.snapshot_payload)

        if profile.backend_kind == BackendKind.SOFTWARE:
            return SoftwareCapabilities.from_json_dict(snapshot.software_detail.snapshot_payload)

        if profile.backend_kind == BackendKind.REST:
            return RestCapabilities.from_json_dict(snapshot.rest_detail.snapshot_payload)

        msg = f'Unsupported backend kind {profile.backend_kind!r}.'
        raise UnsupportedBackendKindError(msg)


class CryptoManagedKeyRepository:
    """Persistence helpers for backend-managed key references."""

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
    def create_managed_key(  # noqa: PLR0913
        self,
        *,
        profile: CryptoProviderProfileModel,
        alias: str,
        provider_label: str | None,
        binding: ManagedKeyBinding,
        public_key: SupportedPublicKey,
        policy: KeyPolicy,
    ) -> CryptoManagedKeyModel:
        """Persist a newly created managed-key binding."""
        self._validate_profile_binding_compatibility(profile, binding)

        public_key_fingerprint = self.public_key_fingerprint_sha256(public_key)
        binding_fingerprint = binding.public_key_fingerprint_sha256
        if binding_fingerprint is not None and binding_fingerprint != public_key_fingerprint:
            msg = 'Generated managed-key fingerprint does not match the backend binding fingerprint.'
            raise InternalConsistencyError(msg)

        managed_key = CryptoManagedKeyModel(
            alias=alias,
            provider_label=_optional_db_text(provider_label),
            provider_profile=profile,
            algorithm=binding.algorithm.value,
            public_key_fingerprint_sha256=public_key_fingerprint,
            signing_execution_mode=binding.signing_execution_mode.value,
            policy_snapshot=self.policy_snapshot(policy),
            status=ManagedKeyStatus.ACTIVE,
            last_verified_at=timezone.now(),
            last_verification_error='',
        )
        managed_key.full_clean()
        _save_untyped_model(managed_key)

        self._persist_backend_binding(profile=profile, managed_key=managed_key, binding=binding)
        return managed_key

    @transaction.atomic
    def mark_verification_success(
        self,
        *,
        managed_key: CryptoManagedKeyModel,
    ) -> CryptoManagedKeyModel:
        """Mark a managed key as successfully verified against the provider."""
        managed_key.status = ManagedKeyStatus.ACTIVE
        managed_key.last_verified_at = timezone.now()
        managed_key.last_verification_error = ''
        _save_untyped_model(
            managed_key,
            update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'],
        )
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
        _save_untyped_model(
            managed_key,
            update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'],
        )
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
        _save_untyped_model(
            managed_key,
            update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'],
        )
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
        _save_untyped_model(
            managed_key,
            update_fields=['status', 'last_verified_at', 'last_verification_error', 'updated_at'],
        )
        return managed_key

    @staticmethod
    def build_managed_key_ref(managed_key: CryptoManagedKeyModel) -> ManagedKeyRef:
        """Convert a persisted managed-key record back into a domain ref."""
        return managed_key.to_managed_key_ref()

    @staticmethod
    def build_backend_binding(managed_key: CryptoManagedKeyModel) -> ManagedKeyBinding:
        """Convert a persisted managed-key record into the backend-specific binding."""
        algorithm = KeyAlgorithm(managed_key.algorithm)
        signing_execution_mode = SigningExecutionMode(managed_key.signing_execution_mode)

        try:
            protected_import_binding = managed_key.protected_import_binding
        except CryptoManagedKeyProtectedImportBindingModel.DoesNotExist:
            protected_import_binding = None

        if protected_import_binding is not None:
            return ProtectedImportManagedKeyBinding(
                key_handle=protected_import_binding.key_handle,
                algorithm=algorithm,
                encrypted_private_key_pkcs8_der_b64=protected_import_binding.encrypted_private_key_pkcs8_der_b64,
                encryption_metadata=protected_import_binding.encryption_metadata,
                public_key_fingerprint_sha256=managed_key.public_key_fingerprint_sha256,
                signing_execution_mode=signing_execution_mode,
                provider_label=_optional_domain_text(managed_key.provider_label),
            )

        if managed_key.provider_profile.backend_kind == BackendKind.PKCS11:
            pkcs11_binding = managed_key.pkcs11_binding
            return Pkcs11ManagedKeyBinding(
                key_id=bytes.fromhex(pkcs11_binding.key_id_hex),
                algorithm=algorithm,
                public_key_fingerprint_sha256=managed_key.public_key_fingerprint_sha256,
                signing_execution_mode=signing_execution_mode,
                provider_label=_optional_domain_text(managed_key.provider_label),
            )

        if managed_key.provider_profile.backend_kind == BackendKind.SOFTWARE:
            software_binding = managed_key.software_binding
            return SoftwareManagedKeyBinding(
                key_handle=software_binding.key_handle,
                algorithm=algorithm,
                encrypted_private_key_pkcs8_der=bytes(software_binding.encrypted_private_key_pkcs8_der),
                encryption_metadata=software_binding.encryption_metadata,
                public_key_fingerprint_sha256=managed_key.public_key_fingerprint_sha256,
                signing_execution_mode=signing_execution_mode,
                provider_label=_optional_domain_text(managed_key.provider_label),
            )

        if managed_key.provider_profile.backend_kind == BackendKind.REST:
            rest_binding = managed_key.rest_binding
            return RestManagedKeyBinding(
                remote_key_id=rest_binding.remote_key_id,
                algorithm=algorithm,
                remote_key_version=_optional_domain_text(rest_binding.remote_key_version),
                public_key_fingerprint_sha256=managed_key.public_key_fingerprint_sha256,
                signing_execution_mode=signing_execution_mode,
                provider_label=_optional_domain_text(managed_key.provider_label),
            )

        msg = f'Unsupported backend kind {managed_key.provider_profile.backend_kind!r}.'
        raise UnsupportedBackendKindError(msg)

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

    @staticmethod
    def _validate_profile_binding_compatibility(
        profile: CryptoProviderProfileModel,
        binding: ManagedKeyBinding,
    ) -> None:
        """Validate that a binding instance matches the owning backend kind."""
        if profile.backend_kind == BackendKind.PKCS11 and isinstance(binding, Pkcs11ManagedKeyBinding):
            return
        if profile.backend_kind == BackendKind.PKCS11 and isinstance(binding, ProtectedImportManagedKeyBinding):
            return
        if profile.backend_kind == BackendKind.SOFTWARE and isinstance(binding, ProtectedImportManagedKeyBinding):
            return
        if profile.backend_kind == BackendKind.SOFTWARE and isinstance(binding, SoftwareManagedKeyBinding):
            return
        if profile.backend_kind == BackendKind.REST and isinstance(binding, RestManagedKeyBinding):
            return

        msg = (
            f'Backend binding type {type(binding).__name__} does not match '
            f'provider backend kind {profile.backend_kind!r}.'
        )
        raise InternalConsistencyError(msg)

    @staticmethod
    def _persist_backend_binding(
        *,
        profile: CryptoProviderProfileModel,
        managed_key: CryptoManagedKeyModel,
        binding: ManagedKeyBinding,
    ) -> None:
        """Persist the backend-specific binding record."""
        if profile.backend_kind == BackendKind.PKCS11 and isinstance(binding, Pkcs11ManagedKeyBinding):
            pkcs11_model = CryptoManagedKeyPkcs11BindingModel(
                managed_key=managed_key,
                provider_profile=profile,
                key_id_hex=binding.key_id_hex,
            )
            pkcs11_model.full_clean()
            _save_untyped_model(pkcs11_model)
            return

        if profile.backend_kind == BackendKind.PKCS11 and isinstance(binding, ProtectedImportManagedKeyBinding):
            protected_import_model = CryptoManagedKeyProtectedImportBindingModel(
                managed_key=managed_key,
                provider_profile=profile,
                key_handle=binding.key_handle,
                encrypted_private_key_pkcs8_der_b64=binding.encrypted_private_key_pkcs8_der_b64,
                encryption_metadata=binding.encryption_metadata,
            )
            protected_import_model.full_clean()
            _save_untyped_model(protected_import_model)
            return

        if profile.backend_kind == BackendKind.SOFTWARE and isinstance(binding, ProtectedImportManagedKeyBinding):
            protected_import_model = CryptoManagedKeyProtectedImportBindingModel(
                managed_key=managed_key,
                provider_profile=profile,
                key_handle=binding.key_handle,
                encrypted_private_key_pkcs8_der_b64=binding.encrypted_private_key_pkcs8_der_b64,
                encryption_metadata=binding.encryption_metadata,
            )
            protected_import_model.full_clean()
            _save_untyped_model(protected_import_model)
            return

        if profile.backend_kind == BackendKind.SOFTWARE and isinstance(binding, SoftwareManagedKeyBinding):
            software_model = CryptoManagedKeySoftwareBindingModel(
                managed_key=managed_key,
                provider_profile=profile,
                key_handle=binding.key_handle,
                encrypted_private_key_pkcs8_der=binding.encrypted_private_key_pkcs8_der,
                encryption_metadata=binding.encryption_metadata,
            )
            software_model.full_clean()
            _save_untyped_model(software_model)
            return

        if profile.backend_kind == BackendKind.REST and isinstance(binding, RestManagedKeyBinding):
            rest_model = CryptoManagedKeyRestBindingModel(
                managed_key=managed_key,
                provider_profile=profile,
                remote_key_id=binding.remote_key_id,
                remote_key_version=_optional_db_text(binding.remote_key_version),
            )
            rest_model.full_clean()
            _save_untyped_model(rest_model)
            return

        msg = (
            f'Cannot persist binding type {type(binding).__name__} for '
            f'backend kind {profile.backend_kind!r}.'
        )
        raise InternalConsistencyError(msg)
