"""Application-facing crypto backend service."""

from __future__ import annotations

from time import perf_counter
from typing import TYPE_CHECKING, cast

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import DatabaseError

from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding
from crypto.adapters.rest.bindings import RestManagedKeyBinding
from crypto.adapters.software.bindings import SoftwareManagedKeyBinding
from crypto.application.audit import (
    audit_crypto_backend_operation,
    key_policy_audit_details,
    key_spec_audit_details,
    sign_request_audit_details,
)
from crypto.application.backend_factory import BackendAdapterFactory, DefaultBackendAdapterFactory
from crypto.application.capabilities import BackendCapabilityService
from crypto.domain.errors import CryptoError, KeyNotFoundError, ProviderConfigurationError, UnsupportedKeySpecError
from crypto.domain.refs import ManagedKeyRef, ManagedKeyVerification, ManagedKeyVerificationStatus
from crypto.models import CryptoManagedKeyModel, CryptoProviderProfileModel
from crypto.repositories import CryptoManagedKeyRepository, CryptoProviderProfileRepository, ManagedKeyBinding
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from crypto.application.provider_backend import ManagedKeyBackendAdapter
    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.policies import KeyPolicy
    from crypto.domain.specs import KeySpec, SignRequest


class TrustpointCryptoBackend(LoggerMixin):
    """Stateless application-facing crypto service for the configured instance backend."""

    provider_name = 'trustpoint'

    def __init__(
        self,
        *,
        profile_repository: CryptoProviderProfileRepository | None = None,
        managed_key_repository: CryptoManagedKeyRepository | None = None,
        adapter_factory: BackendAdapterFactory | None = None,
    ) -> None:
        """Initialize the application-facing crypto backend."""
        self._profile_repository: CryptoProviderProfileRepository = (
            profile_repository or CryptoProviderProfileRepository()
        )
        self._managed_key_repository: CryptoManagedKeyRepository = (
            managed_key_repository or CryptoManagedKeyRepository()
        )
        self._adapter_factory: BackendAdapterFactory = adapter_factory or DefaultBackendAdapterFactory()

    def verify_provider(self) -> None:
        """Validate that the configured instance backend can be loaded and used."""
        profile = self._get_configured_profile()
        adapter = self._build_adapter(profile)
        started_at = perf_counter()
        try:
            adapter.verify_provider()
        except (CryptoError, DatabaseError, DjangoValidationError, RuntimeError, TypeError, ValueError) as exc:
            audit_crypto_backend_operation(
                operation='verify_provider',
                target=profile,
                target_display=self._profile_target_display(profile),
                started_at=started_at,
                status='error',
                profile=profile,
                error=exc,
            )
            raise
        else:
            audit_crypto_backend_operation(
                operation='verify_provider',
                target=profile,
                target_display=self._profile_target_display(profile),
                started_at=started_at,
                status='success',
                profile=profile,
            )
        finally:
            adapter.close()

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> ManagedKeyRef:
        """Generate a managed key using the configured instance backend."""
        profile = self._get_configured_profile()
        capability_report = BackendCapabilityService(
            profile_repository=self._profile_repository,
            adapter_factory=self._adapter_factory,
        ).active_report()
        if capability_report.capabilities_known and not capability_report.supports_key_spec(key_spec):
            diagnostics = '; '.join(capability_report.diagnostics) or f'unsupported key spec {key_spec!r}'
            msg = f'The configured crypto backend cannot generate key {alias!r}: {diagnostics}'
            raise UnsupportedKeySpecError(msg)

        adapter = self._build_adapter(profile)
        binding: ManagedKeyBinding | None = None
        managed_key: CryptoManagedKeyModel | None = None
        started_at = perf_counter()
        details = {
            'alias': alias,
            **key_spec_audit_details(key_spec),
            **key_policy_audit_details(policy),
        }

        try:
            raw_binding = adapter.generate_managed_key(alias=alias, key_spec=key_spec, policy=policy)
            binding = self._managed_key_binding_or_error(raw_binding)
            public_key = adapter.get_public_key(binding)
            managed_key = self._managed_key_repository.create_managed_key(
                profile=profile,
                alias=alias,
                provider_label=getattr(binding, 'provider_label', None) or alias,
                binding=binding,
                public_key=public_key,
                policy=policy,
            )
        except (CryptoError, DatabaseError, DjangoValidationError, RuntimeError, TypeError, ValueError) as exc:
            if binding is not None:
                self._cleanup_orphaned_binding(adapter=adapter, alias=alias, binding=binding)
            audit_crypto_backend_operation(
                operation='generate_managed_key',
                target=managed_key or profile,
                target_display=(
                    self._managed_key_target_display(managed_key)
                    if managed_key is not None
                    else self._profile_target_display(profile)
                ),
                started_at=started_at,
                status='error',
                profile=profile,
                managed_key=managed_key,
                details=details,
                error=exc,
            )
            raise
        else:
            if managed_key is None:
                msg = 'Backend generated a key but no managed-key record was persisted.'
                raise ProviderConfigurationError(msg)
            audit_crypto_backend_operation(
                operation='generate_managed_key',
                target=managed_key,
                target_display=self._managed_key_target_display(managed_key),
                started_at=started_at,
                status='success',
                profile=profile,
                managed_key=managed_key,
                details=details,
            )
        finally:
            adapter.close()

        return managed_key.to_managed_key_ref()

    def verify_managed_key(self, key: ManagedKeyRef) -> ManagedKeyVerification:
        """Verify that a managed-key reference still resolves correctly."""
        managed_key = self._load_managed_key(key)
        app_ref = managed_key.to_managed_key_ref()
        adapter = self._build_adapter(managed_key.provider_profile)
        started_at = perf_counter()

        try:
            binding = self._managed_key_repository.build_backend_binding(managed_key)
            verification = adapter.verify_managed_key(binding)
        except CryptoError as exc:
            self._managed_key_repository.mark_error(managed_key=managed_key, error_summary=str(exc))
            audit_crypto_backend_operation(
                operation='verify_managed_key',
                target=managed_key,
                target_display=self._managed_key_target_display(managed_key),
                started_at=started_at,
                status='error',
                profile=managed_key.provider_profile,
                managed_key=managed_key,
                error=exc,
            )
            raise
        finally:
            adapter.close()

        if verification.status is ManagedKeyVerificationStatus.PRESENT:
            self._managed_key_repository.mark_verification_success(managed_key=managed_key)
        elif verification.status is ManagedKeyVerificationStatus.MISSING:
            self._managed_key_repository.mark_missing(
                managed_key=managed_key,
                error_summary='Managed key binding is missing from the provider.',
            )
        else:
            self._managed_key_repository.mark_mismatch(
                managed_key=managed_key,
                error_summary='Managed key binding resolved to a different public key.',
            )

        audit_crypto_backend_operation(
            operation='verify_managed_key',
            target=managed_key,
            target_display=self._managed_key_target_display(managed_key),
            started_at=started_at,
            status='success',
            profile=managed_key.provider_profile,
            managed_key=managed_key,
            details={'verification_status': verification.status.value},
        )

        return ManagedKeyVerification(
            key=app_ref,
            status=verification.status,
            resolved_public_key_fingerprint_sha256=verification.resolved_public_key_fingerprint_sha256,
        )

    def get_public_key(self, key: ManagedKeyRef) -> SupportedPublicKey:
        """Load the public key for a managed key."""
        managed_key = self._load_managed_key(key)
        adapter = self._build_adapter(managed_key.provider_profile)
        started_at = perf_counter()
        try:
            public_key = adapter.get_public_key(self._managed_key_repository.build_backend_binding(managed_key))
        except (CryptoError, DatabaseError, DjangoValidationError, RuntimeError, TypeError, ValueError) as exc:
            audit_crypto_backend_operation(
                operation='get_public_key',
                target=managed_key,
                target_display=self._managed_key_target_display(managed_key),
                started_at=started_at,
                status='error',
                profile=managed_key.provider_profile,
                managed_key=managed_key,
                error=exc,
            )
            raise
        else:
            audit_crypto_backend_operation(
                operation='get_public_key',
                target=managed_key,
                target_display=self._managed_key_target_display(managed_key),
                started_at=started_at,
                status='success',
                profile=managed_key.provider_profile,
                managed_key=managed_key,
            )
            return public_key
        finally:
            adapter.close()

    def sign(self, *, key: ManagedKeyRef, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes with a managed key."""
        managed_key = self._load_managed_key(key)
        adapter = self._build_adapter(managed_key.provider_profile)
        started_at = perf_counter()
        details = sign_request_audit_details(request, data_length=len(data))
        try:
            signature = adapter.sign(
                key=self._managed_key_repository.build_backend_binding(managed_key),
                data=data,
                request=request,
            )
        except (CryptoError, DatabaseError, DjangoValidationError, RuntimeError, TypeError, ValueError) as exc:
            audit_crypto_backend_operation(
                operation='sign',
                target=managed_key,
                target_display=self._managed_key_target_display(managed_key),
                started_at=started_at,
                status='error',
                profile=managed_key.provider_profile,
                managed_key=managed_key,
                details=details,
                error=exc,
            )
            raise
        else:
            audit_crypto_backend_operation(
                operation='sign',
                target=managed_key,
                target_display=self._managed_key_target_display(managed_key),
                started_at=started_at,
                status='success',
                profile=managed_key.provider_profile,
                managed_key=managed_key,
                details=details,
            )
            return signature
        finally:
            adapter.close()

    def destroy_managed_key(self, key: ManagedKeyRef) -> None:
        """Destroy an unreferenced managed key in the backend and remove its binding record."""
        managed_key = self._load_managed_key(key)
        profile = managed_key.provider_profile
        target_display = self._managed_key_target_display(managed_key)
        adapter = self._build_adapter(managed_key.provider_profile)
        started_at = perf_counter()
        try:
            adapter.destroy_managed_key(self._managed_key_repository.build_backend_binding(managed_key))
        except (CryptoError, DatabaseError, DjangoValidationError, RuntimeError, TypeError, ValueError) as exc:
            audit_crypto_backend_operation(
                operation='destroy_managed_key',
                target=managed_key,
                target_display=target_display,
                started_at=started_at,
                status='error',
                profile=profile,
                managed_key=managed_key,
                error=exc,
            )
            raise
        else:
            audit_crypto_backend_operation(
                operation='destroy_managed_key',
                target=managed_key,
                target_display=target_display,
                started_at=started_at,
                status='success',
                profile=profile,
                managed_key=managed_key,
            )
        finally:
            adapter.close()

        managed_key.delete()

    def _get_configured_profile(self) -> CryptoProviderProfileModel:
        """Return the configured instance backend profile or raise a configuration error."""
        try:
            return self._profile_repository.get_configured_profile()
        except CryptoProviderProfileModel.DoesNotExist as exc:
            msg = 'No configured crypto backend profile exists for this Trustpoint instance.'
            raise ProviderConfigurationError(msg) from exc

    def _load_managed_key(self, key: ManagedKeyRef) -> CryptoManagedKeyModel:
        """Resolve an application-facing managed-key reference to its stored binding."""
        try:
            return self._managed_key_repository.get_by_id(managed_key_id=key.id)
        except CryptoManagedKeyModel.DoesNotExist as exc:
            msg = f'Managed key {key.id} does not exist.'
            raise KeyNotFoundError(msg) from exc

    def _build_adapter(self, profile_model: CryptoProviderProfileModel) -> ManagedKeyBackendAdapter:
        """Build a backend-kind-specific adapter for a persisted provider profile."""
        return cast('ManagedKeyBackendAdapter', self._adapter_factory.build(profile_model))

    @staticmethod
    def _profile_target_display(profile: CryptoProviderProfileModel) -> str:
        """Return a stable audit display label for a provider profile."""
        return f'Crypto backend profile: {profile.name}'

    @staticmethod
    def _managed_key_target_display(managed_key: CryptoManagedKeyModel) -> str:
        """Return a stable audit display label for a managed key."""
        return f'Managed crypto key: {managed_key.alias}'

    @staticmethod
    def _managed_key_binding_or_error(binding: object) -> ManagedKeyBinding:
        """Return a concrete managed-key binding or raise a configuration error."""
        if isinstance(binding, (Pkcs11ManagedKeyBinding, SoftwareManagedKeyBinding, RestManagedKeyBinding)):
            return binding

        msg = f'Backend adapter returned unsupported managed-key binding type {type(binding).__name__}.'
        raise ProviderConfigurationError(msg)

    def _cleanup_orphaned_binding(
        self,
        *,
        adapter: ManagedKeyBackendAdapter,
        alias: str,
        binding: ManagedKeyBinding,
    ) -> None:
        """Best-effort cleanup of a generated key if DB persistence fails."""
        try:
            adapter.destroy_managed_key(binding)
        except CryptoError as exc:
            self.logger.warning(
                'Failed to clean up orphaned managed key for alias %r after persistence failure: %s',
                alias,
                exc,
            )
