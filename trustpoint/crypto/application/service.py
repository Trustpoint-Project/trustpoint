"""Application-facing crypto backend service."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError

from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.domain.errors import CryptoError, KeyNotFoundError, ProviderConfigurationError
from crypto.domain.refs import ManagedKeyRef, ManagedKeyVerification, ManagedKeyVerificationStatus
from crypto.models import CryptoManagedKeyModel, CryptoProviderProfileModel
from crypto.repositories import CryptoManagedKeyRepository, CryptoProviderProfileRepository
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding
    from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile
    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.policies import KeyPolicy
    from crypto.domain.specs import KeySpec, SignRequest

type AdapterFactory = Callable[[Pkcs11ProviderProfile], Pkcs11Backend]


class TrustpointCryptoBackend(LoggerMixin):
    """Stateless application-facing crypto backend for Trustpoint."""

    provider_name = 'trustpoint'

    def __init__(
        self,
        *,
        profile_repository: CryptoProviderProfileRepository | None = None,
        managed_key_repository: CryptoManagedKeyRepository | None = None,
        adapter_factory: AdapterFactory | None = None,
    ) -> None:
        """Initialize the application-facing crypto backend."""
        self._profile_repository = profile_repository or CryptoProviderProfileRepository()
        self._managed_key_repository = managed_key_repository or CryptoManagedKeyRepository()
        self._adapter_factory = adapter_factory or (lambda profile: Pkcs11Backend(profile=profile))

    def verify_provider(self) -> None:
        """Validate that the active provider can be loaded and used."""
        profile = self._get_active_profile()
        adapter = self._build_adapter(profile)
        try:
            adapter.verify_provider()
        finally:
            adapter.close()

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> ManagedKeyRef:
        """Generate a managed key and persist its application binding."""
        profile = self._get_active_profile()
        adapter = self._build_adapter(profile)

        try:
            binding = adapter.generate_managed_key(alias=alias, key_spec=key_spec, policy=policy)
            public_key = adapter.get_public_key(binding)
            managed_key = self._managed_key_repository.create_managed_key(
                profile=profile,
                alias=alias,
                binding=binding,
                public_key=public_key,
                policy=policy,
            )
        except Exception:
            if 'binding' in locals():
                self._cleanup_orphaned_binding(adapter=adapter, alias=alias, binding=binding)
            raise
        finally:
            adapter.close()

        return managed_key.to_managed_key_ref()

    def verify_managed_key(self, key: ManagedKeyRef) -> ManagedKeyVerification:
        """Verify that a managed-key reference still resolves correctly."""
        managed_key = self._load_managed_key(key)
        app_ref = managed_key.to_managed_key_ref()
        adapter = self._build_adapter(managed_key.provider_profile)

        try:
            binding = self._managed_key_repository.build_pkcs11_binding(managed_key)
            verification = adapter.verify_managed_key(binding)
        except CryptoError as exc:
            self._managed_key_repository.mark_error(managed_key=managed_key, error_summary=str(exc))
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

        return ManagedKeyVerification(
            key=app_ref,
            status=verification.status,
            resolved_public_key_fingerprint_sha256=verification.resolved_public_key_fingerprint_sha256,
        )

    def get_public_key(self, key: ManagedKeyRef) -> SupportedPublicKey:
        """Load the public key for a managed key."""
        managed_key = self._load_managed_key(key)
        adapter = self._build_adapter(managed_key.provider_profile)
        try:
            return adapter.get_public_key(self._managed_key_repository.build_pkcs11_binding(managed_key))
        finally:
            adapter.close()

    def sign(self, *, key: ManagedKeyRef, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes with a managed key."""
        managed_key = self._load_managed_key(key)
        adapter = self._build_adapter(managed_key.provider_profile)
        try:
            return adapter.sign(
                key=self._managed_key_repository.build_pkcs11_binding(managed_key),
                data=data,
                request=request,
            )
        finally:
            adapter.close()

    def _get_active_profile(self) -> CryptoProviderProfileModel:
        """Return the active provider profile or raise a configuration error."""
        try:
            return self._profile_repository.get_active_profile()
        except CryptoProviderProfileModel.DoesNotExist as exc:
            msg = 'No active crypto provider profile is configured.'
            raise ProviderConfigurationError(msg) from exc

    def _load_managed_key(self, key: ManagedKeyRef) -> CryptoManagedKeyModel:
        """Resolve an application-facing managed key reference to its stored binding."""
        try:
            return self._managed_key_repository.get_by_id(managed_key_id=key.id)
        except CryptoManagedKeyModel.DoesNotExist as exc:
            msg = f'Managed key {key.id} does not exist.'
            raise KeyNotFoundError(msg) from exc

    def _build_adapter(self, profile_model: CryptoProviderProfileModel) -> Pkcs11Backend:
        """Build a PKCS#11 adapter for a persisted provider profile."""
        try:
            provider_profile = profile_model.build_provider_profile()
        except ValidationError as exc:
            msg = f'Provider profile {profile_model.name!r} is invalid.'
            raise ProviderConfigurationError(msg) from exc
        return self._adapter_factory(provider_profile)

    def _cleanup_orphaned_binding(
        self,
        *,
        adapter: Pkcs11Backend,
        alias: str,
        binding: Pkcs11ManagedKeyBinding,
    ) -> None:
        """Best-effort cleanup of a generated key if DB persistence fails."""
        try:
            adapter.destroy_managed_key(binding)
        except CryptoError as exc:
            self.logger.warning(
                'Failed to clean up orphaned PKCS#11 managed key for alias %r after persistence failure: %s',
                alias,
                exc,
            )
