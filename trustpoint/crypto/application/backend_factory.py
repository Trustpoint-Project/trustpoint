"""Backend-adapter factory for provider profiles."""

from __future__ import annotations

from typing import Protocol

from django.core.exceptions import ObjectDoesNotExist, ValidationError

from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.adapters.rest.backend import RestBackend
from crypto.adapters.software.backend import SoftwareBackend
from crypto.application.provider_backend import ManagedKeyBackendAdapter
from crypto.domain.errors import ProviderConfigurationError, UnsupportedBackendKindError
from crypto.models import BackendKind, CryptoProviderProfileModel


class BackendAdapterFactory(Protocol):
    """Factory protocol for constructing backend-kind-specific adapters."""

    def build(self, profile_model: CryptoProviderProfileModel) -> ManagedKeyBackendAdapter:
        """Build an adapter for the given provider profile."""


class DefaultBackendAdapterFactory:
    """Default backend-adapter factory."""

    def build(self, profile_model: CryptoProviderProfileModel) -> ManagedKeyBackendAdapter:
        """Construct the configured backend adapter."""
        try:
            if profile_model.backend_kind == BackendKind.PKCS11:
                return Pkcs11Backend(profile=profile_model.pkcs11_config.build_provider_profile())

            if profile_model.backend_kind == BackendKind.SOFTWARE:
                return SoftwareBackend(profile=profile_model.software_config.build_provider_profile())

            if profile_model.backend_kind == BackendKind.REST:
                return RestBackend(profile=profile_model.rest_config.build_provider_profile())
        except ObjectDoesNotExist as exc:
            msg = (
                f'Provider profile {profile_model.name!r} is missing its '
                f'{profile_model.backend_kind!r} backend configuration.'
            )
            raise ProviderConfigurationError(msg) from exc
        except ValidationError as exc:
            msg = f'Provider profile {profile_model.name!r} is invalid.'
            raise ProviderConfigurationError(msg) from exc

        msg = f'Unsupported backend kind {profile_model.backend_kind!r}.'
        raise UnsupportedBackendKindError(msg)
