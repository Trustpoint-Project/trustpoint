"""Shared pytest fixtures for crypto tests."""

from __future__ import annotations

import pytest

from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.domain.errors import (
    AuthenticationError,
    ProviderConfigurationError,
    ProviderUnavailableError,
    SessionUnavailableError,
)
from crypto.models import CryptoProviderProfileModel


@pytest.fixture
def live_pkcs11_backend(db) -> Pkcs11Backend:
    """Return a backend connected to a live PKCS#11 token or skip cleanly."""
    profile_model = CryptoProviderProfileModel.objects.filter(active=True).order_by("id").first()
    if profile_model is None:
        profile_model = CryptoProviderProfileModel.objects.order_by("id").first()

    if profile_model is None:
        pytest.skip("Skipping PKCS#11 integration tests: no crypto provider profile is configured.")

    try:
        profile = profile_model.build_provider_profile()
    except ProviderConfigurationError as exc:
        pytest.skip(f"Skipping PKCS#11 integration tests: provider profile is invalid ({exc}).")

    backend = Pkcs11Backend(profile=profile)

    try:
        backend.refresh_capabilities()
    except (
        ProviderUnavailableError,
        AuthenticationError,
        SessionUnavailableError,
        ProviderConfigurationError,
    ) as exc:
        pytest.skip(f"Skipping PKCS#11 integration tests: no usable HSM/token is available ({exc}).")

    return backend


@pytest.fixture
def live_pkcs11_capabilities(live_pkcs11_backend: Pkcs11Backend):
    """Return the current live PKCS#11 capability snapshot."""
    current = live_pkcs11_backend.current_capabilities()
    if current is not None:
        return current
    return live_pkcs11_backend.refresh_capabilities()
