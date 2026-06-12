"""Tests for backend placeholder and environment guard behavior."""

from __future__ import annotations

import pytest

from crypto.adapters.rest.backend import RestBackend
from crypto.adapters.rest.config import RestProviderProfile
from crypto.domain.errors import ProviderOperationNotImplementedError


def test_crypto_package_exports_trustpoint_crypto_backend() -> None:
    """Package-level service export resolves lazily when explicitly requested."""
    from crypto import TrustpointCryptoBackend  # noqa: PLC0415
    from crypto.application.service import TrustpointCryptoBackend as ServiceBackend  # noqa: PLC0415

    assert isinstance(TrustpointCryptoBackend(), ServiceBackend)


def test_rest_backend_scaffold_is_not_operational() -> None:
    """REST backend scaffold rejects operational verification."""
    backend = RestBackend(
        profile=RestProviderProfile(
            name='rest-placeholder',
            base_url='https://example.invalid',
            auth_type='none',
        )
    )

    with pytest.raises(ProviderOperationNotImplementedError, match='cannot be configured'):
        backend.verify_provider()
