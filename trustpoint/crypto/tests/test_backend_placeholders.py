"""Tests for backend placeholder and environment guard behavior."""

from __future__ import annotations

import pytest

from crypto.adapters.rest.backend import RestBackend
from crypto.adapters.rest.config import RestProviderProfile
from crypto.adapters.software.backend import SoftwareBackend
from crypto.adapters.software.config import SoftwareProviderProfile
from crypto.domain.errors import DevelopmentOnlyBackendError, ProviderOperationNotImplementedError


def test_rest_backend_scaffold_is_not_operational() -> None:
    backend = RestBackend(
        profile=RestProviderProfile(
            name='rest-placeholder',
            base_url='https://example.invalid',
            auth_type='none',
        )
    )

    with pytest.raises(ProviderOperationNotImplementedError, match='cannot be configured'):
        backend.verify_provider()
