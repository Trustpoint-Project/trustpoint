"""Integration tests against a configured live PKCS#11 provider."""

from __future__ import annotations

import pytest

from crypto.adapters.pkcs11.backend import Pkcs11Backend


pytestmark = [pytest.mark.integration, pytest.mark.hsm, pytest.mark.django_db]


def test_refresh_capabilities_returns_non_empty_mechanism_set(
    live_pkcs11_backend: Pkcs11Backend,
    live_pkcs11_capabilities,
) -> None:
    assert live_pkcs11_capabilities.mechanisms
    assert any(
        live_pkcs11_capabilities.derived_features.get(name, False)
        for name in (
            "can_generate_rsa",
            "can_generate_ec",
            "can_sign_rsa_pkcs1v15",
            "can_sign_rsa_pss",
            "can_sign_ecdsa",
        )
    )


def test_verify_provider_reprobes(live_pkcs11_backend: Pkcs11Backend) -> None:
    live_pkcs11_backend.verify_provider()
    capabilities = live_pkcs11_backend.current_capabilities()
    assert capabilities is not None
    assert capabilities.mechanisms
