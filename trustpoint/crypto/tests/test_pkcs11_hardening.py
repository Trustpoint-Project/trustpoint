# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Security hardening tests for PKCS#11 provider configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector, validate_pkcs11_module_path
from crypto.domain.errors import ProviderConfigurationError


def test_provider_profile_requires_token_serial() -> None:
    """A real provider profile cannot rely on label or slot identity alone."""
    with pytest.raises(ProviderConfigurationError, match='require token_serial'):
        Pkcs11ProviderProfile(
            name='provider',
            module_path='/usr/lib/missing-test-pkcs11.so',
            token=Pkcs11TokenSelector(token_label='expected-token'),
            user_pin_env_var='TRUSTPOINT_TEST_PIN',
        )


def test_serial_mismatch_cannot_fall_back_to_matching_label() -> None:
    """A matching label never overrides a configured serial-number mismatch."""
    selector = Pkcs11TokenSelector(
        token_label='expected-token',
        token_serial='expected-serial',
        slot_id=7,
    )

    assert not selector.matches(
        slot_id=7,
        token_label='expected-token',
        token_serial='attacker-serial',
    )


def test_serial_pinning_survives_slot_change() -> None:
    """Token serial remains the stable identity when slot numbering changes."""
    selector = Pkcs11TokenSelector(
        token_label='expected-token',
        token_serial='expected-serial',
        slot_id=7,
    )

    assert selector.matches(
        slot_id=8,
        token_label='expected-token',
        token_serial='expected-serial',
    )


def test_module_path_must_be_absolute() -> None:
    """Relative module paths are rejected before a native library can be loaded."""
    with pytest.raises(ProviderConfigurationError, match='must be absolute'):
        validate_pkcs11_module_path('relative/provider.so')


def test_module_path_rejects_world_writable_parent() -> None:
    """Provider libraries cannot be selected from a world-writable directory."""
    with pytest.raises(ProviderConfigurationError, match='group- or world-writable'):
        validate_pkcs11_module_path('/tmp/trustpoint-provider.so')


def test_module_path_accepts_staged_absolute_path_under_protected_parent() -> None:
    """A missing staged module is allowed when its existing parent path is protected."""
    normalized = validate_pkcs11_module_path('/usr/lib/trustpoint-provider-not-installed.so')

    assert Path(normalized).is_absolute()
