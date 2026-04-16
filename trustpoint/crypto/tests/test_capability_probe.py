"""Unit tests for PKCS#11 capability probing."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from crypto.adapters.pkcs11.capability_probe import (
    Pkcs11Capabilities,
    Pkcs11CapabilityProbe,
)
from crypto.domain.errors import ProviderUnavailableError
from pkcs11 import Mechanism


@dataclass
class FakeMechanismInfo:
    flags: tuple[str, ...]
    min_key_size: int | None = None
    max_key_size: int | None = None


class FakeSlot:
    slot_id = 7
    cryptoki_version = None

    def __init__(self) -> None:
        self._mechanisms = {
            Mechanism.RSA_PKCS,
            Mechanism.RSA_PKCS_KEY_PAIR_GEN,
            Mechanism.ECDSA,
            Mechanism.EC_KEY_PAIR_GEN,
        }

    def get_mechanisms(self):
        return self._mechanisms

    def get_mechanism_info(self, mechanism):
        if mechanism in {Mechanism.RSA_PKCS, Mechanism.RSA_PKCS_KEY_PAIR_GEN}:
            return FakeMechanismInfo(flags=('SIGN', 'VERIFY'), min_key_size=1024, max_key_size=4096)
        if mechanism in {Mechanism.ECDSA, Mechanism.EC_KEY_PAIR_GEN}:
            return FakeMechanismInfo(flags=('SIGN', 'VERIFY'), min_key_size=256, max_key_size=521)
        raise AssertionError(f'Unexpected mechanism: {mechanism!r}')


class FakeToken:
    label = 'Test Token   '
    serial = b'12345678    '
    model = 'Simulator'
    manufacturer = 'Test Vendor'
    hardware_version = None
    firmware_version = None
    flags = ('LOGIN_REQUIRED', 'USER_PIN_INITIALIZED')


def test_probe_produces_serializable_snapshot() -> None:
    capabilities = Pkcs11CapabilityProbe().probe(slot=FakeSlot(), token=FakeToken())
    payload = capabilities.to_json_dict()

    rebuilt = Pkcs11Capabilities.from_json_dict(payload)

    assert rebuilt.token.serial == '12345678'
    assert 'CKM_RSA_PKCS' in rebuilt.mechanisms
    assert rebuilt.derived_features['can_generate_rsa'] is True
    assert rebuilt.derived_features['can_sign_ecdsa'] is True


def test_probe_fingerprint_is_stable_for_same_contents() -> None:
    probe = Pkcs11CapabilityProbe()

    first = probe.probe(slot=FakeSlot(), token=FakeToken())
    second = probe.probe(slot=FakeSlot(), token=FakeToken())

    assert first.fingerprint() == second.fingerprint()


def test_probe_requires_slot_get_mechanisms() -> None:
    class BrokenSlot(FakeSlot):
        get_mechanisms = None  # type: ignore[assignment]

    with pytest.raises(ProviderUnavailableError):
        Pkcs11CapabilityProbe().probe(slot=BrokenSlot(), token=FakeToken())


def test_probe_requires_slot_get_mechanism_info() -> None:
    class BrokenSlot(FakeSlot):
        get_mechanism_info = None  # type: ignore[assignment]

    with pytest.raises(ProviderUnavailableError):
        Pkcs11CapabilityProbe().probe(slot=BrokenSlot(), token=FakeToken())
