"""Tests for PKCS#11 adapter configuration helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from crypto.adapters.pkcs11.config import (
    Pkcs11ProviderProfile,
    Pkcs11TokenSelector,
    _normalize_pkcs11_text,
)
from crypto.domain.errors import ProviderConfigurationError


def test_normalize_pkcs11_text_accepts_str() -> None:
    assert _normalize_pkcs11_text('  token-serial\x00   ') == 'token-serial'


def test_normalize_pkcs11_text_accepts_bytes() -> None:
    assert _normalize_pkcs11_text(b'token-serial\x00   ') == 'token-serial'


def test_token_selector_matches_binding_bytes_serial() -> None:
    selector = Pkcs11TokenSelector(token_serial='87de2f12e07ee8a5')

    assert selector.matches(
        slot_id=0,
        token_label='Trustpoint-SoftHSM',
        token_serial=b'87de2f12e07ee8a5',
    )


def test_token_selector_matches_binding_bytes_label() -> None:
    selector = Pkcs11TokenSelector(token_label='Trustpoint-SoftHSM')

    assert selector.matches(
        slot_id=0,
        token_label=b'Trustpoint-SoftHSM',
        token_serial='87de2f12e07ee8a5',
    )


def test_token_selector_rejects_mismatched_serial() -> None:
    selector = Pkcs11TokenSelector(token_serial='expected')

    assert not selector.matches(
        slot_id=0,
        token_label='Trustpoint-SoftHSM',
        token_serial=b'actual',
    )


def test_provider_profile_requires_exactly_one_pin_source(tmp_path: Path) -> None:
    pin_file = tmp_path / 'user-pin.txt'
    pin_file.write_text('secret-pin', encoding='utf-8')

    with pytest.raises(ProviderConfigurationError, match='Exactly one PKCS#11 user PIN source'):
        Pkcs11ProviderProfile(
            name='local-dev-softhsm',
            module_path='/usr/lib/libpkcs11-proxy.so',
            token=Pkcs11TokenSelector(token_serial='87de2f12e07ee8a5'),
            user_pin='inline-secret',
            user_pin_file=str(pin_file),
        )


def test_provider_profile_reads_user_pin_from_file(tmp_path: Path) -> None:
    pin_file = tmp_path / 'user-pin.txt'
    pin_file.write_text('secret-pin\n', encoding='utf-8')

    profile = Pkcs11ProviderProfile(
        name='local-dev-softhsm',
        module_path='/usr/lib/libpkcs11-proxy.so',
        token=Pkcs11TokenSelector(token_serial='87de2f12e07ee8a5'),
        user_pin_file=str(pin_file),
    )

    assert profile.require_user_pin() == 'secret-pin'
