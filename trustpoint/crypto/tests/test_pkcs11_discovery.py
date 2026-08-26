# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for unauthenticated PKCS#11 token discovery."""

from __future__ import annotations

from dataclasses import dataclass

from crypto.adapters.pkcs11.discovery import DiscoveredPkcs11Token, discover_pkcs11_tokens


@dataclass
class FakeToken:
    """Minimal token identity exposed by python-pkcs11."""

    label: str
    serial: str
    model: str
    manufacturer_id: str


@dataclass
class FakeSlot:
    """Minimal populated PKCS#11 slot."""

    slot_id: int
    token: FakeToken

    def get_token(self) -> FakeToken:
        """Return the token in this slot."""
        return self.token


class FakeLibrary:
    """Minimal library returning populated slots."""

    def __init__(self, slots: list[FakeSlot]) -> None:
        """Store slots returned by the fake provider."""
        self.slots = slots

    def get_slots(self, *, token_present: bool) -> list[FakeSlot]:
        """Return the configured slots."""
        assert token_present is True
        return self.slots


def test_discover_pkcs11_tokens_returns_sorted_normalized_identities() -> None:
    """Discovery requires neither a token selector nor a user PIN."""
    library = FakeLibrary(
        [
            FakeSlot(8, FakeToken(' Second  ', ' 002 ', 'Model B', 'Vendor')),
            FakeSlot(2, FakeToken('Primary   ', '001', 'Model A', 'Vendor')),
        ]
    )

    tokens = discover_pkcs11_tokens('/usr/lib/opensc-pkcs11.so', library_loader=lambda _path: library)

    assert tokens == (
        DiscoveredPkcs11Token(2, 'Primary', '001', 'Model A', 'Vendor'),
        DiscoveredPkcs11Token(8, 'Second', '002', 'Model B', 'Vendor'),
    )


def test_discovered_token_json_round_trip() -> None:
    """Discovery identities remain safe to persist in a wizard session."""
    token = DiscoveredPkcs11Token(3, 'HSM', 'serial', 'model', 'manufacturer')

    assert DiscoveredPkcs11Token.from_json_dict(token.to_json_dict()) == token
