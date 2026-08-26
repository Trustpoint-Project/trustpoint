# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Unauthenticated PKCS#11 token discovery."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from crypto.domain.errors import ProviderUnavailableError
from pkcs11 import PKCS11Error
from pkcs11 import lib as pkcs11_lib
from pkcs11.exceptions import TokenNotPresent, TokenNotRecognised

if TYPE_CHECKING:
    from pkcs11 import Slot

type LibraryLoader = Callable[[str], Any]


def _normalize_text(value: bytes | str | None) -> str | None:
    """Normalize fixed-width PKCS#11 identity text."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    normalized = value.rstrip('\x00 ').strip()
    return normalized or None


@dataclass(frozen=True, slots=True)
class DiscoveredPkcs11Token:
    """Non-secret identity details for a token exposed by one PKCS#11 module."""

    slot_id: int
    label: str | None
    serial: str | None
    model: str | None
    manufacturer: str | None

    def to_json_dict(self) -> dict[str, str | int | None]:
        """Return a JSON-serializable token identity."""
        return {
            'slot_id': self.slot_id,
            'label': self.label,
            'serial': self.serial,
            'model': self.model,
            'manufacturer': self.manufacturer,
        }

    @classmethod
    def from_json_dict(cls, payload: dict[str, Any]) -> DiscoveredPkcs11Token:
        """Build a token identity from command output."""
        return cls(
            slot_id=int(payload['slot_id']),
            label=_normalize_text(payload.get('label')),
            serial=_normalize_text(payload.get('serial')),
            model=_normalize_text(payload.get('model')),
            manufacturer=_normalize_text(payload.get('manufacturer')),
        )


def _token_from_slot(slot: Slot) -> DiscoveredPkcs11Token | None:
    """Return token identity for a populated slot without opening a session."""
    try:
        token = slot.get_token()
    except (TokenNotPresent, TokenNotRecognised):
        return None

    serial = getattr(token, 'serial', None) or getattr(token, 'serial_number', None)
    manufacturer = getattr(token, 'manufacturer_id', None) or getattr(token, 'manufacturer', None)
    return DiscoveredPkcs11Token(
        slot_id=int(slot.slot_id),
        label=_normalize_text(getattr(token, 'label', None)),
        serial=_normalize_text(serial),
        model=_normalize_text(getattr(token, 'model', None)),
        manufacturer=_normalize_text(manufacturer),
    )


def _tokens_from_slots(slots: Iterable[Slot]) -> tuple[DiscoveredPkcs11Token, ...]:
    """Normalize and deterministically order populated slots."""
    tokens = [token for slot in slots if (token := _token_from_slot(slot)) is not None]
    return tuple(sorted(tokens, key=lambda token: (token.slot_id, token.serial or '', token.label or '')))


def discover_pkcs11_tokens(
    module_path: str,
    *,
    library_loader: LibraryLoader = pkcs11_lib,
) -> tuple[DiscoveredPkcs11Token, ...]:
    """Discover tokens without requiring a PIN or authenticated session."""
    try:
        library = library_loader(module_path)
    except OSError as exc:
        msg = f'Failed to load PKCS#11 module at {module_path!r}.'
        raise ProviderUnavailableError(msg) from exc

    try:
        return _tokens_from_slots(library.get_slots(token_present=True))
    except PKCS11Error as token_present_error:
        try:
            return _tokens_from_slots(library.get_slots(token_present=False))
        except PKCS11Error as full_scan_error:
            initial_name = type(token_present_error).__name__
            fallback_name = type(full_scan_error).__name__
            msg = (
                'PKCS#11 provider failed while discovering tokens. '
                f'Token-present scan failed with {initial_name}; full scan failed with {fallback_name}.'
            )
            raise ProviderUnavailableError(msg) from full_scan_error
