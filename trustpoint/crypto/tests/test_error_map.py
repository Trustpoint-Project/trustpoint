"""Unit tests for PKCS#11 error mapping."""

from __future__ import annotations

from crypto.adapters.pkcs11.error_map import map_pkcs11_error
from crypto.domain.errors import (
    AuthenticationError,
    KeyNotFoundError,
    ProviderUnavailableError,
    SessionUnavailableError,
)
from pkcs11.exceptions import NoSuchKey, PinIncorrect, SessionClosed


def test_maps_missing_key() -> None:
    error = map_pkcs11_error(NoSuchKey(), operation='lookup')
    assert isinstance(error, KeyNotFoundError)


def test_maps_authentication_failure() -> None:
    error = map_pkcs11_error(PinIncorrect(), operation='login')
    assert isinstance(error, AuthenticationError)


def test_maps_session_failure() -> None:
    error = map_pkcs11_error(SessionClosed(), operation='sign')
    assert isinstance(error, SessionUnavailableError)


def test_preserves_already_normalized_error() -> None:
    original = ProviderUnavailableError('already normalized')
    mapped = map_pkcs11_error(original, operation='probe')
    assert mapped is original
