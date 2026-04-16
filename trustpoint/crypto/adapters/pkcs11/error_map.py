"""Translate raw PKCS#11 failures into crypto-domain errors."""

from __future__ import annotations

from crypto.domain.errors import (
    AuthenticationError,
    CryptoError,
    KeyNotFoundError,
    ProviderUnavailableError,
    SessionUnavailableError,
)
from pkcs11.exceptions import (
    NoSuchKey,
    NoSuchToken,
    PinIncorrect,
    PinLocked,
    PKCS11Error,
    SessionClosed,
    SessionCount,
    SessionHandleInvalid,
    TokenNotRecognised,
    UserNotLoggedIn,
)


def map_pkcs11_error(exception: Exception, *, operation: str) -> CryptoError:
    """Map a PKCS#11 exception to a domain-level crypto error."""
    if isinstance(exception, CryptoError):
        return exception
    if isinstance(exception, NoSuchKey):
        return KeyNotFoundError(f'PKCS#11 key lookup failed during {operation}.')
    if isinstance(exception, (PinIncorrect, PinLocked, UserNotLoggedIn)):
        return AuthenticationError(f'PKCS#11 authentication failed during {operation}.')
    if isinstance(exception, (SessionClosed, SessionCount, SessionHandleInvalid)):
        return SessionUnavailableError(f'PKCS#11 session failed during {operation}.')
    if isinstance(exception, (NoSuchToken, TokenNotRecognised, PKCS11Error)):
        return ProviderUnavailableError(f'PKCS#11 provider failed during {operation}.')
    return ProviderUnavailableError(f'Unexpected provider failure during {operation}: {type(exception).__name__}.')
