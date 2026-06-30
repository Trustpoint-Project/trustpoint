"""Translate raw PKCS#11 failures into crypto-domain errors."""

from __future__ import annotations

from collections.abc import Callable

from crypto.domain.errors import (
    AuthenticationError,
    CryptoError,
    KeyNotFoundError,
    MechanismUnsupportedError,
    ProviderConfigurationError,
    ProviderUnavailableError,
    SessionUnavailableError,
    UnsupportedKeySpecError,
)
from pkcs11.exceptions import (
    AttributeValueInvalid,
    DomainParamsInvalid,
    KeySizeRange,
    MechanismInvalid,
    MechanismParamInvalid,
    NoSuchKey,
    NoSuchToken,
    PinIncorrect,
    PinLocked,
    PKCS11Error,
    SessionClosed,
    SessionCount,
    SessionHandleInvalid,
    SessionReadOnly,
    TemplateIncomplete,
    TemplateInconsistent,
    TokenNotRecognised,
    TokenWriteProtected,
    UserNotLoggedIn,
)

ErrorFactory = Callable[[str], CryptoError]

PKCS11_ERROR_MAPPINGS: tuple[tuple[type[Exception] | tuple[type[Exception], ...], ErrorFactory, str], ...] = (
    (NoSuchKey, KeyNotFoundError, 'PKCS#11 key lookup failed during {operation}.'),
    (
        (PinIncorrect, PinLocked, UserNotLoggedIn),
        AuthenticationError,
        'PKCS#11 authentication failed during {operation}.',
    ),
    (
        (MechanismInvalid, MechanismParamInvalid),
        MechanismUnsupportedError,
        'PKCS#11 mechanism unsupported during {operation}.',
    ),
    (
        (AttributeValueInvalid, DomainParamsInvalid, KeySizeRange, TemplateIncomplete, TemplateInconsistent),
        UnsupportedKeySpecError,
        'PKCS#11 key specification unsupported during {operation}.',
    ),
    (
        (SessionClosed, SessionCount, SessionHandleInvalid),
        SessionUnavailableError,
        'PKCS#11 session failed during {operation}.',
    ),
    (
        (SessionReadOnly, TokenWriteProtected),
        ProviderConfigurationError,
        'PKCS#11 provider is misconfigured for {operation}.',
    ),
    (
        (NoSuchToken, TokenNotRecognised, PKCS11Error),
        ProviderUnavailableError,
        'PKCS#11 provider failed during {operation}.',
    ),
)


def map_pkcs11_error(exception: Exception, *, operation: str) -> CryptoError:
    """Map a PKCS#11 exception to a domain-level crypto error."""
    if isinstance(exception, CryptoError):
        return exception

    for exception_types, error_factory, message_template in PKCS11_ERROR_MAPPINGS:
        if isinstance(exception, exception_types):
            return error_factory(message_template.format(operation=operation))

    return ProviderUnavailableError(f'Unexpected provider failure during {operation}: {type(exception).__name__}.')
