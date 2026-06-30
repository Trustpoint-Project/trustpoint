"""Application-facing interfaces for the redesigned crypto layer."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from crypto.application.backend import CryptoBackend

if TYPE_CHECKING:
    from crypto.application.service import TrustpointCryptoBackend

__all__ = ['CryptoBackend', 'TrustpointCryptoBackend']


def __getattr__(name: str) -> object:
    """Lazily expose service-level application interfaces."""
    if name == 'TrustpointCryptoBackend':
        service_module = import_module('crypto.application.service')
        return service_module.TrustpointCryptoBackend

    msg = f'module {__name__!r} has no attribute {name!r}'
    raise AttributeError(msg)
