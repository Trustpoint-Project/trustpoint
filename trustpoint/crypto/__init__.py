"""New crypto backend package for the Trustpoint redesign."""

from __future__ import annotations

from importlib import import_module

from crypto.application.backend import CryptoBackend
from crypto.domain.algorithms import (
    EllipticCurveName,
    HashAlgorithmName,
    KeyAlgorithm,
    SignatureAlgorithm,
)
from crypto.domain.policies import KeyPolicy, KeyUsage
from crypto.domain.refs import ManagedKeyRef, ManagedKeyVerification, ManagedKeyVerificationStatus
from crypto.domain.specs import EcKeySpec, RsaKeySpec, SignRequest

__all__ = [
    'CryptoBackend',
    'EcKeySpec',
    'EllipticCurveName',
    'HashAlgorithmName',
    'KeyAlgorithm',
    'KeyPolicy',
    'KeyUsage',
    'ManagedKeyRef',
    'ManagedKeyVerification',
    'ManagedKeyVerificationStatus',
    'RsaKeySpec',
    'SignRequest',
    'SignatureAlgorithm',
    'TrustpointCryptoBackend',
]


class _TrustpointCryptoBackendProxy:
    """Callable proxy that lazily instantiates the service-level backend."""

    def __call__(self, *args: object, **kwargs: object) -> object:
        backend_module = import_module('crypto.application.service')
        return backend_module.TrustpointCryptoBackend(*args, **kwargs)


TrustpointCryptoBackend = _TrustpointCryptoBackendProxy()


def __getattr__(name: str) -> object:
    """Lazily expose service-level crypto APIs without importing Django models at package import time."""
    if name == 'TrustpointCryptoBackend':
        return TrustpointCryptoBackend

    msg = f'module {__name__!r} has no attribute {name!r}'
    raise AttributeError(msg)
