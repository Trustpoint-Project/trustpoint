"""New crypto backend package for the Trustpoint redesign."""

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

TrustpointCryptoBackend = None

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


def __getattr__(name: str) -> object:
    if name == 'TrustpointCryptoBackend':
        from crypto.application.service import TrustpointCryptoBackend

        return TrustpointCryptoBackend
    msg = f'module {__name__!r} has no attribute {name!r}'
    raise AttributeError(msg)
