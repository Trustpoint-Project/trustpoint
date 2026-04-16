"""Core domain types for the new crypto layer."""

from crypto.domain.algorithms import (
    EllipticCurveName,
    HashAlgorithmName,
    KeyAlgorithm,
    SignatureAlgorithm,
    SupportedPublicKey,
)
from crypto.domain.errors import (
    AuthenticationError,
    CryptoError,
    KeyAlreadyExistsError,
    KeyNotFoundError,
    MechanismUnsupportedError,
    ProviderConfigurationError,
    ProviderUnavailableError,
    SessionUnavailableError,
    UnsupportedKeySpecError,
)
from crypto.domain.policies import KeyPolicy, KeyUsage
from crypto.domain.refs import ManagedKeyRef
from crypto.domain.specs import EcKeySpec, KeySpec, RsaKeySpec, SignRequest, algorithm_for_key_spec

__all__ = [
    'AuthenticationError',
    'CryptoError',
    'EcKeySpec',
    'EllipticCurveName',
    'HashAlgorithmName',
    'KeyAlgorithm',
    'KeyAlreadyExistsError',
    'KeyNotFoundError',
    'KeyPolicy',
    'KeySpec',
    'KeyUsage',
    'ManagedKeyRef',
    'MechanismUnsupportedError',
    'ProviderConfigurationError',
    'ProviderUnavailableError',
    'RsaKeySpec',
    'SessionUnavailableError',
    'SignRequest',
    'SignatureAlgorithm',
    'SupportedPublicKey',
    'UnsupportedKeySpecError',
    'algorithm_for_key_spec',
]
