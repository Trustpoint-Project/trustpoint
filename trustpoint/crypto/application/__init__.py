"""Application-facing interfaces for the redesigned crypto layer."""

from crypto.application.backend import CryptoBackend

__all__ = ['CryptoBackend', 'TrustpointCryptoBackend']


def __getattr__(name: str) -> object:
    if name == 'TrustpointCryptoBackend':
        from crypto.application.service import TrustpointCryptoBackend

        return TrustpointCryptoBackend
    msg = f'module {__name__!r} has no attribute {name!r}'
    raise AttributeError(msg)
