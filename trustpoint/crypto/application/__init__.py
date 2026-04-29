"""Application-facing interfaces for the redesigned crypto layer."""

from crypto.application.backend import CryptoBackend

__all__ = ['CryptoBackend', 'TrustpointCryptoBackend']

TrustpointCryptoBackend = None


def __getattr__(name: str) -> object:
    if name == 'TrustpointCryptoBackend':
        global TrustpointCryptoBackend
        if TrustpointCryptoBackend is None:
            from crypto.application.service import TrustpointCryptoBackend as _TrustpointCryptoBackend

            TrustpointCryptoBackend = _TrustpointCryptoBackend
        return TrustpointCryptoBackend
    msg = f'module {__name__!r} has no attribute {name!r}'
    raise AttributeError(msg)
