"""Domain error types for the redesigned crypto layer."""


class CryptoError(Exception):
    """Base class for crypto-layer failures."""


class ProviderConfigurationError(CryptoError):
    """Raised when provider configuration is incomplete or invalid."""


class ProviderUnavailableError(CryptoError):
    """Raised when the configured provider cannot be reached or loaded."""


class AuthenticationError(CryptoError):
    """Raised when the provider rejects authentication or key-unsealing material."""


class SessionUnavailableError(CryptoError):
    """Raised when no usable provider session can be acquired."""


class KeyNotFoundError(CryptoError):
    """Raised when a referenced key does not exist."""


class KeyAlreadyExistsError(CryptoError):
    """Raised when attempting to create a key with a duplicate identity."""


class UnsupportedKeySpecError(CryptoError):
    """Raised when the caller requests an unsupported key specification."""


class MechanismUnsupportedError(CryptoError):
    """Raised when the provider cannot satisfy an algorithm/mechanism request."""


class UnsupportedBackendKindError(CryptoError):
    """Raised when Trustpoint encounters an unknown backend kind."""


class InternalConsistencyError(CryptoError):
    """Raised when backend-produced crypto state is internally inconsistent."""


class ProviderOperationNotImplementedError(CryptoError):
    """Raised when a configured backend exists but an operation is not implemented yet."""
