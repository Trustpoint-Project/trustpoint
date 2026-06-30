"""Configuration types for the REST backend."""

from __future__ import annotations

import os
from dataclasses import dataclass

from crypto.domain.errors import AuthenticationError, ProviderConfigurationError


@dataclass(frozen=True, slots=True)
class RestProviderProfile:
    """Configuration for the REST backend."""

    name: str
    base_url: str
    auth_type: str
    auth_ref: str | None = None
    timeout_seconds: float = 5.0
    verify_tls: bool = True

    def require_auth_value(self) -> str | None:
        """Resolve the configured authentication material if the auth type needs it."""
        if self.auth_type == 'none':
            return None

        if self.auth_type in {'bearer_env', 'api_key_env'}:
            if not self.auth_ref:
                msg = f'REST backend auth type {self.auth_type!r} requires auth_ref.'
                raise ProviderConfigurationError(msg)
            value = os.environ.get(self.auth_ref)
            if not value:
                msg = f'REST backend auth secret env var {self.auth_ref!r} is missing.'
                raise AuthenticationError(msg)
            return value

        if self.auth_type == 'mtls':
            if not self.auth_ref:
                msg = 'REST backend mTLS configuration requires auth_ref.'
                raise ProviderConfigurationError(msg)
            return self.auth_ref

        msg = f'Unsupported REST backend auth type {self.auth_type!r}.'
        raise ProviderConfigurationError(msg)
