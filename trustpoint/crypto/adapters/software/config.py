"""Configuration types for the software backend."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from crypto.domain.errors import AuthenticationError, ProviderConfigurationError


@dataclass(frozen=True, slots=True)
class SoftwareProviderProfile:
    """Configuration for the durable development-only software backend."""

    name: str
    encryption_source: str
    encryption_source_ref: str | None = None
    allow_exportable_private_keys: bool = False

    def require_encryption_material(self) -> bytes:
        """Resolve and return the private-key encryption material."""
        if self.encryption_source == 'env':
            if not self.encryption_source_ref:
                msg = 'Software backend env encryption source requires an environment variable name.'
                raise ProviderConfigurationError(msg)
            value = os.environ.get(self.encryption_source_ref)
            if not value:
                msg = f'Software backend encryption secret env var {self.encryption_source_ref!r} is missing.'
                raise AuthenticationError(msg)
            return value.encode('utf-8')

        if self.encryption_source == 'file':
            if not self.encryption_source_ref:
                msg = 'Software backend file encryption source requires a file path.'
                raise ProviderConfigurationError(msg)
            path = Path(self.encryption_source_ref)
            try:
                data = path.read_text(encoding='utf-8').strip()
            except OSError as exc:
                msg = f'Unable to read software backend encryption secret file {str(path)!r}.'
                raise AuthenticationError(msg) from exc
            if not data:
                msg = f'Software backend encryption secret file {str(path)!r} is empty.'
                raise AuthenticationError(msg)
            return data.encode('utf-8')

        if self.encryption_source == 'dev_plaintext':
            return b'trustpoint-development-software-backend-secret'

        msg = f'Unsupported software backend encryption source {self.encryption_source!r}.'
        raise ProviderConfigurationError(msg)
