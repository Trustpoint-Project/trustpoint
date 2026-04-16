"""Provider configuration for the PKCS#11 adapter."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from crypto.domain.errors import ProviderConfigurationError


def _normalize_pkcs11_text(value: str | bytes | None) -> str | None:
    """Normalize PKCS#11 text fields coming from config or the binding.

    PKCS#11 token metadata is often space-padded and some Python bindings expose
    fields such as token serials as ``bytes`` rather than ``str``. This helper
    normalizes both representations into a plain stripped Python string.

    Assumption:
        Token labels and serials are effectively ASCII/UTF-8 compatible for the
        providers we support. For undecodable bytes we conservatively ignore
        invalid UTF-8 bytes instead of raising inside selector matching.
    """
    if value is None:
        return None

    if isinstance(value, bytes):
        normalized = value.rstrip(b'\x00 ').decode('utf-8', errors='ignore').strip()
        return normalized or None

    normalized = value.rstrip('\x00 ').strip()
    return normalized or None


@dataclass(frozen=True, slots=True)
class Pkcs11TokenSelector:
    """How the backend should select a PKCS#11 token."""

    token_label: str | None = None
    token_serial: str | None = None
    slot_id: int | None = None

    def __post_init__(self) -> None:
        """Validate and normalize selector values."""
        object.__setattr__(self, 'token_label', _normalize_pkcs11_text(self.token_label))
        object.__setattr__(self, 'token_serial', _normalize_pkcs11_text(self.token_serial))

        if self.token_label is None and self.token_serial is None and self.slot_id is None:
            msg = 'A PKCS#11 token selector requires at least one of token_label, token_serial, or slot_id.'
            raise ProviderConfigurationError(msg)

    def matches(self, *, slot_id: int, token_label: str | bytes | None, token_serial: str | bytes | None) -> bool:
        """Return whether a discovered slot/token matches this selector."""
        normalized_label = _normalize_pkcs11_text(token_label)
        normalized_serial = _normalize_pkcs11_text(token_serial)

        if self.slot_id is not None and self.slot_id != slot_id:
            return False
        if self.token_label is not None and self.token_label != normalized_label:
            return False
        if self.token_serial is not None and self.token_serial != normalized_serial:
            return False
        return True


@dataclass(frozen=True, slots=True)
class Pkcs11ProviderProfile:
    """Complete configuration for a PKCS#11-backed provider."""

    name: str
    module_path: str
    token: Pkcs11TokenSelector

    user_pin: str | None = None
    user_pin_env_var: str | None = None
    user_pin_file: str | None = None

    max_sessions: int = 8
    borrow_timeout_seconds: float = 5.0
    rw_sessions: bool = True
    allow_legacy_label_lookup: bool = False

    def __post_init__(self) -> None:
        """Validate basic provider settings."""
        normalized_name = self.name.strip()
        normalized_module_path = self.module_path.strip()
        object.__setattr__(self, 'name', normalized_name)
        object.__setattr__(self, 'module_path', normalized_module_path)

        if not normalized_name:
            msg = 'Provider profile name must not be empty.'
            raise ProviderConfigurationError(msg)
        if not normalized_module_path:
            msg = 'PKCS#11 module path must not be empty.'
            raise ProviderConfigurationError(msg)
        if self.max_sessions < 1:
            msg = 'PKCS#11 max_sessions must be at least 1.'
            raise ProviderConfigurationError(msg)
        if self.borrow_timeout_seconds <= 0:
            msg = 'PKCS#11 borrow_timeout_seconds must be greater than zero.'
            raise ProviderConfigurationError(msg)

        configured_auth_sources = sum(
            value is not None and str(value).strip() != ''
            for value in (self.user_pin, self.user_pin_env_var, self.user_pin_file)
        )
        if configured_auth_sources != 1:
            msg = 'Exactly one PKCS#11 user PIN source must be configured.'
            raise ProviderConfigurationError(msg)

    def require_user_pin(self) -> str:
        """Return the configured user PIN or raise a configuration error."""
        if self.user_pin is not None:
            pin = self.user_pin.strip()
            if pin:
                return pin
            msg = f'Provider profile {self.name!r} has an empty inline user PIN.'
            raise ProviderConfigurationError(msg)

        if self.user_pin_env_var is not None:
            env_var = self.user_pin_env_var.strip()
            if not env_var:
                msg = f'Provider profile {self.name!r} has an empty user PIN environment variable name.'
                raise ProviderConfigurationError(msg)
            pin = os.getenv(env_var, '').strip()
            if pin:
                return pin
            msg = f'Provider profile {self.name!r} could not resolve a user PIN from environment variable {env_var!r}.'
            raise ProviderConfigurationError(msg)

        if self.user_pin_file is not None:
            file_path = self.user_pin_file.strip()
            if not file_path:
                msg = f'Provider profile {self.name!r} has an empty user PIN file path.'
                raise ProviderConfigurationError(msg)
            path = Path(file_path)
            try:
                pin = path.read_text(encoding='utf-8').strip()
            except OSError as exc:
                msg = f'Provider profile {self.name!r} could not read user PIN file {file_path!r}.'
                raise ProviderConfigurationError(msg) from exc
            if pin:
                return pin
            msg = f'Provider profile {self.name!r} resolved an empty user PIN from file {file_path!r}.'
            raise ProviderConfigurationError(msg)

        msg = f'Provider profile {self.name!r} is missing a user PIN source.'
        raise ProviderConfigurationError(msg)
