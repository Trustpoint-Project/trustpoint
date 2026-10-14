# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provider configuration for the PKCS#11 adapter."""

from __future__ import annotations

import os
import stat
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


def _validate_existing_path_permissions(path: Path, *, description: str) -> None:
    """Reject filesystem objects writable by group or other users.

    The Trustpoint process cannot protect a PKCS#11 provider from a host/root
    compromise. This check instead prevents configuration from pointing at a
    provider file, or a directory containing it, that an unprivileged process
    can replace at runtime.
    """
    try:
        path_stat = path.stat()
    except OSError as exc:
        msg = f'Unable to inspect {description} {str(path)!r}.'
        raise ProviderConfigurationError(msg) from exc

    unsafe_write_bits = stat.S_IWGRP | stat.S_IWOTH
    if path_stat.st_mode & unsafe_write_bits:
        msg = f'{description.capitalize()} {str(path)!r} must not be group- or world-writable.'
        raise ProviderConfigurationError(msg)

    effective_uid = os.geteuid()
    runtime_user_can_replace = (
        effective_uid != 0
        and path_stat.st_uid == effective_uid
        and bool(path_stat.st_mode & stat.S_IWUSR)
    )
    if runtime_user_can_replace:
        msg = f'{description.capitalize()} {str(path)!r} must not be writable by the Trustpoint runtime user.'
        raise ProviderConfigurationError(msg)


def _validate_parent_directories(path: Path) -> None:
    """Reject provider paths whose existing parent directories are mutable by unprivileged users."""
    parent = path.parent
    while True:
        if parent.exists():
            _validate_existing_path_permissions(parent, description='PKCS#11 module parent directory')
        if parent == parent.parent:
            break
        parent = parent.parent


def validate_pkcs11_module_path(module_path: str) -> str:
    """Validate and normalize a PKCS#11 module path.

    Security properties enforced here:

    * the configured module path must be absolute;
    * every existing parent directory must not be group/world writable;
    * an existing module must be a regular file;
    * an existing module must not be group/world writable.

    A missing module is not rejected here because configuration can legitimately
    be staged before the provider package is mounted into a container. Loading
    the provider will still fail closed later if the module does not exist.
    """
    raw_path = module_path.strip()
    if not raw_path:
        msg = 'PKCS#11 module path must not be empty.'
        raise ProviderConfigurationError(msg)

    path = Path(raw_path)
    if not path.is_absolute():
        msg = 'PKCS#11 module path must be absolute.'
        raise ProviderConfigurationError(msg)

    try:
        normalized_path = path.resolve(strict=False)
    except OSError as exc:
        msg = f'Unable to normalize PKCS#11 module path {str(path)!r}.'
        raise ProviderConfigurationError(msg) from exc

    _validate_parent_directories(normalized_path)

    if normalized_path.exists():
        if not normalized_path.is_file():
            msg = f'PKCS#11 module path {str(normalized_path)!r} must resolve to a regular file.'
            raise ProviderConfigurationError(msg)

        _validate_existing_path_permissions(normalized_path, description='PKCS#11 module')

    return str(normalized_path)


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
        """Return whether a discovered slot/token matches this selector.

        When a serial is configured it is authoritative: a slot or label match
        can never override a serial mismatch. Provider profiles require a serial,
        which makes token selection stable across slot changes while preventing
        label-only token substitution.
        """
        normalized_label = _normalize_pkcs11_text(token_label)
        normalized_serial = _normalize_pkcs11_text(token_serial)

        if self.token_serial is not None:
            if self.token_serial != normalized_serial:
                return False
            return not (self.token_label is not None and self.token_label != normalized_label)

        if self.slot_id is not None and self.slot_id == slot_id:
            return self.token_label is None or self.token_label == normalized_label
        return bool(self.token_label is not None and self.token_label == normalized_label)


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

    def __post_init__(self) -> None:
        """Validate basic provider settings and enforce strong provider identity."""
        normalized_name = self.name.strip()
        normalized_module_path = validate_pkcs11_module_path(self.module_path)
        object.__setattr__(self, 'name', normalized_name)
        object.__setattr__(self, 'module_path', normalized_module_path)

        if not normalized_name:
            msg = 'Provider profile name must not be empty.'
            raise ProviderConfigurationError(msg)
        if self.token.token_serial is None:
            msg = 'PKCS#11 provider profiles require token_serial for strong token pinning.'
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
