"""Thin Django field wrappers over the application-secret encryption subsystem."""

from __future__ import annotations

import math
from typing import Any, Never

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from appsecrets.service import CIPHERTEXT_PREFIX, AppSecretError, decrypt_app_secret, encrypt_app_secret


class _EncryptedFieldMixin:
    """Shared encryption/decryption helpers for encrypted Django model fields."""

    description = _('Encrypted field using Trustpoint application secrets')

    def raise_validation_error(self, msg: str) -> Never:
        """Raise a ValidationError with the given message."""
        raise ValidationError(msg)

    def should_encrypt(self) -> bool:
        """Return whether values should be routed through the app-secret subsystem."""
        return True

    def encrypt_value(self, value: str | None) -> str | None:
        """Encrypt a string value for database storage."""
        if value in (None, ''):
            return value
        if not self.should_encrypt():
            return value
        try:
            return encrypt_app_secret(value)
        except AppSecretError as exc:
            raise ValidationError(_('Failed to encrypt field value: %s') % exc) from exc

    def decrypt_value(self, encrypted_value: str | None) -> str | None:
        """Decrypt a stored string value."""
        if encrypted_value in (None, ''):
            return encrypted_value
        if not self.should_encrypt():
            return encrypted_value
        try:
            return decrypt_app_secret(encrypted_value)
        except Exception as exc:
            error_msg = str(exc) or type(exc).__name__
            raise ValidationError(_('Failed to decrypt field value: %s') % error_msg) from exc

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> str | None:  # noqa: ARG002
        """Convert the database representation to a Python string."""
        if value is None:
            return value
        return self.decrypt_value(str(value))

    def to_python(self, value: Any) -> str | None:
        """Normalize incoming values to strings."""
        if isinstance(value, str) or value is None:
            return value
        return str(value)

    def get_prep_value(self, value: Any) -> str | None:
        """Convert the Python representation to the database representation."""
        if value is None:
            return value
        return self.encrypt_value(str(value))


class EncryptedTextField(_EncryptedFieldMixin, models.TextField[str, str]):
    """Text field whose value is encrypted via the app-secret subsystem."""


class EncryptedCharField(_EncryptedFieldMixin, models.CharField[str, str]):
    """Char field whose value is encrypted via the app-secret subsystem."""

    description = _('Encrypted char field using Trustpoint application secrets')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Store the plaintext max length while keeping the DB column large enough for ciphertext."""
        self._plaintext_max_length = kwargs.get('max_length')
        super().__init__(*args, **kwargs)

    @staticmethod
    def _calculate_encrypted_length(plaintext_max_length: int) -> int:
        """Calculate the database column size needed for prefixed base64 AES-GCM ciphertext."""
        payload_length = plaintext_max_length + 12 + 16
        base64_length = 4 * math.ceil(payload_length / 3)
        return len(CIPHERTEXT_PREFIX) + base64_length

    def deconstruct(self) -> tuple[str, str, list[Any], dict[str, Any]]:
        """Persist the plaintext max length in migrations."""
        name, path, args, kwargs = super().deconstruct()
        if self._plaintext_max_length is not None:
            kwargs['max_length'] = self._plaintext_max_length
        return name, path, list(args), kwargs

    def db_type(self, connection: Any) -> str:
        """Use a column size that fits encrypted values rather than plaintext."""
        if self._plaintext_max_length is None:
            db_type_result = super().db_type(connection)
            if db_type_result is None:
                return 'text'
            return db_type_result
        encrypted_length = self._calculate_encrypted_length(self._plaintext_max_length)
        return f'varchar({encrypted_length})'
