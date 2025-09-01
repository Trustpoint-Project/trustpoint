"""Encrypted fields for sensitive data using PKCS#11 DEK encryption."""

from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _


class EncryptedTextField(models.TextField[str, str]):
    """A TextField that automatically encrypts/decrypts data using PKCS#11 DEK.

    This field uses AES-256-CBC encryption with the DEK (Data Encryption Key)
    from the PKCS#11 token to encrypt sensitive data before storing it in the database.
    """

    description = _('Encrypted text field using PKCS#11 DEK')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the encrypted field."""
        super().__init__(*args, **kwargs)

    def get_dek(self) -> bytes:
        """Get the DEK from PKCS#11 token, preferring cached value.

        Returns:
            bytes: The 32-byte DEK.

        Raises:
            ValidationError: If no PKCS#11 token is configured or DEK unavailable.
        """
        from settings.models import PKCS11Token

        token = PKCS11Token.objects.first()
        if not token:
            raise ValidationError(_('No PKCS#11 token configured for encryption.'))

        dek_cache = token.get_dek_cache()
        if dek_cache:
            return dek_cache

        try:
            return token.get_dek()
        except Exception as e:
            raise ValidationError(_('Failed to retrieve DEK from PKCS#11 token: %s') % e) from e

    def encrypt_value(self, value: str) -> str:
        """Encrypt a string value using AES-256-GCM with the PKCS#11 DEK.

        Args:
            value: The plaintext string to encrypt.

        Returns:
            str: Base64-encoded encrypted data in format: nonce:tag:ciphertext
        """
        if not value:
            return value

        try:
            dek = self.get_dek()

            # Generate a random nonce for GCM
            nonce = os.urandom(12)  # 12 bytes for GCM

            # Add random padding to obscure length patterns
            padding_length = os.urandom(1)[0] % 16  # 0-15 random bytes
            padded_value = value + '\x00' * padding_length + chr(padding_length)

            # Create cipher
            cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce))
            encryptor = cipher.encryptor()

            # Encrypt (no padding needed for GCM)
            ciphertext = encryptor.update(padded_value.encode('utf-8'))
            encryptor.finalize()

            # Get authentication tag
            tag = encryptor.tag

            # Return base64-encoded nonce + tag + ciphertext
            combined = nonce + tag + ciphertext
            return base64.b64encode(combined).decode('ascii')

        except Exception as e:
            raise ValidationError(_('Failed to encrypt field value: %s') % e) from e

    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt a base64-encoded encrypted value using the PKCS#11 DEK.

        Args:
            encrypted_value: Base64-encoded encrypted data.

        Returns:
            str: The decrypted plaintext string.
        """
        if not encrypted_value:
            return encrypted_value

        try:
            dek = self.get_dek()

            # Decode from base64
            combined = base64.b64decode(encrypted_value.encode('ascii'))

            # Extract nonce, tag, and ciphertext
            nonce = combined[:12]       # First 12 bytes are nonce
            tag = combined[12:28]       # Next 16 bytes are auth tag
            ciphertext = combined[28:]  # Rest is ciphertext

            # Create cipher with tag for authentication
            cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            # Decrypt and verify authenticity
            padded_data = decryptor.update(ciphertext)
            decryptor.finalize()  # Raises exception if authentication fails

            # Remove random padding
            padding_length = ord(padded_data[-1:])
            max_padding_length = 16
            data = padded_data[:-padding_length - 1] if padding_length < max_padding_length else padded_data

            return data.decode('utf-8')

        except Exception as e:
            raise ValidationError(_('Failed to decrypt field value: %s') % e) from e

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> str | None:  # noqa: ARG002
        """Convert value from database to Python object.

        This method is called when data is loaded from the database.
        """
        if value is None:
            return value
        return self.decrypt_value(value)

    def to_python(self, value: Any) -> str | None:
        """Convert value to Python object.

        This method is called during deserialization and in forms.
        """
        if isinstance(value, str) or value is None:
            return value
        return str(value)

    def get_prep_value(self, value: Any) -> str | None:
        """Convert Python object to database value.

        This method is called when saving data to the database.
        """
        if value is None:
            return value
        return self.encrypt_value(str(value))


class EncryptedCharField(models.CharField[str, str]):
    """A CharField that automatically encrypts/decrypts data using PKCS#11 DEK.

    Similar to EncryptedTextField but with CharField constraints.
    """

    description = _('Encrypted char field using PKCS#11 DEK')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the encrypted field."""

        if 'max_length' in kwargs:
            original_length = kwargs['max_length']
            # Calculate encrypted length: original + padding + IV + base64 overhead
            encrypted_length = ((original_length + 16 + 15) // 16) * 16  # Padded length
            encrypted_length += 16  # IV
            encrypted_length = int(encrypted_length * 4/3) + 4  # Base64 overhead
            kwargs['max_length'] = encrypted_length

        super().__init__(*args, **kwargs)

    def get_dek(self) -> bytes:
        """Get the DEK from PKCS#11 token, preferring cached value."""
        from settings.models import PKCS11Token

        token = PKCS11Token.objects.first()
        if not token:
            raise ValidationError(_('No PKCS#11 token configured for encryption.'))

        dek_cache = token.get_dek_cache()
        if dek_cache:
            return dek_cache

        try:
            return token.get_dek()
        except Exception as e:
            raise ValidationError(_('Failed to retrieve DEK from PKCS#11 token: %s') % e) from e

        """Encrypt a string value using AES-256-GCM with the PKCS#11 DEK."""
        if not value:
            return value

        try:
            dek = self.get_dek()

            # Generate a random nonce for GCM
            nonce = os.urandom(12)  # 12 bytes for GCM

            # Add random padding to obscure length patterns
            padding_length = os.urandom(1)[0] % 16  # 0-15 random bytes
            padded_value = value + '\x00' * padding_length + chr(padding_length)

            # Create cipher
            cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce))
            encryptor = cipher.encryptor()

            # Encrypt (no padding needed for GCM)
            ciphertext = encryptor.update(padded_value.encode('utf-8'))
            encryptor.finalize()

            # Get authentication tag
            tag = encryptor.tag

            # Return base64-encoded nonce + tag + ciphertext
            combined = nonce + tag + ciphertext
            return base64.b64encode(combined).decode('ascii')

        except Exception as e:
            raise ValidationError(_('Failed to encrypt field value: %s') % e) from e

    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt a base64-encoded encrypted value using the PKCS#11 DEK."""
        if not encrypted_value:
            return encrypted_value

        try:
            dek = self.get_dek()

            # Decode from base64
            combined = base64.b64decode(encrypted_value.encode('ascii'))

            # Extract nonce, tag, and ciphertext
            nonce = combined[:12]       # First 12 bytes are nonce
            tag = combined[12:28]       # Next 16 bytes are auth tag
            ciphertext = combined[28:]  # Rest is ciphertext

            # Create cipher with tag for authentication
            cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            # Decrypt and verify authenticity
            padded_data = decryptor.update(ciphertext)
            decryptor.finalize()  # Raises exception if authentication fails

            # Remove random padding
            padding_length = ord(padded_data[-1:])
            max_padding_length = 16
            data = padded_data[:-padding_length - 1] if padding_length < max_padding_length else padded_data

            return data.decode('utf-8')

        except Exception as e:
            raise ValidationError(_('Failed to decrypt field value: %s') % e) from e

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> str | None:  # noqa: ARG002
        """Convert value from database to Python object."""
        if value is None:
            return value
        return self.decrypt_value(value)

    def to_python(self, value: Any) -> str | None:
        """Convert value to Python object."""
        if isinstance(value, str) or value is None:
            return value
        return str(value)

    def get_prep_value(self, value: Any) -> str | None:
        """Convert Python object to database value."""
        if value is None:
            return value
        return self.encrypt_value(str(value))
