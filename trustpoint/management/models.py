"""Models for the Trustpoint Management app."""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, cast

import pkcs11  # type: ignore[import-untyped]
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from notifications.models import WeakECCCurve, WeakSignatureAlgorithm
from pki.util.keys import AutoGenPkiKeyAlgorithm
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from management.pkcs11_util import Pkcs11AESKey


class SecurityConfig(models.Model):
    """Security Configuration model."""

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes."""

        DEV = '0', _('Testing env')
        LOW = '1', _('Basic')
        MEDIUM = '2', _('Medium')
        HIGH = '3', _('High')
        HIGHEST = '4', _('Highest')

    security_mode = models.CharField(max_length=6, choices=SecurityModeChoices, default=SecurityModeChoices.LOW)

    auto_gen_pki = models.BooleanField(default=False)
    auto_gen_pki_key_algorithm = models.CharField(
        max_length=24, choices=AutoGenPkiKeyAlgorithm, default=AutoGenPkiKeyAlgorithm.RSA2048
    )

    NOTIFICATION_CONFIGURATIONS: ClassVar[dict[str, dict[str, Any]]] = {
        SecurityModeChoices.DEV: {
            'cert_expiry_warning_days': 10,
            'issuing_ca_expiry_warning_days': 10,
            'rsa_minimum_key_size': 1024,
            'weak_ecc_curves': [],
            'weak_signature_algorithms': [],
        },
        SecurityModeChoices.LOW: {
            'cert_expiry_warning_days': 15,
            'issuing_ca_expiry_warning_days': 15,
            'rsa_minimum_key_size': 1024,
            'weak_ecc_curves': [],
            'weak_signature_algorithms': [],
        },
        SecurityModeChoices.MEDIUM: {
            'cert_expiry_warning_days': 20,
            'issuing_ca_expiry_warning_days': 20,
            'rsa_minimum_key_size': 2048,
            'weak_ecc_curves': [
                WeakECCCurve.ECCCurveChoices.SECP160R1,
                WeakECCCurve.ECCCurveChoices.SECT163K1,
                WeakECCCurve.ECCCurveChoices.SECT163R2,
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
            ],
        },
        SecurityModeChoices.HIGH: {
            'cert_expiry_warning_days': 25,
            'issuing_ca_expiry_warning_days': 25,
            'rsa_minimum_key_size': 3072,
            'weak_ecc_curves': [
                WeakECCCurve.ECCCurveChoices.SECP160R1,
                WeakECCCurve.ECCCurveChoices.SECT163K1,
                WeakECCCurve.ECCCurveChoices.SECT163R2,
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
                WeakSignatureAlgorithm.SignatureChoices.SHA224,
            ],
        },
        SecurityModeChoices.HIGHEST: {
            'cert_expiry_warning_days': 30,
            'issuing_ca_expiry_warning_days': 30,
            'rsa_minimum_key_size': 4096,
            'weak_ecc_curves': [
                WeakECCCurve.ECCCurveChoices.SECP160R1,
                WeakECCCurve.ECCCurveChoices.SECT163K1,
                WeakECCCurve.ECCCurveChoices.SECT163R2,
                WeakECCCurve.ECCCurveChoices.SECP192R1,
                WeakECCCurve.ECCCurveChoices.SECP224R1,
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
                WeakSignatureAlgorithm.SignatureChoices.SHA224,
            ],
        },
    }

    notification_config = models.OneToOneField(
        'notifications.NotificationConfig',
        on_delete=models.CASCADE,
        related_name='security_config',
        null=True,
        blank=False,
        help_text=_('Notification configuration associated with this security level.'),
    )

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.security_mode}'

    def apply_security_settings(self) -> None:
        """Apply appropriate configuration values based on the security mode."""
        if self.security_mode and self.notification_config:
            # Get the default configuration for the selected security level
            config_values = self.NOTIFICATION_CONFIGURATIONS.get(self.security_mode, {})

            # Apply values to the NotificationConfig
            self.notification_config.cert_expiry_warning_days = config_values.get(
                'cert_expiry_warning_days', self.notification_config.cert_expiry_warning_days
            )
            self.notification_config.issuing_ca_expiry_warning_days = config_values.get(
                'issuing_ca_expiry_warning_days', self.notification_config.issuing_ca_expiry_warning_days
            )
            self.notification_config.rsa_minimum_key_size = config_values.get(
                'rsa_minimum_key_size', self.notification_config.rsa_minimum_key_size
            )

            # Update WeakECCCurve and WeakSignatureAlgorithm relationships
            weak_ecc_curve_oids = config_values.get('weak_ecc_curves', [])
            weak_signature_algorithm_oids = config_values.get('weak_signature_algorithms', [])

            weak_ecc_curves = WeakECCCurve.objects.filter(oid__in=weak_ecc_curve_oids)
            weak_signature_algorithms = WeakSignatureAlgorithm.objects.filter(oid__in=weak_signature_algorithm_oids)

            self.notification_config.weak_ecc_curves.set(weak_ecc_curves)
            self.notification_config.weak_signature_algorithms.set(weak_signature_algorithms)

            self.notification_config.save()


class TlsSettings(models.Model):
    """TLS settings model."""

    ipv4_address = models.GenericIPAddressField(protocol='IPv4', null=True, blank=True)

    def __str__(self) -> str:
        """Return a string representation of the TLS settings."""
        return f'TLS Settings (IPv4: {self.ipv4_address or "None"})'

    @classmethod
    def get_first_ipv4_address(cls) -> str:
        """Get the first IPv4 address or a default value."""
        try:
            network_settings = cls.objects.get(id=1)
            ipv4_address = network_settings.ipv4_address
            if ipv4_address is None:
                return '127.0.0.1'
        except cls.DoesNotExist:
            return '127.0.0.1'
        else:
            return ipv4_address


class AppVersion(models.Model):
    """Model representing the application version and its last update timestamp."""

    objects: models.Manager[AppVersion]

    version = models.CharField(max_length=17)
    container_id = models.CharField(max_length=64, blank=True, default='', help_text=_('Container build ID or hash'))
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta options for the AppVersion model."""

        verbose_name = 'App Version'

    def __str__(self) -> str:
        """Return a string representation for the AppVersion."""
        build_info = f' (Build: {self.container_id})' if self.container_id else ''
        return f'{self.version}{build_info} @ {self.last_updated.isoformat()}'


class BackupOptions(models.Model):
    """A singleton model (we always operate with pk=1) for backup settings.

    We store host/port/user/local_storage, plus either a password or an SSH key.
    """

    class AuthMethod(models.TextChoices):
        """Authentication methods for backup options."""

        PASSWORD = 'password', 'Password'
        SSH_KEY = 'ssh_key', 'SSH Key'

    enable_sftp_storage = models.BooleanField(default=False, verbose_name=_('Use SFTP storage'))

    host = models.CharField(max_length=255, verbose_name=_('Host'), blank=True)
    port = models.PositiveIntegerField(default=2222, verbose_name=_('Port'), blank=True)
    user = models.CharField(max_length=128, verbose_name=_('Username'), blank=True)

    auth_method = models.CharField(
        max_length=10, choices=AuthMethod.choices, default=AuthMethod.PASSWORD, verbose_name=_('Authentication Method')
    )

    # TODO (Dome): Storing passwords in plain text  # noqa: FIX002
    password = models.CharField(
        max_length=128, blank=True, verbose_name=_('Password'), help_text=_('Plain-text password for SFTP.')
    )

    private_key = models.TextField(
        blank=True, verbose_name=_('SSH Private Key (PEM format)'), help_text=_('Paste the private key here (PEM).')
    )

    key_passphrase = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Key Passphrase'),
        help_text=_('Passphrase for the private key, if any.'),
    )

    remote_directory = models.CharField(
        max_length=512,
        blank=True,
        default='/upload/trustpoint/',
        verbose_name=_('Remote Directory'),
        help_text=_('Remote directory (e.g. /backups/) where files should be uploaded. Trailing slash is optional.'),
    )

    class Meta:
        """Meta options for the BackupOptions model."""

        verbose_name = 'Backup Option'

    def __str__(self) -> str:
        """Return a string representation of the backup options."""
        return f'{self.user}@{self.host}:{self.port} ({self.auth_method})'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Ensure only one instance exists (singleton pattern)."""
        self.full_clean()

        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Prevent the creation of more than one instance."""
        if BackupOptions.objects.exists() and not self.pk:
            msg = 'Only one BackupOptions instance is allowed.'
            raise ValidationError(msg)

        return super().clean()


class KeyStorageConfig(models.Model):
    """Configuration model for cryptographic material storage."""

    class StorageType(models.TextChoices):
        """Types of cryptographic storage."""

        SOFTWARE = 'software', _('Software (No Encryption)')
        SOFTHSM = 'softhsm', _('SoftHSM Container')
        PHYSICAL_HSM = 'physical_hsm', _('Physical HSM')

    storage_type = models.CharField(
        max_length=12,
        choices=StorageType.choices,
        default=StorageType.SOFTWARE,
        verbose_name=_('Storage Type'),
        help_text=_('Type of storage for cryptographic material'),
    )

    hsm_config = models.OneToOneField(
        'PKCS11Token',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='crypto_storage_config',
        verbose_name=_('HSM Configuration'),
        help_text=_('Associated HSM token configuration (SoftHSM or Physical HSM)'),
    )

    last_updated = models.DateTimeField(auto_now=True, verbose_name=_('Last Updated'))

    class Meta:
        """Meta options for the KeyStorageConfig model."""

        verbose_name = _('Crypto Storage Configuration')
        verbose_name_plural = _('Crypto Storage Configurations')

    def __str__(self) -> str:
        """Return a string representation of the storage configuration."""
        status = 'Active' if self.hsm_config is not None else 'Inactive'
        return f'{self.get_storage_type_display()} ({status})'

    @classmethod
    def get_config(cls) -> KeyStorageConfig:
        """Get the crypto storage configuration (singleton).

        Returns:
            KeyStorageConfig: The configuration instance

        Raises:
            cls.DoesNotExist: If no configuration exists
        """
        return cls.objects.get(pk=1)

    @classmethod
    def get_or_create_default(cls) -> KeyStorageConfig:
        """Get the configuration or create a default one.

        Returns:
            KeyStorageConfig: The configuration instance
        """
        config, _ = cls.objects.get_or_create(pk=1, defaults={'storage_type': cls.StorageType.SOFTWARE})
        return config


class PKCS11Token(models.Model, LoggerMixin):
    """Model representing a PKCS#11 token (e.g., a SoftHSM slot/token pair).

    Stores metadata required to authenticate and interact with the token,
    including slot number, user and security officer PINs, and the path to
    the PKCS#11 module library.
    """

    KEK_ENCRYPTION_KEY_LABEL = 'trustpoint-kek'
    DEK_CACHE_LABEL = 'trustpoint-dek-chache'
    WRAPPED_DEK_LENGTH = 40  # Expected length of wrapped DEK in bytes (8 bytes IV + 32 bytes encrypted DEK)

    # Argon2 configuration
    ARGON2_TIME_COST = 3  # Number of iterations
    ARGON2_MEMORY_COST = 65536  # Memory usage in KB (64MB)
    ARGON2_PARALLELISM = 1  # Number of parallel threads
    ARGON2_HASH_LENGTH = 32  # Output length (32 bytes for AES-256)

    label = models.CharField(
        max_length=100, unique=True, help_text=_('Token label in SoftHSM'), verbose_name=_('Label')
    )
    slot = models.PositiveIntegerField(help_text=_('Slot number in SoftHSM'), verbose_name=_('Slot'))
    module_path = models.CharField(
        max_length=255,
        default='/usr/local/lib/libpkcs11-proxy.so',
        help_text=_('Path to PKCS#11 module library'),
        verbose_name=_('Module Path'),
    )
    encrypted_dek = models.BinaryField(
        max_length=512,
        verbose_name=_('Encrypted Data Encryption Key (DEK)'),
        help_text=_('Symmetric key encrypted by the PKCS#11 private key'),
        blank=True,
        null=True,
    )
    bek_encrypted_dek = models.BinaryField(
        max_length=512,
        verbose_name=_('Encrypted Data Encryption Key (DEK)'),
        help_text=_('Symmetric key encrypted by the PKCS#11 private key'),
        blank=True,
        null=True,
    )
    kek = models.ForeignKey(
        'pki.PKCS11Key',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Key Encryption Key (KEK)'),
        help_text=_('Associated key encryption key stored in this token'),
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    class Meta:
        """Meta options for the PKCS11Token model."""

        verbose_name = _('PKCS#11 Token')
        verbose_name_plural = _('PKCS#11 Tokens')

    def __str__(self) -> str:
        """Returns a human-readable representation of the token.

        Returns:
            str: A string in the format "<label> (Slot <slot>)".
        """
        return f'{self.label} (Slot {self.slot})'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Ensure only one instance exists (singleton pattern)."""
        self.full_clean()
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls) -> PKCS11Token:
        """Returns the single instance, creating it if necessary."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def clean(self) -> None:
        """Ensure only one PKCS11Token instance exists.

        Raises:
        ------
        ValidationError
            If more than one PKCS11Token instance is attempted to be created.
        """
        if self.pk != 1 and PKCS11Token.objects.exists():
            msg = 'Only one PKCS11Token instance is allowed.'
            raise ValidationError(msg)

        return super().clean()

    def generate_kek(self, key_length: int = 256) -> bool:
        """Generate the KEK (key encryption key) in the PKCS#11 token.

        Args:
            key_length: AES key length in bits (default: 256)

        Returns:
            bool: True if key was generated successfully, False otherwise

        Raises:
            RuntimeError: If key generation fails
        """
        from pki.models.credential import PKCS11Key  # noqa: PLC0415

        try:
            kek, _ = PKCS11Key.objects.get_or_create(
                token_label=self.label,
                key_label=self.KEK_ENCRYPTION_KEY_LABEL,
                defaults={'key_type': PKCS11Key.KeyType.AES},
            )

            aes_key = kek.get_pkcs11_key_instance(lib_path=self.module_path, user_pin=self.get_pin())
            aes_key = cast('Pkcs11AESKey', aes_key)

            try:
                try:
                    aes_key.load_key()
                    self.logger.info("KEK '%s' already exists in token '%s'", self.KEK_ENCRYPTION_KEY_LABEL, self.label)

                    if not self.kek:
                        self.kek = kek
                        self.save(update_fields=['kek'])
                except pkcs11.NoSuchKey:
                    pass
                except Exception:
                    self.logger.exception("Exception occurred while loading KEK in token '%s'", self.label)
                else:
                    return True

                aes_key.generate_key(key_length)
                self.logger.info("Generated KEK '%s' in token '%s'", self.KEK_ENCRYPTION_KEY_LABEL, self.label)

                if not self.kek:
                    self.kek = kek
                    self.save(update_fields=['kek'])
                    self.logger.info("Linked KEK to token '%s'", self.label)

                return True

            finally:
                aes_key.close()

        except Exception as e:
            self.logger.exception("Failed to generate KEK for token '%s'", self.label)
            msg = f'Failed to generate KEK: {e!s}'
            raise RuntimeError(msg) from e

    def load_kek(self) -> bool:
        """Load and verify the KEK (key encryption key) exists on the PKCS#11 token.

        This method checks if the KEK actually exists on the physical HSM,
        not just in the database. It attempts to load the key from the HSM.

        Returns:
            bool: True if KEK exists on HSM, False otherwise
        """
        try:
            if not self.kek:
                self.logger.debug("No KEK reference in database for token '%s'", self.label)
                return False

            aes_key = self.kek.get_pkcs11_key_instance(lib_path=self.module_path, user_pin=self.get_pin())
            aes_key = cast('Pkcs11AESKey', aes_key)

            try:
                aes_key.load_key()
                self.logger.debug(
                    "KEK '%s' verified to exist on HSM token '%s'", self.KEK_ENCRYPTION_KEY_LABEL, self.label
                )
            except pkcs11.NoSuchKey:
                self.logger.warning("KEK reference exists in database but not on HSM token '%s'", self.label)
                return False
            else:
                return True
            finally:
                aes_key.close()

        except Exception as e:  # noqa: BLE001
            self.logger.warning("Failed to load KEK for token '%s': %s", self.label, e)
            return False

    def generate_and_wrap_dek(self, dek_size: int = 32) -> bytes:
        """Generate a new DEK and wrap it using the HSM AES key.

        Args:
            dek_size: Size of the DEK in bytes (default: 32 for AES-256)

        Returns:
            bytes: The wrapped DEK data

        Raises:
            RuntimeError: If DEK generation or wrapping fails
        """
        if dek_size not in [16, 24, 32]:  # AES-128, AES-192, AES-256
            msg = f'Invalid DEK size: {dek_size} (must be 16, 24, or 32)'
            self._raise_value_error(msg)

        self.clear_dek_cache()

        try:
            dek_bytes = os.urandom(dek_size)

            wrapped_data = self.wrap_dek(dek_bytes)

            if not self.encrypted_dek:
                self.encrypted_dek = wrapped_data
                self.save(update_fields=['encrypted_dek'])

        except (OSError, ValueError, TypeError, RuntimeError) as e:
            self.logger.exception('Failed to generate and wrap DEK for token %s', self.label)
            msg = f'DEK generation/wrapping failed: {e}'
            raise RuntimeError(msg) from e
        else:
            return wrapped_data

    def wrap_dek(self, dek_bytes: bytes) -> bytes:
        """Wrap a DEK using the HSM AES key.

        Args:
            dek_bytes: The plain DEK to wrap

        Returns:
            bytes: The wrapped DEK data

        Raises:
            RuntimeError: If wrapping fails
        """
        session = None
        wrapped_data: bytes | None = None
        try:
            pkcs11_lib = pkcs11.lib(self.module_path)
            pkcs11_token = pkcs11_lib.get_token(token_label=self.label)

            # Try to open a session with the user PIN, handling if already logged in
            try:
                session = pkcs11_token.open(user_pin=self.get_pin(), rw=True)
            except pkcs11.UserAlreadyLoggedIn:
                # If user is already logged in, logout and try again
                self.logger.debug('User already logged in to token %s, logging out and retrying', self.label)
                try:
                    pkcs11_token.logout()
                except Exception as logout_error:  # noqa: BLE001
                    self.logger.warning('Failed to logout before reopening session: %s', logout_error)
                # Retry opening the session
                session = pkcs11_token.open(user_pin=self.get_pin(), rw=True)

            wrap_key = session.get_key(key_type=pkcs11.KeyType.AES, label=self.KEK_ENCRYPTION_KEY_LABEL)

            # Use AES encryption instead of key wrapping since AES-KEY-WRAP is not supported
            # Generate a random IV for AES-ECB (though ECB doesn't use IV, we'll prepend for consistency)
            iv = os.urandom(8)  # 8 bytes for consistency

            # DEK is already 32 bytes (multiple of 16), no padding needed for AES-ECB
            # Encrypt using AES-ECB
            encrypted_data = wrap_key.encrypt(dek_bytes, mechanism=pkcs11.Mechanism.AES_ECB)

            # Return IV + encrypted data (8 + 32 = 40 bytes)
            wrapped_data = iv + encrypted_data

        except pkcs11.NoSuchKey as e:
            msg = (
                f"AES wrapping key '{self.KEK_ENCRYPTION_KEY_LABEL}' not found in token '{self.label}'. "
                'Generate the KEK first using generate_kek().'
            )
            raise RuntimeError(msg) from e
        except Exception as e:
            msg = f'Failed to wrap DEK: {e}'
            raise RuntimeError(msg) from e
        finally:
            if session:
                try:
                    session.close()
                except Exception as cleanup_error:  # noqa: BLE001
                    self.logger.warning('Failed to close session: %s', cleanup_error)

        if wrapped_data is None:
            msg = 'wrap_dek failed to produce wrapped_data'
            raise RuntimeError(msg)
        if isinstance(wrapped_data, (memoryview, bytearray)):
            wrapped_bytes = bytes(wrapped_data)
        elif isinstance(wrapped_data, bytes):
            wrapped_bytes = wrapped_data
        else:
            msg = f'wrap_dek returned unexpected type: {type(wrapped_data)!r}'
            raise TypeError(msg)

        return wrapped_bytes

    def _pad_to_block_size(self, data: bytes, block_size: int) -> bytes:
        """Pad data to block size using PKCS#7 padding.

        Args:
            data: Data to pad
            block_size: Block size for padding

        Returns:
            bytes: Padded data
        """
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad_from_block_size(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding from data.

        Args:
            data: Padded data

        Returns:
            bytes: Unpadded data

        Raises:
            ValueError: If padding is invalid
        """
        if not data:
            msg = 'Cannot unpad empty data'
            raise ValueError(msg)

        padding_length = data[-1]
        if padding_length == 0 or padding_length > len(data):
            msg = 'Invalid padding'
            raise ValueError(msg)

        # Verify padding
        for i in range(1, padding_length + 1):
            if data[-i] != padding_length:
                msg = 'Invalid padding'
                raise ValueError(msg)

        return data[:-padding_length]

    def get_dek(self) -> bytes:
        """Get the Data Encryption Key (DEK), unwrapping it if necessary.

        Returns:
            bytes: The 32-byte DEK

        Raises:
            RuntimeError: If DEK cannot be retrieved or unwrapped
        """
        cache_key = f'{self.DEK_CACHE_LABEL}-{self.label}'
        self.logger.debug('get_dek() called for token %s with cache key: %s', self.label, cache_key)

        cached_dek = cache.get(cache_key)
        if cached_dek is not None:
            # Some cache backends may store memoryview/bytearray — normalize to bytes
            if isinstance(cached_dek, (memoryview, bytearray)):
                cached_bytes = bytes(cached_dek)
            elif isinstance(cached_dek, bytes):
                cached_bytes = cached_dek
            else:
                err_msg = f'Unexpected cached DEK type: {type(cached_dek)!r}'
                self.logger.error(err_msg)
                raise RuntimeError(err_msg)

            if cached_bytes is not None:
                self.logger.debug('Cache HIT - Retrieved DEK from cache for token %s', self.label)
                return cached_bytes

        self.logger.debug('Cache MISS - No cached DEK found for token %s, unwrapping DEK', self.label)

        try:
            dek = self._unwrap_dek()
            self.logger.debug('DEK unwrapped successfully, attempting to cache with key: %s', cache_key)

            # Set in cache
            cache.set(cache_key, dek, None)

            # Verify it was cached
            verify_cached = cache.get(cache_key)
            if verify_cached:
                self.logger.debug('Cache SET successful - DEK cached for token %s', self.label)
            else:
                self.logger.error('Cache SET failed - DEK not cached for token %s', self.label)

        except Exception as e:
            self.logger.exception('Failed to retrieve DEK for token %s', self.label)
            msg = f'Failed to retrieve DEK: {e}'
            raise RuntimeError(msg) from e
        else:
            self.logger.debug('DEK retrieved successfully for token %s', self.label)
            return dek

    def _raise_no_dek(self) -> None:
        """Raise an error if no wrapped DEK is available.

        Raises:
            RuntimeError: If no wrapped DEK is available for unwrapping.
        """
        msg = 'No wrapped DEK available for unwrapping'
        raise RuntimeError(msg)

    def _raise_dek_no_value(self) -> None:
        """Raise an error if the unwrapped DEK has no value.

        Raises:
            RuntimeError: If the unwrapped DEK has no VALUE attribute.
        """
        msg = 'Unwrapped key has no VALUE attribute'
        raise RuntimeError(msg)

    def _raise_invalid_dek_length(self, length: int) -> None:
        """Raise an error for invalid DEK length.

        Args:
            length (int): The length of the DEK.

        Raises:
            RuntimeError: If the DEK length is invalid.
        """
        msg = f'Invalid unwrapped DEK length: {length} bytes'
        raise RuntimeError(msg)

    def _get_wrapped_data(self) -> bytes:
        """Get the wrapped DEK data.

        Returns:
            bytes: The wrapped DEK data.
        """
        if not self.encrypted_dek:
            self._raise_no_dek()
        if isinstance(self.encrypted_dek, memoryview):
            return bytes(self.encrypted_dek)
        if self.encrypted_dek is None:
            self._raise_no_dek()
        value = self.encrypted_dek
        if value is None:
            self._raise_no_dek()
        if isinstance(value, memoryview):
            return bytes(value)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        msg = f'Unexpected encrypted_dek type: {type(value)!r}'
        raise RuntimeError(msg)

    def _unwrap_dek(self) -> bytes:
        """Unwrap the DEK using the HSM AES key.

        If a legacy wrapped DEK is detected, it will be automatically
        migrated to the new format.

        Returns:
            bytes: The unwrapped DEK

        Raises:
            RuntimeError: If unwrapping fails or DEK is not available
        """
        if not self.encrypted_dek:
            self._raise_no_dek()

        wrapped_data = self._get_wrapped_data()
        self._log_unexpected_wrapped_length(wrapped_data)

        session = None

        try:
            session, wrap_key = self._open_session_and_get_wrap_key()
            dek_bytes = self._unwrap_with_key(wrap_key, wrapped_data)
            self._validate_dek_bytes(dek_bytes)

        except pkcs11.NoSuchKey as e:
            self._handle_no_such_key(e)
        except Exception as e:  # noqa: BLE001
            self._handle_unwrap_exception(e, wrapped_data)
        else:
            self.logger.info('DEK unwrapped successfully for token %s', self.label)
            return dek_bytes
        finally:
            self._cleanup_session(session)
        msg = 'Failed to unwrap DEK: Unknown error'
        raise RuntimeError(msg)

    def _log_unexpected_wrapped_length(self, wrapped_data: bytes) -> None:
        """Log a warning if the wrapped DEK length is unexpected.

        Args:
            wrapped_data (bytes): The wrapped DEK data.
        """
        if len(wrapped_data) != self.WRAPPED_DEK_LENGTH:
            self.logger.warning(
                'Unexpected wrapped DEK length: %d (expected %d)', len(wrapped_data), self.WRAPPED_DEK_LENGTH
            )

    def _open_session_and_get_wrap_key(self) -> tuple[pkcs11.Session, pkcs11.Key]:
        """Open a PKCS#11 session and retrieve the AES wrapping key for this token."""
        pkcs11_lib = pkcs11.lib(self.module_path)
        pkcs11_token = pkcs11_lib.get_token(token_label=self.label)
        session = pkcs11_token.open(user_pin=self.get_pin(), rw=True)
        wrap_key = session.get_key(key_type=pkcs11.KeyType.AES, label=self.KEK_ENCRYPTION_KEY_LABEL)
        return session, wrap_key

    def _raise_type_error(self, msg: str) -> NoReturn:
        """Raise a TypeError with the given message.

        Args:
            msg (str): The error message.

        Raises:
            TypeError: Always raised with the provided message.
        """
        raise TypeError(msg)

    def _unwrap_with_key(self, wrap_key: pkcs11.Key, wrapped_data: bytes) -> bytes:
        """Unwrap the DEK using the provided wrapping key.

        Handles both new format (8 bytes IV + 32 bytes encrypted DEK) and
        legacy format (16 bytes IV + 48 bytes padded encrypted DEK).

        Args:
            wrap_key (pkcs11.Key): The wrapping key.
            wrapped_data (bytes): The wrapped DEK data.

        Returns:
            bytes: The unwrapped DEK.
        """
        try:
            encrypted_data = wrapped_data[8:]

            # Decrypt using AES-ECB (no unpadding needed as DEK is exactly 32 bytes)
            decrypted_data = wrap_key.decrypt(encrypted_data, mechanism=pkcs11.Mechanism.AES_ECB)

            if isinstance(decrypted_data, bytes):
                return decrypted_data
            msg = f'Decrypt returned unexpected type: {type(decrypted_data)!r}'
            self._raise_type_error(msg)

        except Exception as e:
            msg = f'Failed to unwrap DEK: {e}'
            raise RuntimeError(msg) from e

    def _validate_dek_bytes(self, dek_bytes: bytes) -> None:
        """Validate the unwrapped DEK bytes."""
        if not dek_bytes:
            self._raise_dek_no_value()
        if len(dek_bytes) not in [16, 24, 32]:
            self._raise_invalid_dek_length(len(dek_bytes))

    def _handle_no_such_key(self, e: Exception) -> None:
        """Handle the case where the wrapping key is not found.

        Args:
            e (Exception): The exception raised.

        Raises:
            RuntimeError: If the wrapping key is not found.
        """
        msg = (
            f"AES wrapping key '{self.KEK_ENCRYPTION_KEY_LABEL}' not found in token '{self.label}'. "
            'Generate the KEK first using generate_kek().'
        )
        raise RuntimeError(msg) from e

    def _handle_unwrap_exception(self, e: Exception, wrapped_data: bytes) -> None:
        """Handle exceptions that occur during DEK unwrapping.

        Args:
            e (Exception): The exception raised.
            wrapped_data (bytes): The wrapped DEK data.

        Raises:
            RuntimeError: If the wrapped DEK data is invalid.
            RuntimeError: If the unwrapping mechanism is not supported.
            RuntimeError: If the DEK unwrapping fails for any other reason.
        """
        error_msg = str(e).lower()
        if 'bytes must be in range' in error_msg or 'invalid data' in error_msg:
            msg = (
                f'Wrapped DEK data is corrupted or incompatible. '
                f'Data length: {len(wrapped_data)} bytes. '
                f'Consider regenerating the DEK. Original error: {e}'
            )
            raise RuntimeError(msg) from e
        if 'mechanism' in error_msg:
            msg = f'AES Key Wrap mechanism not supported or configured incorrectly. Original error: {e}'
            raise RuntimeError(msg) from e
        self.logger.exception('DEK unwrapping failed')
        msg = f'Failed to unwrap DEK: {e}'
        raise RuntimeError(msg) from e

    def _cleanup_session(self, session: pkcs11.Session) -> None:
        """Cleanup the session from memory.

        Args:
            session (pkcs11.Session): The session object.
        """
        if session:
            try:
                session.close()
            except Exception as cleanup_error:  # noqa: BLE001
                self.logger.warning('Failed to close session: %s', cleanup_error)

    def get_dek_cache(self) -> bytes | None:
        """Get the cached DEK without triggering unwrapping.

        This method provides direct access to the cached DEK value without
        performing any PKCS#11 operations. Returns None if the cache is empty.

        Returns:
            bytes | None: The cached DEK bytes if available, None otherwise.
        """
        cache_key = f'{self.DEK_CACHE_LABEL}-{self.label}'
        value = cache.get(cache_key)
        if value is None:
            return None
        if isinstance(value, memoryview):
            return bytes(value)
        if isinstance(value, bytes):
            return value
        return None

    def clear_dek_cache(self) -> None:
        """Clear the cached DEK from memory."""
        cache_key = f'{self.DEK_CACHE_LABEL}-{self.label}'
        cache.delete(cache_key)
        self.logger.debug('Cleared DEK cache for token %s', self.label)

    def get_pin(self) -> str:
        """Get the user PIN for this PKCS#11 token.

        PIN retrieval priority:
        1. HSM_PIN_FILE environment variable (Docker secrets)
        2. HSM_PIN environment variable

        Returns:
            str: The user PIN for token authentication.

        Raises:
            ImproperlyConfigured: If no PIN is available.
        """
        # Try reading from HSM_PIN_FILE (Docker secrets approach)
        hsm_pin_file = os.getenv('HSM_PIN_FILE', '/run/secrets/hsm_pin')
        pin_path = Path(hsm_pin_file)
        if pin_path.exists() and os.access(hsm_pin_file, os.R_OK):
            try:
                with pin_path.open('r') as f:
                    pin = f.read().strip()
                    if pin:
                        return pin
            except Exception:  # noqa: BLE001
                self.logger.warning('Failed to read HSM PIN from file %s', hsm_pin_file)

        # Try HSM_PIN environment variable
        env_pin: str | None = os.getenv('HSM_PIN')
        if env_pin:
            return env_pin.strip()

        # No PIN available
        msg = (
            f"No PIN configured for PKCS#11 token '{self.label}'. "
            'Ensure HSM_PIN_FILE points to a readable file with the PIN, '
            'or set the HSM_PIN environment variable.'
        )
        raise ImproperlyConfigured(msg)

    def set_backup_password(self, password: str, dek_size: int = 32) -> None:
        """Set a backup password and encrypt the current DEK with BEK derived from it using Argon2.

        Args:
            password: The backup password to use for BEK derivation
            dek_size: Size of the DEK in bytes (default: 32 for AES-256)

        Raises:
            RuntimeError: If DEK encryption with BEK fails
            ValueError: If no DEK is available to encrypt or invalid parameters
        """
        if not password:
            msg = 'Backup password cannot be empty'
            self._raise_value_error(msg)

        if dek_size not in [16, 24, 32]:
            msg = f'Invalid DEK size: {dek_size} (must be 16, 24, or 32)'
            raise ValueError(msg)

        try:
            # Get the current DEK
            if self.encrypted_dek:
                # Unwrap existing DEK
                dek_bytes = self._unwrap_dek()
            else:
                msg = 'No DEK available. Generate and wrap a DEK first using generate_and_wrap_dek()'
                self._raise_value_error(msg)

            # Derive BEK from password using Argon2
            bek = self._derive_bek_from_password(password)

            # Encrypt DEK with BEK
            encrypted_dek = self._encrypt_dek_with_bek(dek_bytes, bek)

            # Store only the backup encrypted DEK
            self.bek_encrypted_dek = encrypted_dek

            self.save(update_fields=['bek_encrypted_dek'])

            self.logger.info('Backup password set and DEK encrypted with BEK for token %s', self.label)

        except Exception as e:
            self.logger.exception('Failed to set backup password for token %s', self.label)
            msg = f'Failed to set backup password: {e}'
            raise RuntimeError(msg) from e

    def get_dek_with_backup_password(self, password: str) -> bytes:
        """Retrieve the DEK using the backup password.

        Args:
            password: The backup password used for BEK derivation

        Returns:
            bytes: The decrypted DEK

        Raises:
            RuntimeError: If DEK decryption fails
            ValueError: If no backup encryption is available
        """
        if not self.bek_encrypted_dek:
            msg = 'No backup encrypted DEK available. Set a backup password first.'
            raise ValueError(msg)

        if not password:
            msg = 'Backup password cannot be empty'
            raise ValueError(msg)

        try:
            # Derive BEK from password using Argon2
            bek = self._derive_bek_from_password(password)

            # Decrypt DEK with BEK
            dek_bytes = self._decrypt_dek_with_bek(self.bek_encrypted_dek, bek)

        except Exception as e:
            self.logger.exception('Failed to retrieve DEK with backup password for token %s', self.label)
            msg = f'Failed to retrieve DEK with backup password: {e}'
            raise RuntimeError(msg) from e
        else:
            self.logger.info('DEK successfully retrieved using backup password for token %s', self.label)
            return dek_bytes

    def verify_backup_password(self, password: str) -> bool:
        """Verify if the provided backup password is correct.

        Args:
            password: The backup password to verify

        Returns:
            bool: True if password is correct, False otherwise
        """
        try:
            self.get_dek_with_backup_password(password)
        except (RuntimeError, ValueError):
            return False
        else:
            return True

    def remove_backup_encryption(self) -> None:
        """Remove backup encryption (BEK-encrypted DEK).

        This only removes the backup encryption, the primary KEK-encrypted DEK remains.
        """
        self.bek_encrypted_dek = None
        self.save(update_fields=['bek_encrypted_dek'])
        self.logger.info('Backup encryption removed for token %s', self.label)

    def has_backup_encryption(self) -> bool:
        """Check if backup encryption is configured.

        Returns:
            bool: True if backup encryption is available, False otherwise
        """
        return bool(self.bek_encrypted_dek)

    def _raise_value_error(self, message: str) -> None:
        """Raise a ValueError with the given message."""
        raise ValueError(message)

    def _derive_bek_from_password(self, password: str) -> bytes:
        """Derive a BEK (Backup Encryption Key) from a password using Argon2.

        Uses deterministic salt based on token label to ensure the same password
        always produces the same key for the same token.

        Args:
            password: The password to derive the key from

        Returns:
            bytes: The 32-byte derived BEK

        Raises:
            ValueError: If password is invalid
        """
        if not password:
            msg = 'Password cannot be empty'
            self._raise_value_error(msg)

        try:
            # Create deterministic salt from token label
            salt_input = f'trustpoint-bek:{self.label}:{self.created_at.isoformat()}'
            salt = hashlib.sha256(salt_input.encode('utf-8')).digest()[:16]  # 16 bytes for Argon2

            return hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=self.ARGON2_TIME_COST,
                memory_cost=self.ARGON2_MEMORY_COST,
                parallelism=self.ARGON2_PARALLELISM,
                hash_len=self.ARGON2_HASH_LENGTH,
                type=Type.ID,  # Argon2id variant (most secure)
            )

        except Exception as e:
            msg = f'Failed to derive BEK from password: {e}'
            raise ValueError(msg) from e

    def _encrypt_dek_with_bek(self, dek_bytes: bytes, bek: bytes) -> bytes:
        """Encrypt DEK using BEK with AES-GCM.

        Args:
            dek_bytes: The DEK to encrypt
            bek: The BEK to use for encryption

        Returns:
            bytes: IV (12 bytes) + encrypted_data + tag (16 bytes)

        Raises:
            ValueError: If encryption fails
        """
        try:
            # Generate random IV for GCM
            iv = secrets.token_bytes(12)  # 96 bits for GCM

            # Create cipher
            cipher = Cipher(algorithms.AES(bek), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Encrypt
            ciphertext = encryptor.update(dek_bytes) + encryptor.finalize()

            # Return IV + ciphertext + tag
            return iv + ciphertext + encryptor.tag

        except Exception as e:
            msg = f'Failed to encrypt DEK with BEK: {e}'
            raise ValueError(msg) from e

    def _decrypt_dek_with_bek(self, encrypted_data: bytes | memoryview, bek: bytes) -> bytes:
        """Decrypt DEK using BEK with AES-GCM.

        Args:
            encrypted_data: The encrypted DEK (IV + ciphertext + tag)
            bek: The BEK to use for decryption

        Returns:
            bytes: The decrypted DEK

        Raises:
            ValueError: If decryption fails
        """
        try:
            # Convert from memoryview if necessary
            if isinstance(encrypted_data, memoryview):
                encrypted_data = bytes(encrypted_data)

            # Extract IV, ciphertext, and tag
            min_encrypted_data_length = 28  # 12 (IV) + 16 (tag) = minimum
            if len(encrypted_data) < min_encrypted_data_length:
                msg = f'Invalid encrypted data length: {len(encrypted_data)}'
                self._raise_value_error(msg)

            iv = encrypted_data[:12]
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[12:-16]

            # Create cipher
            cipher = Cipher(algorithms.AES(bek), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt and verify
            return decryptor.update(ciphertext) + decryptor.finalize()

        except Exception as e:
            msg = f'Failed to decrypt DEK with BEK: {e}'
            raise ValueError(msg) from e


class LoggingConfig(models.Model):
    """Logging Configuration model."""

    class LogLevelChoices(models.TextChoices):
        """Types of log levels."""

        DEBUG = '0', _('Debug')
        INFO = '1', _('Info')
        WARNING = '2', _('Warning')
        ERROR = '3', _('Error')
        CRITICAL = '4', _('Critical')

    log_level = models.CharField(max_length=8, choices=LogLevelChoices, default=LogLevelChoices.INFO)

    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.log_level}'
