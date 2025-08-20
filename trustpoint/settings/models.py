"""Models concerning the Trustpoint settings."""
import base64
import os
from typing import ClassVar, Optional

import pkcs11
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.db import models
from django.utils.translation import gettext_lazy as _
from notifications.models import WeakECCCurve, WeakSignatureAlgorithm
from pki.util.keys import AutoGenPkiKeyAlgorithm
from trustpoint.logger import LoggerMixin



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

    NOTIFICATION_CONFIGURATIONS: ClassVar[dict] = {
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
    """TLS settings model"""

    ipv4_address = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)

    @classmethod
    def get_first_ipv4_address(cls) -> str:
        """Get the first IPv4 address or a default value."""

        try:
            network_settings = cls.objects.get(id=1)
            ipv4_address = network_settings.ipv4_address
        except cls.DoesNotExist:
            ipv4_address = '127.0.0.1'

        return ipv4_address


class AppVersion(models.Model):
    objects: models.Manager['AppVersion']

    version = models.CharField(max_length=17)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'App Version'

    def __str__(self) -> str:
        return f'{self.version} @ {self.last_updated.isoformat()}'


class BackupOptions(models.Model):
    """A singleton model (we always operate with pk=1) for backup settings.
    We store host/port/user/local_storage, plus either a password or an SSH key.
    """

    class AuthMethod(models.TextChoices):
        PASSWORD = 'password', 'Password'
        SSH_KEY   = 'ssh_key',  'SSH Key'

    local_storage = models.BooleanField(default=True, verbose_name=_('Use local storage'))

    sftp_storage = models.BooleanField(default=False, verbose_name=_('Use SFTP storage'))

    host = models.CharField(max_length=255, verbose_name=_('Host'), blank=True)
    port = models.PositiveIntegerField(default=2222, verbose_name=_('Port'), blank=True)
    user = models.CharField(max_length=128, verbose_name=_('Username'), blank=True)

    auth_method = models.CharField(
        max_length=10,
        choices=AuthMethod.choices,
        default=AuthMethod.PASSWORD,
        verbose_name=_('Authentication Method')
    )

    # TODO (Dome): Storing passwords in plain text
    password = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Password'),
        help_text=_('Plain‐text password for SFTP.')
    )

    private_key = models.TextField(
        blank=True,
        verbose_name=_('SSH Private Key (PEM format)'),
        help_text=_('Paste the private key here (PEM).')
    )

    key_passphrase = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Key Passphrase'),
        help_text=_('Passphrase for the private key, if any.')
    )

    remote_directory = models.CharField(
        max_length=512,
        blank=True,
        default='/upload/trustpoint/',
        verbose_name=_('Remote Directory'),
        help_text=_('Remote directory (e.g. /backups/) where files should be uploaded. '
                  'Trailing slash is optional.'),
    )

    def save(self, *args, **kwargs):
        """Ensure only one instance exists (singleton pattern)."""
        self.full_clean()

        super().save(*args, **kwargs)

    def clean(self):
        """Prevent the creation of more than one instance."""
        if BackupOptions.objects.exists() and not self.pk:
            raise ValidationError("Only one BackupOptions instance is allowed.")

        return super().clean()

    class Meta:
        verbose_name = "Backup Option"

    def __str__(self) -> str:
        return f'{self.user}@{self.host}:{self.port} ({self.auth_method})'

class PKCS11Token(models.Model, LoggerMixin):
    """
    Model representing a PKCS#11 token (e.g., a SoftHSM slot/token pair).

    Stores metadata required to authenticate and interact with the token,
    including slot number, user and security officer PINs, and the path to
    the PKCS#11 module library.
    """

    KEK_ENCRYPTION_KEY_LABEL = "trustpoint-kek"

    class HSMType(models.TextChoices):
        """Types of HSM."""
        SOFTHSM = 'softhsm', _('SoftHSM')
        PHYSICAL = 'physical', _('Physical HSM')

    hsm_type: str = models.CharField(
        max_length=10,
        choices=HSMType.choices,
        default=HSMType.SOFTHSM,
        help_text=_("Type of HSM (SoftHSM or Physical)"),
        verbose_name=_("HSM Type")
    )

    label: str = models.CharField(
        max_length=100,
        unique=True,
        help_text=_("Token label in SoftHSM"),
        verbose_name=_("Label")
    )
    slot: int = models.PositiveIntegerField(
        help_text=_("Slot number in SoftHSM"),
        verbose_name=_("Slot")
    )
    module_path: str = models.CharField(
        max_length=255,
        default="/usr/lib/softhsm/libsofthsm2.so",
        help_text=_("Path to PKCS#11 module library"),
        verbose_name=_("Module Path")
    )
    encrypted_dek = models.BinaryField(
        max_length=512,
        verbose_name=_('Encrypted Data Encryption Key (DEK)'),
        help_text=_('Symmetric key encrypted by the PKCS#11 private key'),
        blank=True,
        null=True
    )
    kek = models.ForeignKey(
        'pki.PKCS11Key',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Key Encryption Key (KEK)'),
        help_text=_('Associated key encryption key stored in this token')
    )

    created_at = models.DateTimeField(
        verbose_name=_('Created'),
        auto_now_add=True
    )

    _dek_cache: Optional[bytes] = None


    class Meta:
        """
        Meta configuration for the PKCS11Token model.
        """
        verbose_name = _("PKCS#11 Token")
        verbose_name_plural = _("PKCS#11 Tokens")

    def __str__(self) -> str:
        """
        Returns a human-readable representation of the token.

        Returns:
            str: A string in the format "<label> (Slot <slot>)".
        """
        return f"{self.label} (Slot {self.slot})"

    def generate_kek(self, key_length: int = 256) -> bool:
        """
        Generate the KEK (key encryption key) in the PKCS#11 token.

        Args:
            key_length: AES key length in bits (default: 256)

        Returns:
            bool: True if key was generated successfully, False otherwise

        Raises:
            RuntimeError: If key generation fails
        """
        from pki.models import PKCS11Key

        try:
            kek, created = PKCS11Key.objects.get_or_create(
                token_label=self.label,
                key_label=self.KEK_ENCRYPTION_KEY_LABEL,
                defaults={
                    'key_type': PKCS11Key.KeyType.AES
                }
            )

            aes_key = kek.get_pkcs11_key_instance(
                lib_path=self.module_path,
                user_pin=self.get_pin()
            )

            try:
                try:
                    aes_key.load_aes_key()
                    self.logger.info(f"KEK '{self.KEK_ENCRYPTION_KEY_LABEL}' already exists in token '{self.label}'")

                    if not self.kek:
                        self.kek = kek
                        self.save(update_fields=['kek'])

                    return True
                except Exception:
                    pass

                aes_key.generate_aes_key(key_length=key_length)
                self.logger.info(f"Generated KEK '{self.KEK_ENCRYPTION_KEY_LABEL}' in token '{self.label}'")

                aes_key.load_aes_key()
                self.logger.info(f"KEK verification successful for token '{self.label}'")

                if not self.kek:
                    self.kek = kek
                    self.save(update_fields=['kek'])
                    self.logger.info(f"Linked KEK to token '{self.label}'")

                return True

            finally:
                aes_key.close()

        except Exception as e:
            self.logger.error(f"Failed to generate KEK for token '{self.label}': {e}")
            raise RuntimeError(f"Failed to generate KEK: {str(e)}")

    def generate_and_wrap_dek(self, dek_size: int = 32) -> bytes:
        """
        Generate a new DEK and wrap it using the HSM AES key.

        Args:
            dek_size: Size of the DEK in bytes (default: 32 for AES-256)

        Returns:
            bytes: The wrapped DEK data

        Raises:
            RuntimeError: If DEK generation or wrapping fails
        """
        if dek_size not in [16, 24, 32]:  # AES-128, AES-192, AES-256
            raise ValueError(f"Invalid DEK size: {dek_size} (must be 16, 24, or 32)")

        self._dek_cache = None

        try:
            dek_bytes = os.urandom(dek_size)

            wrapped_data = self._wrap_dek(dek_bytes)

            if not self.encrypted_dek:
                self.encrypted_dek = wrapped_data
                self.save(update_fields=['encrypted_dek'])

            return wrapped_data

        except Exception as e:
            self.logger.error(f"Failed to generate and wrap DEK for token {self.label}: {e}")
            raise RuntimeError(f"DEK generation/wrapping failed: {e}")

    def _wrap_dek(self, dek_bytes: bytes) -> bytes:
        """
        Wrap a DEK using the HSM AES key.

        Args:
            dek_bytes: The plain DEK to wrap

        Returns:
            bytes: The wrapped DEK data

        Raises:
            RuntimeError: If wrapping fails
        """
        session = None
        temp_key = None

        try:
            pkcs11_lib = pkcs11.lib(self.module_path)
            pkcs11_token = pkcs11_lib.get_token(token_label=self.label)
            session = pkcs11_token.open(user_pin=self.get_pin(), rw=True)

            wrap_key = session.get_key(
                key_type=pkcs11.KeyType.AES,
                label=self.KEK_ENCRYPTION_KEY_LABEL
            )

            temp_label = f"temp-wrap-{os.urandom(8).hex()}"
            temp_key = session.create_object({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
                pkcs11.Attribute.TOKEN: False,  # Session key only
                pkcs11.Attribute.EXTRACTABLE: True,
                pkcs11.Attribute.VALUE: dek_bytes,
                pkcs11.Attribute.LABEL: temp_label,
            })

            wrapped_data = wrap_key.wrap_key(
                temp_key,
                mechanism=pkcs11.Mechanism.AES_KEY_WRAP
            )

            return wrapped_data

        except pkcs11.NoSuchKey:
            raise RuntimeError(
                f"AES wrapping key '{self.KEK_ENCRYPTION_KEY_LABEL}' not found in token '{self.label}'. "
                "Generate the KEK first using generate_kek()."
            )
        except Exception as e:
            raise RuntimeError(f"Failed to wrap DEK: {e}")

        finally:
            # Cleanup
            if temp_key:
                try:
                    temp_key.destroy()
                except Exception as cleanup_error:
                    self.logger.warning(f"Failed to cleanup temp key: {cleanup_error}")

            if session:
                try:
                    session.close()
                except Exception as cleanup_error:
                    self.logger.warning(f"Failed to close session: {cleanup_error}")

    def get_dek(self) -> bytes:
        """
        Get the Data Encryption Key (DEK), unwrapping it if necessary.

        Returns:
            bytes: The 32-byte DEK

        Raises:
            RuntimeError: If DEK cannot be retrieved or unwrapped
        """
        if hasattr(self, '_dek_cache') and self._dek_cache:
            return self._dek_cache

        try:
            dek = self._unwrap_dek()

            self._dek_cache = dek

            self.logger.info(f"Successfully retrieved DEK for token {self.label}")
            return dek

        except Exception as e:
            self.logger.error(f"Failed to retrieve DEK for token {self.label}: {e}")
            raise RuntimeError(f"Failed to retrieve DEK: {e}")

    def _unwrap_dek(self) -> bytes:
        """
        Unwrap the DEK using the HSM AES key.

        Returns:
            bytes: The unwrapped DEK

        Raises:
            RuntimeError: If unwrapping fails or DEK is not available
        """
        if not self.encrypted_dek:
            raise RuntimeError("No wrapped DEK available for unwrapping")

        if isinstance(self.encrypted_dek, memoryview):
            wrapped_data = bytes(self.encrypted_dek)
        else:
            wrapped_data = self.encrypted_dek

        if len(wrapped_data) != 40:
            self.logger.warning(f"Unexpected wrapped DEK length: {len(wrapped_data)} (expected 40)")

        session = None
        unwrapped_key = None

        try:
            pkcs11_lib = pkcs11.lib(self.module_path)
            pkcs11_token = pkcs11_lib.get_token(token_label=self.label)
            session = pkcs11_token.open(user_pin=self.get_pin(), rw=True)

            wrap_key = session.get_key(
                key_type=pkcs11.KeyType.AES,
                label=self.KEK_ENCRYPTION_KEY_LABEL
            )

            temp_label = f"temp-unwrap-{os.urandom(8).hex()}"
            unwrapped_key = wrap_key.unwrap_key(
                pkcs11.ObjectClass.SECRET_KEY,
                pkcs11.KeyType.AES,
                wrapped_data,
                template={
                    pkcs11.Attribute.LABEL: temp_label,
                    pkcs11.Attribute.TOKEN: False,
                    pkcs11.Attribute.ENCRYPT: True,
                    pkcs11.Attribute.DECRYPT: True,
                    pkcs11.Attribute.EXTRACTABLE: True,
                    pkcs11.Attribute.SENSITIVE: False,
                },
                mechanism=pkcs11.Mechanism.AES_KEY_WRAP
            )

            dek_bytes = unwrapped_key[pkcs11.Attribute.VALUE]

            if not dek_bytes:
                raise RuntimeError("Unwrapped key has no VALUE attribute")

            if len(dek_bytes) not in [16, 24, 32]:
                raise RuntimeError(f"Invalid unwrapped DEK length: {len(dek_bytes)} bytes")

            self.logger.info(f"Successfully unwrapped {len(dek_bytes)}-byte DEK")
            return dek_bytes

        except pkcs11.NoSuchKey:
            raise RuntimeError(
                f"AES wrapping key '{self.KEK_ENCRYPTION_KEY_LABEL}' not found in token '{self.label}'. "
                "Generate the KEK first using generate_kek()."
            )
        except Exception as e:
            error_msg = str(e).lower()

            if "bytes must be in range" in error_msg or "invalid data" in error_msg:
                raise RuntimeError(
                    f"Wrapped DEK data is corrupted or incompatible. "
                    f"Data length: {len(wrapped_data)} bytes. "
                    f"Consider regenerating the DEK. Original error: {e}"
                )
            elif "mechanism" in error_msg:
                raise RuntimeError(
                    f"AES Key Wrap mechanism not supported or configured incorrectly. "
                    f"Original error: {e}"
                )
            else:
                self.logger.error(f"DEK unwrapping failed: {e}")
                raise RuntimeError(f"Failed to unwrap DEK: {e}")

        finally:
            if unwrapped_key:
                try:
                    unwrapped_key.destroy()
                except Exception as cleanup_error:
                    self.logger.warning(f"Failed to cleanup unwrapped key: {cleanup_error}")

            if session:
                try:
                    session.close()
                except Exception as cleanup_error:
                    self.logger.warning(f"Failed to close session: {cleanup_error}")

    def clear_dek_cache(self):
        """Clear the cached DEK from memory."""
        if hasattr(self, '_dek_cache'):
            if self._dek_cache:
                self._dek_cache = b'\x00' * len(self._dek_cache)
            self._dek_cache = None
        self.logger.debug(f"Cleared DEK cache for token {self.label}")

    def get_pin(self) -> str:
        """
        Get the user PIN for this PKCS#11 token.

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
        if os.path.exists(hsm_pin_file) and os.access(hsm_pin_file, os.R_OK):
            try:
                with open(hsm_pin_file, 'r') as f:
                    pin = f.read().strip()
                    if pin:
                        return pin
            except (OSError, IOError) as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to read HSM PIN from file {hsm_pin_file}: {e}")

        # Try HSM_PIN environment variable
        pin = os.getenv('HSM_PIN')
        if pin:
            return pin.strip()

        # No PIN available
        raise ImproperlyConfigured(
            f"No PIN configured for PKCS#11 token '{self.label}'. "
            "Ensure HSM_PIN_FILE points to a readable file with the PIN, "
            "or set the HSM_PIN environment variable."
        )

    def __del__(self):
        """Ensure decrypted DEK is cleared when object is destroyed."""
        self.clear_dek_cache()


