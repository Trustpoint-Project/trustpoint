"""Runtime services for application-secret encryption."""

from __future__ import annotations

import base64
import os
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, cast

import pkcs11
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11ConfigModel,
    AppSecretSoftwareConfigModel,
)
from crypto.local_development import ensure_local_software_backends

if TYPE_CHECKING:
    from collections.abc import Iterable

DEK_LENGTH_BYTES: Final[int] = 32
AES_GCM_NONCE_BYTES: Final[int] = 12
AES_GCM_TAG_BYTES: Final[int] = 16
CIPHERTEXT_PREFIX: Final[str] = 'tpsec:v1:'
AAD_CONTEXT: Final[bytes] = b'trustpoint-app-secrets-v1'
APP_SECRET_KEK_CAPABILITIES: Final[pkcs11.MechanismFlag] = (
    pkcs11.MechanismFlag.ENCRYPT
    | pkcs11.MechanismFlag.DECRYPT
    | pkcs11.MechanismFlag.WRAP
    | pkcs11.MechanismFlag.UNWRAP
)
APP_SECRET_KEK_TEMPLATE: Final[dict[pkcs11.Attribute, object]] = {
    pkcs11.Attribute.TOKEN: True,
    pkcs11.Attribute.PRIVATE: True,
    pkcs11.Attribute.SENSITIVE: True,
    pkcs11.Attribute.EXTRACTABLE: False,
    pkcs11.Attribute.ENCRYPT: True,
    pkcs11.Attribute.DECRYPT: True,
    pkcs11.Attribute.WRAP: True,
    pkcs11.Attribute.UNWRAP: True,
}
APP_SECRET_DEK_WRAP_MECHANISMS: Final[tuple[pkcs11.Mechanism, ...]] = (
    pkcs11.Mechanism.AES_KEY_WRAP,
    pkcs11.Mechanism.AES_KEY_WRAP_PAD,
    pkcs11.Mechanism.AES_KEY_WRAP_KWP,
)


class AppSecretError(RuntimeError):
    """Base error for the app-secret subsystem."""


class AppSecretConfigurationError(AppSecretError):
    """Raised when the app-secret subsystem is not configured correctly."""


class _Pkcs11Kek(Protocol):
    def __getitem__(self, attribute: pkcs11.Attribute) -> object:
        """Return a PKCS#11 object attribute value."""
        raise NotImplementedError

    def encrypt(self, plaintext: bytes, *, mechanism: object) -> bytes | bytearray | memoryview:
        """Wrap plaintext with the PKCS#11 key."""
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes, *, mechanism: object) -> bytes | bytearray | memoryview:
        """Unwrap ciphertext with the PKCS#11 key."""
        raise NotImplementedError


class _Pkcs11Slot(Protocol):
    slot_id: int

    def get_token(self) -> pkcs11.Token:
        """Return the token present in this slot."""
        raise NotImplementedError


class _Pkcs11Library(Protocol):
    def get_slots(self, *, token_present: bool = False) -> Iterable[_Pkcs11Slot]:
        """Return library slots, optionally filtered to slots with present tokens."""
        raise NotImplementedError


@dataclass(slots=True)
class _DekCache:
    """Process-local DEK cache state."""

    signature: tuple[object, ...] | None = None
    value: bytes | None = None


_DEK_CACHE_LOCK = threading.Lock()
_DEK_CACHE = _DekCache()


def clear_app_secret_cache() -> None:
    """Clear the process-local DEK cache."""
    with _DEK_CACHE_LOCK:
        _DEK_CACHE.signature = None
        _DEK_CACHE.value = None


class BaseAppSecretService:
    """Common AES-GCM encryption logic for application secrets."""

    def encrypt_text(self, plaintext: str) -> str:
        """Encrypt and encode plaintext for database storage."""
        if plaintext == '':
            return plaintext

        dek = self.require_dek()
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(AAD_CONTEXT)
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        payload = nonce + encryptor.tag + ciphertext
        return CIPHERTEXT_PREFIX + base64.b64encode(payload).decode('ascii')

    def decrypt_text(self, ciphertext: str) -> str:
        """Decode and decrypt stored ciphertext."""
        if ciphertext == '':
            return ciphertext
        if not ciphertext.startswith(CIPHERTEXT_PREFIX):
            msg = 'Value is not in the Trustpoint application-secret ciphertext format.'
            raise AppSecretConfigurationError(msg)

        payload_b64 = ciphertext[len(CIPHERTEXT_PREFIX) :]
        payload = base64.b64decode(payload_b64.encode('ascii'))
        if len(payload) < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES:
            msg = 'Stored ciphertext payload is truncated.'
            raise AppSecretConfigurationError(msg)

        nonce = payload[:AES_GCM_NONCE_BYTES]
        tag = payload[AES_GCM_NONCE_BYTES : AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES]
        encrypted = payload[AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES :]

        dek = self.require_dek()
        cipher = Cipher(algorithms.AES(dek), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(AAD_CONTEXT)
        plaintext = decryptor.update(encrypted) + decryptor.finalize()
        return plaintext.decode('utf-8')

    def ensure_backend_ready(self) -> None:
        """Initialize any missing backend state."""

    def require_dek(self) -> bytes:
        """Return the active DEK."""
        raise NotImplementedError


class SoftwareAppSecretService(BaseAppSecretService):
    """Development-only software implementation for app secrets."""

    def __init__(self, config: AppSecretSoftwareConfigModel) -> None:
        """Initialize the software app-secret service."""
        self._config = config

    def _signature(self) -> tuple[object, ...]:
        return (self._config.backend_id, bytes(self._config.raw_dek or b''), 'software')

    def ensure_backend_ready(self) -> None:
        """Generate a development DEK when one is missing."""
        if self._config.raw_dek:
            return

        self._config.raw_dek = os.urandom(DEK_LENGTH_BYTES)
        self._config.full_clean()
        self._config.save(update_fields=['raw_dek'])
        clear_app_secret_cache()

    def require_dek(self) -> bytes:
        """Return the development DEK."""
        self.ensure_backend_ready()
        signature = self._signature()

        with _DEK_CACHE_LOCK:
            if signature == _DEK_CACHE.signature and _DEK_CACHE.value is not None:
                return _DEK_CACHE.value

            dek = bytes(self._config.raw_dek or b'')
            if len(dek) != DEK_LENGTH_BYTES:
                msg = 'Software app-secret backend DEK is missing or invalid.'
                raise AppSecretConfigurationError(msg)

            _DEK_CACHE.signature = signature
            _DEK_CACHE.value = dek
            return dek


class Pkcs11AppSecretService(BaseAppSecretService):
    """PKCS#11-backed DEK/KEK implementation for app secrets."""

    def __init__(self, config: AppSecretPkcs11ConfigModel) -> None:
        """Initialize the PKCS#11 app-secret service."""
        self._config = config

    def _signature(self) -> tuple[object, ...]:
        return (
            self._config.backend_id,
            self._config.module_path,
            self._config.token_label,
            self._config.token_serial,
            self._config.slot_id,
            self._config.auth_source,
            self._config.auth_source_ref,
            self._config.kek_label,
            bytes(self._config.wrapped_dek or b''),
            'pkcs11',
        )

    def ensure_backend_ready(self) -> None:
        """Ensure a KEK exists and a DEK has been wrapped into persistent state."""
        if self._config.wrapped_dek:
            return

        with self._open_session() as session:
            kek = self._load_or_create_kek(session)
            dek = os.urandom(DEK_LENGTH_BYTES)
            wrapped_dek = self._wrap_dek(kek=kek, dek=dek)

        self._config.wrapped_dek = wrapped_dek
        self._config.full_clean()
        self._config.save(update_fields=['wrapped_dek'])
        clear_app_secret_cache()

    def require_dek(self) -> bytes:
        """Return the unwrapped DEK from the active PKCS#11 configuration."""
        self.ensure_backend_ready()
        signature = self._signature()

        with _DEK_CACHE_LOCK:
            if signature == _DEK_CACHE.signature and _DEK_CACHE.value is not None:
                return _DEK_CACHE.value

            wrapped_dek = bytes(self._config.wrapped_dek or b'')
            if not wrapped_dek:
                msg = 'No wrapped DEK is configured for the PKCS#11 app-secret backend.'
                raise AppSecretConfigurationError(msg)

            with self._open_session() as session:
                kek = self._load_or_create_kek(session)
                dek = self._unwrap_dek(kek=kek, wrapped_dek=wrapped_dek)

            if len(dek) != DEK_LENGTH_BYTES:
                msg = f'Invalid unwrapped DEK length: {len(dek)} bytes.'
                raise AppSecretConfigurationError(msg)

            _DEK_CACHE.signature = signature
            _DEK_CACHE.value = dek
            return dek

    def unwrap_existing_dek(self) -> bytes:
        """Return the configured DEK without creating missing backend material."""
        wrapped_dek = bytes(self._config.wrapped_dek or b'')
        if not wrapped_dek:
            msg = 'No wrapped DEK is configured for the PKCS#11 app-secret backend.'
            raise AppSecretConfigurationError(msg)

        with self._open_session(rw=False) as session:
            kek = self._load_existing_kek(session)
            dek = self._unwrap_dek(kek=kek, wrapped_dek=wrapped_dek)

        if len(dek) != DEK_LENGTH_BYTES:
            msg = f'Invalid unwrapped DEK length: {len(dek)} bytes.'
            raise AppSecretConfigurationError(msg)
        return dek

    def _load_or_create_kek(self, session: pkcs11.Session) -> _Pkcs11Kek:
        """Load the persistent HSM KEK or create it once."""
        try:
            kek = cast('_Pkcs11Kek', session.get_key(label=self._config.kek_label, key_type=pkcs11.KeyType.AES))
        except pkcs11.NoSuchKey:
            kek = cast(
                '_Pkcs11Kek',
                session.generate_key(
                    pkcs11.KeyType.AES,
                    key_length=256,
                    label=self._config.kek_label,
                    store=True,
                    capabilities=APP_SECRET_KEK_CAPABILITIES,
                    template=APP_SECRET_KEK_TEMPLATE,
                ),
            )
            self._validate_kek_policy(kek)
            return kek
        else:
            self._validate_kek_policy(kek)
            return kek

    def _load_existing_kek(self, session: pkcs11.Session) -> _Pkcs11Kek:
        """Load the persistent HSM KEK without creating missing material."""
        try:
            kek = cast('_Pkcs11Kek', session.get_key(label=self._config.kek_label, key_type=pkcs11.KeyType.AES))
        except pkcs11.NoSuchKey as exception:
            msg = f'PKCS#11 app-secret KEK {self._config.kek_label!r} was not found on the configured token.'
            raise AppSecretConfigurationError(msg) from exception
        self._validate_kek_policy(kek)
        return kek

    def _wrap_dek(self, *, kek: _Pkcs11Kek, dek: bytes) -> bytes:
        """Wrap a DEK with an AES key-wrap mechanism."""
        last_error: pkcs11.PKCS11Error | None = None
        for mechanism in APP_SECRET_DEK_WRAP_MECHANISMS:
            try:
                return bytes(kek.encrypt(dek, mechanism=mechanism))
            except pkcs11.PKCS11Error as exception:
                last_error = exception

        msg = 'PKCS#11 app-secret KEK could not wrap the DEK with an AES key-wrap mechanism.'
        raise AppSecretConfigurationError(msg) from last_error

    def _unwrap_dek(self, *, kek: _Pkcs11Kek, wrapped_dek: bytes) -> bytes:
        """Unwrap a DEK with an AES key-wrap mechanism."""
        last_error: pkcs11.PKCS11Error | None = None
        for mechanism in APP_SECRET_DEK_WRAP_MECHANISMS:
            try:
                return bytes(kek.decrypt(wrapped_dek, mechanism=mechanism))
            except pkcs11.PKCS11Error as exception:
                last_error = exception

        msg = 'PKCS#11 app-secret KEK could not unwrap the DEK with a supported AES key-wrap mechanism.'
        raise AppSecretConfigurationError(msg) from last_error

    def _validate_kek_policy(self, kek: _Pkcs11Kek) -> None:
        """Reject KEKs whose visible PKCS#11 attributes are unsafe for app-secret wrapping."""
        expected_attributes = {
            pkcs11.Attribute.EXTRACTABLE: False,
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.PRIVATE: True,
        }
        for attribute, expected_value in expected_attributes.items():
            actual_value = self._optional_bool_attribute(kek, attribute)
            if actual_value is None or actual_value is expected_value:
                continue
            msg = (
                f'PKCS#11 app-secret KEK {self._config.kek_label!r} has unsafe attribute '
                f'{attribute.name}={actual_value!r}.'
            )
            raise AppSecretConfigurationError(msg)

    @staticmethod
    def _optional_bool_attribute(kek: _Pkcs11Kek, attribute: pkcs11.Attribute) -> bool | None:
        """Return a readable boolean PKCS#11 attribute, or None when the provider hides it."""
        try:
            value = kek[attribute]
        except (KeyError, TypeError, pkcs11.PKCS11Error):
            return None
        return bool(value)

    def _resolve_token(self, library: _Pkcs11Library) -> pkcs11.Token:
        """Resolve the configured token from the PKCS#11 library."""
        profile = self._config.build_provider_profile()
        matches: list[pkcs11.Token] = []

        for slot, token in self._discover_token_candidates(library):
            token_serial = getattr(token, 'serial', None) or getattr(token, 'serial_number', None)
            token_label = getattr(token, 'label', None)
            if profile.token.matches(
                slot_id=slot.slot_id,
                token_label=token_label,
                token_serial=token_serial,
            ):
                matches.append(token)

        if not matches:
            msg = 'Unable to resolve the configured PKCS#11 token for application secrets.'
            raise AppSecretConfigurationError(msg)
        if len(matches) > 1:
            msg = 'The configured PKCS#11 token selector matched multiple tokens for application secrets.'
            raise AppSecretConfigurationError(msg)
        return matches[0]

    def _discover_token_candidates(self, library: _Pkcs11Library) -> list[tuple[_Pkcs11Slot, pkcs11.Token]]:
        """Return present token candidates, tolerating providers that reject token-present scans."""
        try:
            return self._token_candidates_from_slots(library.get_slots(token_present=True))
        except pkcs11.PKCS11Error as token_present_error:
            try:
                return self._token_candidates_from_slots(library.get_slots(token_present=False))
            except pkcs11.PKCS11Error as full_scan_error:
                msg = (
                    'PKCS#11 app-secret backend failed while enumerating slots. '
                    f'Initial token-present scan failed with {type(token_present_error).__name__}; '
                    f'fallback full scan failed with {type(full_scan_error).__name__}.'
                )
                raise AppSecretConfigurationError(msg) from full_scan_error

    @staticmethod
    def _token_candidates_from_slots(slots: Iterable[_Pkcs11Slot]) -> list[tuple[_Pkcs11Slot, pkcs11.Token]]:
        """Return slot/token pairs for slots with present, recognized tokens."""
        candidates: list[tuple[_Pkcs11Slot, pkcs11.Token]] = []
        for slot in slots:
            try:
                token = slot.get_token()
            except (pkcs11.exceptions.TokenNotPresent, pkcs11.exceptions.TokenNotRecognised):
                continue
            candidates.append((slot, token))
        return candidates

    def _open_session(self, *, rw: bool = True) -> pkcs11.Session:
        """Open a read-write authenticated PKCS#11 session."""
        profile = self._config.build_provider_profile()
        library = cast('_Pkcs11Library', pkcs11.lib(profile.module_path))
        token = self._resolve_token(library)
        try:
            return token.open(user_pin=profile.require_user_pin(), rw=rw)
        except pkcs11.exceptions.UserAlreadyLoggedIn:
            return token.open(rw=rw)


def get_app_secret_service() -> BaseAppSecretService:
    """Return the active application-secret service implementation."""
    ensure_local_software_backends()
    backend = AppSecretBackendModel.objects.first()
    if backend is None:
        msg = 'The application-secret backend has not been configured yet.'
        raise AppSecretConfigurationError(msg)

    if backend.backend_kind == AppSecretBackendKind.PKCS11:
        return Pkcs11AppSecretService(backend.pkcs11_config)
    if backend.backend_kind == AppSecretBackendKind.SOFTWARE:
        return SoftwareAppSecretService(backend.software_config)

    msg = f'Unsupported app-secret backend kind {backend.backend_kind!r}.'
    raise AppSecretConfigurationError(msg)


def encrypt_app_secret(plaintext: str) -> str:
    """Encrypt plaintext via the configured app-secret backend."""
    return get_app_secret_service().encrypt_text(plaintext)


def decrypt_app_secret(ciphertext: str) -> str:
    """Decrypt ciphertext via the configured app-secret backend."""
    return get_app_secret_service().decrypt_text(ciphertext)
