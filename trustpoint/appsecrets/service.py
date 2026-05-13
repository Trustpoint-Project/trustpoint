"""Runtime services for application-secret encryption."""

from __future__ import annotations

import base64
import os
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, cast

import pkcs11
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings

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


class AppSecretError(RuntimeError):
    """Base error for the app-secret subsystem."""


class AppSecretConfigurationError(AppSecretError):
    """Raised when the app-secret subsystem is not configured correctly."""


class _Pkcs11Kek(Protocol):
    def encrypt(self, plaintext: bytes, *, mechanism: object) -> bytes | bytearray | memoryview: ...

    def decrypt(self, ciphertext: bytes, *, mechanism: object) -> bytes | bytearray | memoryview: ...


class _Pkcs11Slot(Protocol):
    slot_id: int

    def get_token(self) -> pkcs11.Token: ...


class _Pkcs11Library(Protocol):
    def get_slots(self, *, token_present: bool = False) -> Iterable[_Pkcs11Slot]: ...


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
        if not (getattr(settings, 'DEVELOPMENT_ENV', False) or getattr(settings, 'DOCKER_CONTAINER', False)):
            msg = (
                'The software app-secret backend is only allowed for development, testing, or demo-style '
                'container setups.'
            )
            raise AppSecretConfigurationError(msg)

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
            wrapped_dek = bytes(kek.encrypt(dek, mechanism=pkcs11.Mechanism.AES_ECB))

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
                dek = bytes(kek.decrypt(wrapped_dek, mechanism=pkcs11.Mechanism.AES_ECB))

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
            dek = bytes(kek.decrypt(wrapped_dek, mechanism=pkcs11.Mechanism.AES_ECB))

        if len(dek) != DEK_LENGTH_BYTES:
            msg = f'Invalid unwrapped DEK length: {len(dek)} bytes.'
            raise AppSecretConfigurationError(msg)
        return dek

    def _load_or_create_kek(self, session: pkcs11.Session) -> _Pkcs11Kek:
        """Load the persistent HSM KEK or create it once."""
        try:
            return cast('_Pkcs11Kek', session.get_key(label=self._config.kek_label, key_type=pkcs11.KeyType.AES))
        except pkcs11.NoSuchKey:
            return cast(
                '_Pkcs11Kek',
                session.generate_key(
                    pkcs11.KeyType.AES,
                    key_length=256,
                    label=self._config.kek_label,
                    store=True,
                ),
            )

    def _load_existing_kek(self, session: pkcs11.Session) -> _Pkcs11Kek:
        """Load the persistent HSM KEK without creating missing material."""
        try:
            return cast('_Pkcs11Kek', session.get_key(label=self._config.kek_label, key_type=pkcs11.KeyType.AES))
        except pkcs11.NoSuchKey as exception:
            msg = f'PKCS#11 app-secret KEK {self._config.kek_label!r} was not found on the configured token.'
            raise AppSecretConfigurationError(msg) from exception

    def _resolve_token(self, library: _Pkcs11Library) -> pkcs11.Token:
        """Resolve the configured token from the PKCS#11 library."""
        profile = self._config.build_provider_profile()
        matches: list[pkcs11.Token] = []

        for slot in library.get_slots(token_present=True):
            token = slot.get_token()
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
