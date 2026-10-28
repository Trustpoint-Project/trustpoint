# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Runtime services for application-secret encryption."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

import pkcs11
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap_with_padding, aes_key_wrap_with_padding
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
from django.db import DatabaseError, connection, transaction

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11ConfigModel,
    AppSecretSoftwareConfigModel,
)
from crypto.local_development import ensure_local_software_backends
from trustpoint.secret_key import development_software_kek

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

DEK_LENGTH_BYTES: Final[int] = 32
AES_GCM_NONCE_BYTES: Final[int] = 12
AES_GCM_TAG_BYTES: Final[int] = 16
CIPHERTEXT_PREFIX: Final[str] = 'tpsec:v1:'
AAD_CONTEXT: Final[bytes] = b'trustpoint-app-secrets-v1'
PKCS11_CWRAP_DEK_PREFIX: Final[bytes] = b'tpsec:pkcs11:cwrap:v1:'
PKCS11_ENCRYPTED_DEK_GCM_PREFIX: Final[bytes] = b'tpsec:pkcs11:enc-gcm:v1:'
APP_SECRET_KEK_BASE_TEMPLATE: Final[dict[pkcs11.Attribute, object]] = {
    pkcs11.Attribute.TOKEN: True,
    pkcs11.Attribute.PRIVATE: True,
    pkcs11.Attribute.SENSITIVE: True,
    pkcs11.Attribute.EXTRACTABLE: False,
}
APP_SECRET_KEK_PROFILES: Final[tuple[tuple[str, pkcs11.MechanismFlag, dict[pkcs11.Attribute, object]], ...]] = (
    (
        'wrap-unwrap',
        pkcs11.MechanismFlag.WRAP | pkcs11.MechanismFlag.UNWRAP,
        {
            **APP_SECRET_KEK_BASE_TEMPLATE,
            pkcs11.Attribute.WRAP: True,
            pkcs11.Attribute.UNWRAP: True,
        },
    ),
    (
        'encrypt-decrypt',
        pkcs11.MechanismFlag.ENCRYPT | pkcs11.MechanismFlag.DECRYPT,
        {
            **APP_SECRET_KEK_BASE_TEMPLATE,
            pkcs11.Attribute.ENCRYPT: True,
            pkcs11.Attribute.DECRYPT: True,
        },
    ),
    (
        'combined',
        (
            pkcs11.MechanismFlag.ENCRYPT
            | pkcs11.MechanismFlag.DECRYPT
            | pkcs11.MechanismFlag.WRAP
            | pkcs11.MechanismFlag.UNWRAP
        ),
        {
            **APP_SECRET_KEK_BASE_TEMPLATE,
            pkcs11.Attribute.ENCRYPT: True,
            pkcs11.Attribute.DECRYPT: True,
            pkcs11.Attribute.WRAP: True,
            pkcs11.Attribute.UNWRAP: True,
        },
    ),
)
APP_SECRET_DEK_WRAP_MECHANISMS: Final[tuple[pkcs11.Mechanism, ...]] = (
    pkcs11.Mechanism.AES_KEY_WRAP,
    pkcs11.Mechanism.AES_KEY_WRAP_PAD,
    pkcs11.Mechanism.AES_KEY_WRAP_KWP,
)
APP_SECRET_DEK_ENCRYPT_MECHANISMS: Final[tuple[tuple[pkcs11.Mechanism, bytes], ...]] = (
    (pkcs11.Mechanism.AES_GCM, PKCS11_ENCRYPTED_DEK_GCM_PREFIX),
)
PKCS11_MECHANISM_BYTES: Final[int] = 4
PKCS11_ATTEMPT_HEAD_LIMIT: Final[int] = 6
PKCS11_ATTEMPT_TAIL_LIMIT: Final[int] = 4
APP_SECRET_DEK_CAPABILITIES: Final[pkcs11.MechanismFlag] = pkcs11.MechanismFlag.ENCRYPT | pkcs11.MechanismFlag.DECRYPT
APP_SECRET_DEK_KEY_TEMPLATES: Final[tuple[tuple[str, dict[pkcs11.Attribute, object]], ...]] = (
    (
        'private-readable-session',
        {
            pkcs11.Attribute.TOKEN: False,
            pkcs11.Attribute.PRIVATE: True,
            pkcs11.Attribute.SENSITIVE: False,
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.ENCRYPT: True,
            pkcs11.Attribute.DECRYPT: True,
        },
    ),
    (
        'public-readable-session',
        {
            pkcs11.Attribute.TOKEN: False,
            pkcs11.Attribute.PRIVATE: False,
            pkcs11.Attribute.SENSITIVE: False,
            pkcs11.Attribute.EXTRACTABLE: True,
            pkcs11.Attribute.ENCRYPT: True,
            pkcs11.Attribute.DECRYPT: True,
        },
    ),
    (
        'minimal-private-readable-session',
        {
            pkcs11.Attribute.TOKEN: False,
            pkcs11.Attribute.PRIVATE: True,
            pkcs11.Attribute.SENSITIVE: False,
            pkcs11.Attribute.EXTRACTABLE: True,
        },
    ),
    (
        'minimal-public-readable-session',
        {
            pkcs11.Attribute.TOKEN: False,
            pkcs11.Attribute.PRIVATE: False,
            pkcs11.Attribute.SENSITIVE: False,
            pkcs11.Attribute.EXTRACTABLE: True,
        },
    ),
)


class AppSecretError(RuntimeError):
    """Base error for the app-secret subsystem."""


class AppSecretConfigurationError(AppSecretError):
    """Raised when the app-secret subsystem is not configured correctly."""


class _Pkcs11Kek(Protocol):
    @property
    def session(self) -> pkcs11.Session:
        """Return the session that owns this key object."""
        raise NotImplementedError

    def __getitem__(self, attribute: pkcs11.Attribute) -> object:
        """Return a PKCS#11 object attribute value."""
        raise NotImplementedError

    def wrap_key(self, key: _Pkcs11DekKey, *, mechanism: pkcs11.Mechanism) -> bytes | bytearray | memoryview:
        """Wrap a temporary DEK key object with this KEK."""
        raise NotImplementedError

    def encrypt(
        self,
        plaintext: bytes,
        *,
        mechanism: pkcs11.Mechanism,
        mechanism_param: bytes | pkcs11.GCMParams | None = None,
    ) -> bytes | bytearray | memoryview:
        """Encrypt raw DEK bytes with this KEK."""
        raise NotImplementedError

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        mechanism: pkcs11.Mechanism,
        mechanism_param: bytes | pkcs11.GCMParams | None = None,
    ) -> bytes | bytearray | memoryview:
        """Decrypt raw DEK bytes with this KEK."""
        raise NotImplementedError

    def unwrap_key(  # noqa: PLR0913 - mirrors python-pkcs11's unwrap_key API.
        self,
        object_class: pkcs11.ObjectClass,
        key_type: pkcs11.KeyType,
        key_data: bytes,
        *,
        mechanism: pkcs11.Mechanism,
        store: bool = False,
        capabilities: pkcs11.MechanismFlag | None = None,
        template: dict[pkcs11.Attribute, object] | None = None,
    ) -> _Pkcs11DekKey:
        """Unwrap a wrapped DEK into a temporary key object."""
        raise NotImplementedError

    def destroy(self) -> None:
        """Destroy a temporary KEK key object."""
        raise NotImplementedError


class _Pkcs11DekKey(Protocol):
    def __getitem__(self, attribute: pkcs11.Attribute) -> object:
        """Return a PKCS#11 object attribute value."""
        raise NotImplementedError

    def destroy(self) -> None:
        """Destroy the temporary DEK key object."""
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


SOFTWARE_ENVELOPE_PAYLOAD_BYTES: Final[int] = 72  # 32-byte KEK fingerprint and 40-byte RFC 5649 wrapped DEK.
SOFTWARE_DEK_PREFIX: Final[bytes] = b'tpsec:software:aes256-kwp:v1:'


def load_software_kek(*, allow_development_creation: bool = False) -> bytes:
    """Load the KEK; only fresh local initialization may create a development file."""
    path = os.environ.get('TRUSTPOINT_SOFTWARE_KEK_FILE')
    try:
        if path is None:
            if settings.DEBUG and not settings.DOCKER_CONTAINER:
                path = str(
                    development_software_kek(
                        settings.REPO_ROOT / 'var' / 'development' / 'software_kek',
                        allow_creation=allow_development_creation,
                    )
                )
            else:
                path = '/run/secrets/trustpoint_software_kek'
        with Path(path).open(encoding='ascii', newline='') as stream:
            value = stream.read(65)
    except (OSError, UnicodeError, ImproperlyConfigured) as exception:
        msg = 'Software KEK file cannot be read. Set TRUSTPOINT_SOFTWARE_KEK_FILE to the original readable secret file.'
        raise AppSecretConfigurationError(msg) from exception
    if re.fullmatch(r'[0-9a-fA-F]{64}', value) is None:
        msg = 'Software KEK file must contain exactly 64 hexadecimal characters, without whitespace.'
        raise AppSecretConfigurationError(msg)
    return bytes.fromhex(value)


def _stored_dek_ready(
    config: AppSecretSoftwareConfigModel | AppSecretPkcs11ConfigModel, kind: AppSecretBackendKind
) -> bool:
    """Refresh runtime state without taking an initialization lock on every field read."""
    try:
        config.refresh_from_db()
        backend = config.backend
    except ObjectDoesNotExist as exception:
        msg = 'Application-secret configuration is missing. Restore the installation database backup.'
        raise AppSecretConfigurationError(msg) from exception
    if backend.backend_kind != kind:
        msg = 'Application-secret backend changed; restart the application.'
        raise AppSecretConfigurationError(msg)
    return bool(config.wrapped_dek and backend.dek_initialized)


class SoftwareAppSecretService(BaseAppSecretService):
    """AES-256-KWP envelope encryption using an externally provisioned KEK."""

    def __init__(self, config: AppSecretSoftwareConfigModel) -> None:
        """Initialize without reading key material until cryptographic use."""
        self._config = config

    @staticmethod
    def wrap_dek(kek: bytes, dek: bytes) -> bytes:
        """Store format/backend/algorithm/version and a non-secret KEK fingerprint."""
        return SOFTWARE_DEK_PREFIX + hashlib.sha256(kek).digest() + aes_key_wrap_with_padding(kek, dek)

    @staticmethod
    def unwrap_dek(kek: bytes, wrapped: bytes) -> bytes:
        """Recover only supported authenticated envelopes; never replace broken material."""
        if not wrapped.startswith(SOFTWARE_DEK_PREFIX):
            msg = 'Unsupported software wrapped-DEK format. Restore a Trustpoint 1.0 database backup.'
            raise AppSecretConfigurationError(msg)
        payload = wrapped[len(SOFTWARE_DEK_PREFIX) :]
        if len(payload) != SOFTWARE_ENVELOPE_PAYLOAD_BYTES or payload[:32] != hashlib.sha256(kek).digest():
            msg = 'Incorrect software KEK or corrupted wrapped DEK. Restore the original KEK and database backup.'
            raise AppSecretConfigurationError(msg)
        try:
            dek = aes_key_unwrap_with_padding(kek, payload[32:])
        except (InvalidUnwrap, ValueError) as exception:
            msg = 'Software DEK unwrap failed. Restore the original KEK and an intact database backup.'
            raise AppSecretConfigurationError(msg) from exception
        if len(dek) != DEK_LENGTH_BYTES:
            msg = 'Unwrapped software DEK has an invalid length.'
            raise AppSecretConfigurationError(msg)
        return dek

    def ensure_backend_ready(self) -> None:
        """Serialize first initialization on the singleton; persist no plaintext keys."""
        if _stored_dek_ready(self._config, AppSecretBackendKind.SOFTWARE):
            load_software_kek()
            return
        with _initialization_transaction():
            backend = AppSecretBackendModel.objects.select_for_update().get(pk=self._config.backend_id)
            if backend.backend_kind != AppSecretBackendKind.SOFTWARE:
                msg = 'Application-secret backend changed; restart the application.'
                raise AppSecretConfigurationError(msg)
            self._config.refresh_from_db()
            if self._config.wrapped_dek:
                if not backend.dek_initialized:
                    msg = 'Wrapped DEK exists without its initialization marker. Restore consistent database state.'
                    raise AppSecretConfigurationError(msg)
                load_software_kek()
                return
            if backend.dek_initialized or _setup_completed():
                msg = (
                    'Software DEK is missing in an initialized installation. '
                    'Restore the database; no key was generated.'
                )
                raise AppSecretConfigurationError(msg)
            kek = load_software_kek(allow_development_creation=True)
            self._config.wrapped_dek = self.wrap_dek(kek, os.urandom(DEK_LENGTH_BYTES))
            self._config.save(update_fields=['wrapped_dek'])
            backend.dek_initialized = True
            backend.save(update_fields=['dek_initialized'])
        clear_app_secret_cache()

    def require_dek(self) -> bytes:
        """Validate the KEK before any cache hit and recover the persisted DEK."""
        self.ensure_backend_ready()
        kek = load_software_kek()
        wrapped = bytes(self._config.wrapped_dek or b'')
        signature = (self._config.backend_id, wrapped, hashlib.sha256(kek).digest(), 'software')
        with _DEK_CACHE_LOCK:
            if signature != _DEK_CACHE.signature or _DEK_CACHE.value is None:
                dek = self.unwrap_dek(kek, wrapped)
                _DEK_CACHE.signature, _DEK_CACHE.value = signature, dek
            return _DEK_CACHE.value


@contextlib.contextmanager
def _initialization_transaction() -> Iterator[None]:
    """Rollback database conflicts instead of risking replacement key material."""
    try:
        with transaction.atomic():
            yield
    except DatabaseError as exception:
        msg = (
            'DEK initialization database conflict or failure. '
            'Retry after checking database availability; keys were not replaced.'
        )
        raise AppSecretConfigurationError(msg) from exception


def _setup_completed() -> bool:
    """A completed installation must never self-repair deleted key state."""
    from setup_wizard.models import SetupWizardCompletedModel  # noqa: PLC0415

    # Operational databases may intentionally omit the bootstrap-only table.
    # Inspect first: catching a missing-table query inside atomic() would poison
    # the PostgreSQL transaction during genuine first-time initialization.
    tables = connection.introspection.table_names()
    return (
        'setup_wizard_setupwizardcompletedmodel' in tables
        and SetupWizardCompletedModel.objects.filter(pk=1, setup_completed_at__isnull=False).exists()
    )


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
        """Initialize under the database singleton lock, without replacing lost keys."""
        if _stored_dek_ready(self._config, AppSecretBackendKind.PKCS11):
            return
        with _initialization_transaction():
            backend = AppSecretBackendModel.objects.select_for_update().get(pk=self._config.backend_id)
            if backend.backend_kind != AppSecretBackendKind.PKCS11:
                msg = 'Application-secret backend changed; restart the application.'
                raise AppSecretConfigurationError(msg)
            self._config.refresh_from_db()
            if self._config.wrapped_dek:
                if not backend.dek_initialized:
                    msg = 'Wrapped DEK exists without its initialization marker. Restore consistent database state.'
                    raise AppSecretConfigurationError(msg)
                return
            if backend.dek_initialized or _setup_completed():
                msg = 'PKCS#11 DEK is missing in an initialized installation. Restore the database backup.'
                raise AppSecretConfigurationError(msg)
            with self._open_session() as session:
                kek = self._find_existing_kek(session)
                if kek is None:
                    _kek, _dek, protected_dek = self._create_kek_with_protected_dek(session)
                else:
                    self._validate_kek_policy(kek)
                    _dek, protected_dek = self._generate_protected_dek(session=session, kek=kek)
            self._config.wrapped_dek = protected_dek
            self._config.full_clean()
            self._config.save(update_fields=['wrapped_dek'])
            backend.dek_initialized = True
            backend.save(update_fields=['dek_initialized'])
        clear_app_secret_cache()

    def require_dek(self) -> bytes:
        """Return the recovered DEK from the active PKCS#11 configuration."""
        self.ensure_backend_ready()
        signature = self._signature()

        with _DEK_CACHE_LOCK:
            if signature == _DEK_CACHE.signature and _DEK_CACHE.value is not None:
                return _DEK_CACHE.value

            protected_dek = bytes(self._config.wrapped_dek or b'')
            if not protected_dek:
                msg = 'No protected DEK is configured for the PKCS#11 app-secret backend.'
                raise AppSecretConfigurationError(msg)

            with self._open_session() as session:
                kek = self._load_existing_kek(session)
                dek = self._recover_dek(kek=kek, protected_dek=protected_dek)

            if len(dek) != DEK_LENGTH_BYTES:
                msg = f'Invalid recovered DEK length: {len(dek)} bytes.'
                raise AppSecretConfigurationError(msg)

            _DEK_CACHE.signature = signature
            _DEK_CACHE.value = dek
            return dek

    def recover_existing_dek(self) -> bytes:
        """Return the configured DEK without creating missing backend material."""
        protected_dek = bytes(self._config.wrapped_dek or b'')
        if not protected_dek:
            msg = 'No protected DEK is configured for the PKCS#11 app-secret backend.'
            raise AppSecretConfigurationError(msg)

        with self._open_session(rw=False) as session:
            kek = self._load_existing_kek(session)
            dek = self._recover_dek(kek=kek, protected_dek=protected_dek)

        if len(dek) != DEK_LENGTH_BYTES:
            msg = f'Invalid recovered DEK length: {len(dek)} bytes.'
            raise AppSecretConfigurationError(msg)
        return dek

    def _find_existing_kek(self, session: pkcs11.Session) -> _Pkcs11Kek | None:
        """Return the persistent HSM KEK when it already exists."""
        try:
            return cast('_Pkcs11Kek', session.get_key(label=self._config.kek_label, key_type=pkcs11.KeyType.AES))
        except pkcs11.NoSuchKey:
            return None

    def _create_kek_with_protected_dek(self, session: pkcs11.Session) -> tuple[_Pkcs11Kek, bytes, bytes]:
        """Create a persistent KEK using the least broad standard profile that can protect a DEK."""
        attempt_errors: list[str] = []
        for profile_name, capabilities, template in APP_SECRET_KEK_PROFILES:
            kek: _Pkcs11Kek | None = None
            try:
                kek = cast(
                    '_Pkcs11Kek',
                    session.generate_key(
                        pkcs11.KeyType.AES,
                        key_length=DEK_LENGTH_BYTES * 8,
                        label=self._config.kek_label,
                        store=True,
                        capabilities=capabilities,
                        template=dict(template),
                    ),
                )
                self._validate_kek_policy(kek)
                dek, protected_dek = self._generate_protected_dek(session=session, kek=kek)
            except (AppSecretConfigurationError, AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
                attempt_errors.append(f'kek/{profile_name}: {self._format_pkcs11_attempt_error(exception)}')
                self._destroy_kek_best_effort(kek)
            else:
                return kek, dek, protected_dek

        msg = (
            'PKCS#11 app-secret backend could not create a persistent KEK that can protect a DEK.'
            f'{self._format_pkcs11_attempts(attempt_errors)}'
        )
        raise AppSecretConfigurationError(msg)

    def _load_existing_kek(self, session: pkcs11.Session) -> _Pkcs11Kek:
        """Load the persistent HSM KEK without creating missing material."""
        try:
            kek = cast('_Pkcs11Kek', session.get_key(label=self._config.kek_label, key_type=pkcs11.KeyType.AES))
        except pkcs11.NoSuchKey as exception:
            msg = f'PKCS#11 app-secret KEK {self._config.kek_label!r} was not found on the configured token.'
            raise AppSecretConfigurationError(msg) from exception
        self._validate_kek_policy(kek)
        return kek

    def verify_temporary_dek_protection_support(self) -> None:
        """Verify the token supports app-secret DEK protection without storing key material."""
        attempt_errors: list[str] = []
        with self._open_session() as session:
            for profile_name, capabilities, template in APP_SECRET_KEK_PROFILES:
                kek: _Pkcs11Kek | None = None
                try:
                    kek = cast(
                        '_Pkcs11Kek',
                        session.generate_key(
                            pkcs11.KeyType.AES,
                            key_length=DEK_LENGTH_BYTES * 8,
                            store=False,
                            capabilities=capabilities,
                            template={**template, pkcs11.Attribute.TOKEN: False},
                        ),
                    )
                    dek, protected_dek = self._generate_protected_dek(session=session, kek=kek)
                    recovered_dek = self._recover_dek(kek=kek, protected_dek=protected_dek)
                except (AppSecretConfigurationError, AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
                    attempt_errors.append(
                        f'temporary-kek/{profile_name}: {self._format_pkcs11_attempt_error(exception)}'
                    )
                else:
                    if recovered_dek == dek:
                        return
                    attempt_errors.append(
                        f'temporary-kek/{profile_name}: protected-DEK recovery returned a different DEK'
                    )
                finally:
                    self._destroy_kek_best_effort(kek)

        msg = (
            'PKCS#11 app-secret protection self-test failed. The token must support temporary AES KEK generation '
            'plus either AES key wrap/unwrap or authenticated AES-GCM encrypt/decrypt for DEK protection.'
            f'{self._format_pkcs11_attempts(attempt_errors)}'
        )
        raise AppSecretConfigurationError(msg)

    @staticmethod
    def _destroy_kek_best_effort(kek: _Pkcs11Kek | None) -> None:
        """Best-effort destroy for app-secret KEK objects."""
        if kek is not None:
            with contextlib.suppress(pkcs11.PKCS11Error, AttributeError):
                kek.destroy()

    @staticmethod
    def _create_temporary_dek_key(
        session: pkcs11.Session, *, dek: bytes, template: dict[pkcs11.Attribute, object]
    ) -> _Pkcs11DekKey:
        """Import raw DEK bytes as a temporary AES session key that can be wrapped."""
        object_template = {
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.AES,
            pkcs11.Attribute.VALUE: dek,
            **template,
        }
        return cast(
            '_Pkcs11DekKey',
            session.create_object(object_template),
        )

    @staticmethod
    def _generate_temporary_dek_key(
        session: pkcs11.Session,
        *,
        template: dict[pkcs11.Attribute, object],
        capabilities: pkcs11.MechanismFlag | None,
    ) -> _Pkcs11DekKey:
        """Generate a temporary AES session key that can be read and protected."""
        if capabilities is None:
            return cast(
                '_Pkcs11DekKey',
                session.generate_key(
                    pkcs11.KeyType.AES,
                    key_length=DEK_LENGTH_BYTES * 8,
                    store=False,
                    template=dict(template),
                ),
            )
        return cast(
            '_Pkcs11DekKey',
            session.generate_key(
                pkcs11.KeyType.AES,
                key_length=DEK_LENGTH_BYTES * 8,
                store=False,
                capabilities=capabilities,
                template=dict(template),
            ),
        )

    @staticmethod
    def _read_temporary_dek_key_value(dek_key: _Pkcs11DekKey) -> bytes:
        """Read raw DEK bytes from a temporary session key."""
        dek_value = dek_key[pkcs11.Attribute.VALUE]
        if isinstance(dek_value, bytes | bytearray | memoryview):
            return bytes(dek_value)
        msg = 'PKCS#11 app-secret DEK value is not readable bytes.'
        raise TypeError(msg)

    @staticmethod
    def _destroy_temporary_dek_key(dek_key: _Pkcs11DekKey | None) -> None:
        """Best-effort destroy for temporary session keys."""
        if dek_key is not None:
            with contextlib.suppress(pkcs11.PKCS11Error, AttributeError):
                dek_key.destroy()

    @staticmethod
    def _format_pkcs11_attempt_error(exception: Exception) -> str:
        """Return a non-secret PKCS#11 error summary for operator diagnostics."""
        return type(exception).__name__

    @staticmethod
    def _format_pkcs11_attempts(attempt_errors: list[str]) -> str:
        """Format bounded PKCS#11 attempt diagnostics."""
        if not attempt_errors:
            return ''
        visible_errors = attempt_errors[:PKCS11_ATTEMPT_HEAD_LIMIT]
        first_import_error = next((error for error in attempt_errors if error.startswith('import/')), None)
        if first_import_error and first_import_error not in visible_errors:
            visible_errors.append(first_import_error)
        for error in attempt_errors[-PKCS11_ATTEMPT_TAIL_LIMIT:]:
            if error not in visible_errors:
                visible_errors.append(error)
        suffix = ''
        omitted_count = len(attempt_errors) - len(visible_errors)
        if omitted_count > 0:
            suffix = f'; {omitted_count} additional attempts omitted'
        return ' Attempts: ' + '; '.join(visible_errors) + suffix

    def _generate_protected_dek(self, *, session: pkcs11.Session, kek: _Pkcs11Kek) -> tuple[bytes, bytes]:
        """Create a new DEK and protect it using generic PKCS#11 session-key flows."""
        attempt_errors: list[str] = []
        generated_dek = self._try_generate_and_protect_dek(session=session, kek=kek, attempt_errors=attempt_errors)
        if generated_dek is not None:
            return generated_dek

        dek = os.urandom(DEK_LENGTH_BYTES)
        protected_dek = self._try_import_and_protect_dek(
            session=session,
            kek=kek,
            dek=dek,
            attempt_errors=attempt_errors,
        )
        if protected_dek is not None:
            return dek, protected_dek
        encrypted_dek = self._try_encrypt_dek(kek=kek, dek=dek, attempt_errors=attempt_errors)
        if encrypted_dek is not None:
            return dek, encrypted_dek

        msg = (
            'PKCS#11 app-secret backend could not protect a DEK with standard PKCS#11 AES flows.'
            f'{self._format_pkcs11_attempts(attempt_errors)}'
        )
        raise AppSecretConfigurationError(msg)

    def _try_generate_and_protect_dek(
        self,
        *,
        session: pkcs11.Session,
        kek: _Pkcs11Kek,
        attempt_errors: list[str],
    ) -> tuple[bytes, bytes] | None:
        """Try generating a readable temporary DEK on the token, then protecting it."""
        capability_options: tuple[tuple[str, pkcs11.MechanismFlag | None], ...] = (
            ('encrypt-decrypt-capabilities', APP_SECRET_DEK_CAPABILITIES),
            ('default-capabilities', None),
        )
        for template_name, template in APP_SECRET_DEK_KEY_TEMPLATES:
            for capabilities_name, capabilities in capability_options:
                dek_key: _Pkcs11DekKey | None = None
                dek: bytes | None = None
                try:
                    dek_key = self._generate_temporary_dek_key(
                        session,
                        template=template,
                        capabilities=capabilities,
                    )
                    dek = self._read_temporary_dek_key_value(dek_key)
                    if len(dek) != DEK_LENGTH_BYTES:
                        attempt_errors.append(
                            f'generate/{template_name}/{capabilities_name}: '
                            f'generated temporary DEK has invalid length {len(dek)} bytes'
                        )
                        continue
                    protected_dek = self._try_wrap_temporary_dek_key(
                        kek=kek,
                        dek_key=dek_key,
                        attempt_errors=attempt_errors,
                        attempt_prefix=f'generate/{template_name}/{capabilities_name}',
                    )
                    if protected_dek is not None:
                        return dek, protected_dek
                    encrypted_dek = self._try_encrypt_dek(kek=kek, dek=dek, attempt_errors=attempt_errors)
                    if encrypted_dek is not None:
                        return dek, encrypted_dek
                except (AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
                    attempt_errors.append(
                        f'generate/{template_name}/{capabilities_name}: {self._format_pkcs11_attempt_error(exception)}'
                    )
                finally:
                    self._destroy_temporary_dek_key(dek_key)
        return None

    def _try_wrap_temporary_dek_key(
        self,
        *,
        kek: _Pkcs11Kek,
        dek_key: _Pkcs11DekKey,
        attempt_errors: list[str],
        attempt_prefix: str,
    ) -> bytes | None:
        """Try protecting a temporary DEK key object with C_WrapKey."""
        for mechanism in APP_SECRET_DEK_WRAP_MECHANISMS:
            try:
                return (
                    PKCS11_CWRAP_DEK_PREFIX
                    + int(mechanism).to_bytes(PKCS11_MECHANISM_BYTES, 'big')
                    + bytes(kek.wrap_key(dek_key, mechanism=mechanism))
                )
            except (AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
                attempt_errors.append(
                    f'{attempt_prefix}/{mechanism.name}: {self._format_pkcs11_attempt_error(exception)}'
                )
        return None

    def _try_import_and_protect_dek(
        self,
        *,
        session: pkcs11.Session,
        kek: _Pkcs11Kek,
        dek: bytes,
        attempt_errors: list[str],
    ) -> bytes | None:
        """Try importing local DEK bytes as a temporary AES session key, then protect it with C_WrapKey."""
        for template_name, template in APP_SECRET_DEK_KEY_TEMPLATES:
            dek_key: _Pkcs11DekKey | None = None
            try:
                dek_key = self._create_temporary_dek_key(session, dek=dek, template=template)
                protected_dek = self._try_wrap_temporary_dek_key(
                    kek=kek,
                    dek_key=dek_key,
                    attempt_errors=attempt_errors,
                    attempt_prefix=f'import/{template_name}',
                )
                if protected_dek is not None:
                    return protected_dek
            except (AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
                attempt_errors.append(f'import/{template_name}: {self._format_pkcs11_attempt_error(exception)}')
            finally:
                self._destroy_temporary_dek_key(dek_key)
        return None

    def _protect_dek(self, *, kek: _Pkcs11Kek, dek: bytes) -> bytes:
        """Protect an existing DEK with PKCS#11 C_WrapKey or C_Encrypt."""
        attempt_errors: list[str] = []
        session = kek.session
        protected_dek = self._try_import_and_protect_dek(
            session=session,
            kek=kek,
            dek=dek,
            attempt_errors=attempt_errors,
        )
        if protected_dek is not None:
            return protected_dek
        encrypted_dek = self._try_encrypt_dek(kek=kek, dek=dek, attempt_errors=attempt_errors)
        if encrypted_dek is not None:
            return encrypted_dek

        msg = (
            'PKCS#11 app-secret KEK could not protect the DEK with PKCS#11 C_WrapKey or C_Encrypt.'
            f'{self._format_pkcs11_attempts(attempt_errors)}'
        )
        raise AppSecretConfigurationError(msg)

    def _recover_dek(self, *, kek: _Pkcs11Kek, protected_dek: bytes) -> bytes:
        """Recover a DEK protected by a PKCS#11 KEK."""
        if protected_dek.startswith(PKCS11_ENCRYPTED_DEK_GCM_PREFIX):
            return self._decrypt_dek(
                kek=kek,
                protected_dek=protected_dek,
                prefix=PKCS11_ENCRYPTED_DEK_GCM_PREFIX,
                mechanism=pkcs11.Mechanism.AES_GCM,
            )
        if not protected_dek.startswith(PKCS11_CWRAP_DEK_PREFIX):
            msg = 'Stored PKCS#11 app-secret DEK is not in a supported protected-DEK envelope format.'
            raise AppSecretConfigurationError(msg)

        payload = protected_dek[len(PKCS11_CWRAP_DEK_PREFIX) :]
        mechanism_id = int.from_bytes(payload[:PKCS11_MECHANISM_BYTES], 'big')
        mechanisms = tuple(item for item in APP_SECRET_DEK_WRAP_MECHANISMS if int(item) == mechanism_id)
        if not mechanisms or len(payload) <= PKCS11_MECHANISM_BYTES:
            msg = 'Stored PKCS#11 DEK has an unsupported wrapping mechanism or truncated envelope.'
            raise AppSecretConfigurationError(msg)
        cwrapped_dek = payload[PKCS11_MECHANISM_BYTES:]
        attempt_errors: list[str] = []
        for mechanism in mechanisms:
            for template_name, template in APP_SECRET_DEK_KEY_TEMPLATES:
                for capabilities_name, capabilities in (
                    ('encrypt-decrypt-capabilities', APP_SECRET_DEK_CAPABILITIES),
                    ('default-capabilities', None),
                ):
                    dek_key: _Pkcs11DekKey | None = None
                    try:
                        if capabilities is None:
                            dek_key = kek.unwrap_key(
                                pkcs11.ObjectClass.SECRET_KEY,
                                pkcs11.KeyType.AES,
                                cwrapped_dek,
                                mechanism=mechanism,
                                store=False,
                                template=dict(template),
                            )
                        else:
                            dek_key = kek.unwrap_key(
                                pkcs11.ObjectClass.SECRET_KEY,
                                pkcs11.KeyType.AES,
                                cwrapped_dek,
                                mechanism=mechanism,
                                store=False,
                                capabilities=capabilities,
                                template=dict(template),
                            )
                        return self._read_temporary_dek_key_value(dek_key)
                    except (AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
                        attempt_errors.append(
                            f'unwrap/{template_name}/{capabilities_name}/{mechanism.name}: '
                            f'{self._format_pkcs11_attempt_error(exception)}'
                        )
                    finally:
                        self._destroy_temporary_dek_key(dek_key)

        msg = (
            'PKCS#11 app-secret KEK could not unwrap the DEK with PKCS#11 C_UnwrapKey.'
            f'{self._format_pkcs11_attempts(attempt_errors)}'
        )
        raise AppSecretConfigurationError(msg)

    def _try_encrypt_dek(self, *, kek: _Pkcs11Kek, dek: bytes, attempt_errors: list[str]) -> bytes | None:
        """Try protecting raw DEK bytes with PKCS#11 C_Encrypt."""
        for mechanism, prefix in APP_SECRET_DEK_ENCRYPT_MECHANISMS:
            iv = os.urandom(AES_GCM_NONCE_BYTES)
            try:
                ciphertext = bytes(
                    kek.encrypt(dek, mechanism=mechanism, mechanism_param=pkcs11.GCMParams(iv, aad=prefix))
                )
            except (AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
                attempt_errors.append(f'encrypt/{mechanism.name}: {self._format_pkcs11_attempt_error(exception)}')
                continue
            return prefix + iv + ciphertext
        return None

    def _decrypt_dek(
        self,
        *,
        kek: _Pkcs11Kek,
        protected_dek: bytes,
        prefix: bytes,
        mechanism: pkcs11.Mechanism,
    ) -> bytes:
        """Decrypt a DEK protected by PKCS#11 C_Encrypt."""
        payload = protected_dek[len(prefix) :]
        if len(payload) < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES + DEK_LENGTH_BYTES:
            msg = 'Stored PKCS#11 app-secret encrypted DEK payload is truncated.'
            raise AppSecretConfigurationError(msg)
        iv = payload[:AES_GCM_NONCE_BYTES]
        ciphertext = payload[AES_GCM_NONCE_BYTES:]
        try:
            dek = bytes(kek.decrypt(ciphertext, mechanism=mechanism, mechanism_param=pkcs11.GCMParams(iv, aad=prefix)))
        except (AttributeError, TypeError, pkcs11.PKCS11Error) as exception:
            msg = f'PKCS#11 app-secret KEK could not decrypt the DEK with {mechanism.name}.'
            raise AppSecretConfigurationError(msg) from exception
        if len(dek) != DEK_LENGTH_BYTES:
            msg = f'Invalid decrypted DEK length: {len(dek)} bytes.'
            raise AppSecretConfigurationError(msg)
        return dek

    def _validate_kek_policy(self, kek: _Pkcs11Kek) -> None:
        """Reject KEKs whose visible PKCS#11 attributes are unsafe for app-secret protection."""
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
        try:
            library = cast('_Pkcs11Library', pkcs11.lib(profile.module_path))
            token = self._resolve_token(library)
            try:
                return token.open(user_pin=profile.require_user_pin(), rw=rw)
            except pkcs11.exceptions.UserAlreadyLoggedIn:
                return token.open(rw=rw)
        except (pkcs11.PKCS11Error, OSError) as exception:
            msg = 'Cannot open the PKCS#11 token. Check the module, token availability, and configured PIN credentials.'
            raise AppSecretConfigurationError(msg) from exception


def get_app_secret_service() -> BaseAppSecretService:
    """Return the active application-secret service implementation."""
    ensure_local_software_backends()
    backend = AppSecretBackendModel.objects.first()
    if backend is None:
        msg = 'The application-secret backend has not been configured yet.'
        raise AppSecretConfigurationError(msg)

    try:
        if backend.backend_kind == AppSecretBackendKind.PKCS11:
            return Pkcs11AppSecretService(backend.pkcs11_config)
        if backend.backend_kind == AppSecretBackendKind.SOFTWARE:
            return SoftwareAppSecretService(backend.software_config)
    except ObjectDoesNotExist as exception:
        msg = 'Application-secret configuration is missing. Restore the installation database backup.'
        raise AppSecretConfigurationError(msg) from exception

    msg = f'Unsupported app-secret backend kind {backend.backend_kind!r}.'
    raise AppSecretConfigurationError(msg)


def encrypt_app_secret(plaintext: str) -> str:
    """Encrypt plaintext via the configured app-secret backend."""
    return get_app_secret_service().encrypt_text(plaintext)


def decrypt_app_secret(ciphertext: str) -> str:
    """Decrypt ciphertext via the configured app-secret backend."""
    return get_app_secret_service().decrypt_text(ciphertext)
