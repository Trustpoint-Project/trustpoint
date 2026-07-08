"""Tests for application-secret service internals."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pkcs11
import pytest

from appsecrets.service import (
    DEK_LENGTH_BYTES,
    PKCS11_CWRAP_DEK_PREFIX,
    PKCS11_ENCRYPTED_DEK_CBC_PAD_PREFIX,
    AppSecretConfigurationError,
    Pkcs11AppSecretService,
)

pytestmark = pytest.mark.django_db


class _FakeDekKey:
    """Small PKCS#11 key fake for temporary DEK object tests."""

    def __init__(self, value: bytes) -> None:
        self.value = value
        self.destroyed = False

    def __getitem__(self, attribute: pkcs11.Attribute) -> object:
        if attribute == pkcs11.Attribute.VALUE:
            return self.value
        raise KeyError(attribute)

    def destroy(self) -> None:
        self.destroyed = True


class _FakeSession:
    """Small PKCS#11 session fake that creates temporary DEK objects."""

    def __init__(self) -> None:
        self.created_keys: list[_FakeDekKey] = []
        self.generated_keys: list[_FakeDekKey] = []
        self.generated_keks: list[_FakeKek] = []
        self.fail_generation = False
        self.reject_wrap_kek_profile = False

    def create_object(self, attrs: dict[pkcs11.Attribute, object]) -> _FakeDekKey:
        key = _FakeDekKey(bytes(attrs[pkcs11.Attribute.VALUE]))
        self.created_keys.append(key)
        return key

    def generate_key(
        self,
        _key_type: pkcs11.KeyType,
        *,
        key_length: int,
        store: bool,
        _capabilities: pkcs11.MechanismFlag | None = None,
        template: dict[pkcs11.Attribute, object] | None = None,
        **_kwargs: Any,
    ) -> _FakeDekKey | _FakeKek:
        assert key_length == DEK_LENGTH_BYTES * 8
        assert template is not None
        if self.fail_generation:
            raise pkcs11.PKCS11Error
        is_kek_template = (
            template.get(pkcs11.Attribute.SENSITIVE) is True
            and template.get(pkcs11.Attribute.EXTRACTABLE) is False
            and any(
                template.get(attribute) is True
                for attribute in (
                    pkcs11.Attribute.WRAP,
                    pkcs11.Attribute.UNWRAP,
                    pkcs11.Attribute.ENCRYPT,
                    pkcs11.Attribute.DECRYPT,
                )
            )
        )
        if is_kek_template:
            kek = _FakeKek(
                session=self,
                allow_wrap=template.get(pkcs11.Attribute.WRAP) is True,
                allow_encrypt=template.get(pkcs11.Attribute.ENCRYPT) is True,
            )
            if self.reject_wrap_kek_profile and template.get(pkcs11.Attribute.WRAP) is True:
                kek.fail_wrap = True
            self.generated_keks.append(kek)
            return kek
        assert store is False
        value = b'g' * 32
        key = _FakeDekKey(value)
        self.generated_keys.append(key)
        return key


class _FakeKek:
    """Small KEK fake that supports C_WrapKey and C_UnwrapKey style calls."""

    def __init__(
        self,
        session: _FakeSession | None = None,
        *,
        allow_wrap: bool = True,
        allow_encrypt: bool = True,
    ) -> None:
        self.session = session or _FakeSession()
        self.allow_wrap = allow_wrap
        self.allow_encrypt = allow_encrypt
        self.wrap_calls: list[tuple[_FakeDekKey, pkcs11.Mechanism]] = []
        self.unwrap_calls: list[tuple[bytes, pkcs11.Mechanism]] = []
        self.encrypt_calls: list[tuple[bytes, pkcs11.Mechanism, bytes | None]] = []
        self.decrypt_calls: list[tuple[bytes, pkcs11.Mechanism, bytes | None]] = []
        self.unwrapped_keys: list[_FakeDekKey] = []
        self.destroyed = False
        self.fail_wrap = False
        self.fail_encrypt = False
        self.fail_cbc_encrypt = False

    def __getitem__(self, _attribute: pkcs11.Attribute) -> object:
        attributes = {
            pkcs11.Attribute.EXTRACTABLE: False,
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.PRIVATE: True,
            pkcs11.Attribute.WRAP: self.allow_wrap,
            pkcs11.Attribute.UNWRAP: self.allow_wrap,
            pkcs11.Attribute.ENCRYPT: self.allow_encrypt,
            pkcs11.Attribute.DECRYPT: self.allow_encrypt,
        }
        return attributes[_attribute]

    def wrap_key(self, key: _FakeDekKey, *, mechanism: pkcs11.Mechanism) -> bytes:
        if not self.allow_wrap:
            raise pkcs11.exceptions.MechanismInvalid
        if self.fail_wrap:
            raise pkcs11.exceptions.MechanismInvalid
        self.wrap_calls.append((key, mechanism))
        return b'wrapped:' + key.value

    def unwrap_key(
        self,
        _object_class: pkcs11.ObjectClass,
        _key_type: pkcs11.KeyType,
        key_data: bytes,
        *,
        mechanism: pkcs11.Mechanism,
        store: bool = False,
        capabilities: pkcs11.MechanismFlag | None = None,
        template: dict[pkcs11.Attribute, object] | None = None,
        **_kwargs: Any,
    ) -> _FakeDekKey:
        self.unwrap_calls.append((key_data, mechanism))
        key = _FakeDekKey(key_data.removeprefix(b'wrapped:'))
        self.unwrapped_keys.append(key)
        assert store is False
        assert capabilities == pkcs11.MechanismFlag.ENCRYPT | pkcs11.MechanismFlag.DECRYPT
        assert template is not None
        assert template[pkcs11.Attribute.EXTRACTABLE] is True
        return key

    def encrypt(
        self,
        plaintext: bytes,
        *,
        mechanism: pkcs11.Mechanism,
        mechanism_param: bytes | None = None,
    ) -> bytes:
        if not self.allow_encrypt:
            raise pkcs11.exceptions.MechanismInvalid
        if self.fail_encrypt:
            raise pkcs11.exceptions.MechanismInvalid
        if self.fail_cbc_encrypt and mechanism in {pkcs11.Mechanism.AES_CBC_PAD, pkcs11.Mechanism.AES_CBC}:
            raise pkcs11.exceptions.MechanismInvalid
        self.encrypt_calls.append((plaintext, mechanism, mechanism_param))
        return b'encrypted:' + plaintext

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        mechanism: pkcs11.Mechanism,
        mechanism_param: bytes | None = None,
    ) -> bytes:
        self.decrypt_calls.append((ciphertext, mechanism, mechanism_param))
        return ciphertext.removeprefix(b'encrypted:')

    def destroy(self) -> None:
        self.destroyed = True


def _service() -> Pkcs11AppSecretService:
    service = Pkcs11AppSecretService.__new__(Pkcs11AppSecretService)
    object.__setattr__(service, '_config', SimpleNamespace(kek_label='trustpoint-test-kek'))
    return service


def test_pkcs11_app_secret_protect_dek_uses_key_wrap_operation() -> None:
    """DEK protection prefers C_WrapKey over a temporary AES key object."""
    service = _service()
    kek = _FakeKek()

    wrapped = service._protect_dek(kek=kek, dek=b'a' * 32)  # noqa: SLF001

    assert wrapped == PKCS11_CWRAP_DEK_PREFIX + b'wrapped:' + (b'a' * 32)
    assert len(kek.wrap_calls) == 1
    wrapped_key, mechanism = kek.wrap_calls[0]
    assert mechanism == pkcs11.Mechanism.AES_KEY_WRAP
    assert wrapped_key.destroyed


def test_pkcs11_app_secret_generate_protected_dek_prefers_token_generated_key() -> None:
    """New PKCS#11 app-secret DEKs are generated as temporary token keys when possible."""
    service = _service()
    kek = _FakeKek()

    dek, wrapped = service._generate_protected_dek(session=kek.session, kek=kek)  # noqa: SLF001

    assert dek == b'g' * 32
    assert wrapped == PKCS11_CWRAP_DEK_PREFIX + b'wrapped:' + (b'g' * 32)
    assert len(kek.session.generated_keys) == 1
    assert not kek.session.created_keys
    assert kek.session.generated_keys[0].destroyed


def test_pkcs11_app_secret_generate_protected_dek_falls_back_to_imported_key() -> None:
    """Providers that reject temporary key generation can still wrap imported session DEKs."""
    service = _service()
    kek = _FakeKek()
    kek.session.fail_generation = True

    dek, wrapped = service._generate_protected_dek(session=kek.session, kek=kek)  # noqa: SLF001

    assert len(dek) == DEK_LENGTH_BYTES
    assert wrapped == PKCS11_CWRAP_DEK_PREFIX + b'wrapped:' + dek
    assert len(kek.session.created_keys) == 1
    assert kek.session.created_keys[0].destroyed


def test_pkcs11_app_secret_temporary_protection_self_test_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    """The non-persistent PKCS#11 self-test verifies temporary KEK/DEK protection and recovery."""
    service = _service()
    session = _FakeSession()

    class _SessionContext:
        def __enter__(self) -> _FakeSession:
            return session

        def __exit__(self, *_args: object) -> None:
            return None

    def open_session() -> _SessionContext:
        return _SessionContext()

    monkeypatch.setattr(service, '_open_session', open_session)

    service.verify_temporary_dek_protection_support()

    assert len(session.generated_keys) == 1
    assert session.generated_keys[0].destroyed


def test_pkcs11_app_secret_kek_creation_falls_back_to_encrypt_profile() -> None:
    """A token can use an encrypt/decrypt KEK profile when wrap/unwrap cannot protect DEKs."""
    service = _service()
    session = _FakeSession()
    session.reject_wrap_kek_profile = True

    kek, dek, protected_dek = service._create_kek_with_protected_dek(session)  # noqa: SLF001

    assert dek == b'g' * 32
    assert protected_dek.startswith(PKCS11_ENCRYPTED_DEK_CBC_PAD_PREFIX)
    expected_kek_profile_attempts = 2
    assert len(session.generated_keks) == expected_kek_profile_attempts
    assert session.generated_keks[0].destroyed
    assert session.generated_keks[1] is kek


def test_pkcs11_app_secret_generate_protected_dek_falls_back_to_encrypt_when_wrap_is_unsupported() -> None:
    """Providers without AES key-wrap mechanisms can protect the DEK with PKCS#11 AES encryption."""
    service = _service()
    kek = _FakeKek()
    kek.fail_wrap = True

    dek, protected_dek = service._generate_protected_dek(session=kek.session, kek=kek)  # noqa: SLF001

    assert dek == b'g' * 32
    assert protected_dek.startswith(PKCS11_ENCRYPTED_DEK_CBC_PAD_PREFIX)
    assert len(kek.encrypt_calls) == 1
    plaintext, mechanism, mechanism_param = kek.encrypt_calls[0]
    assert plaintext == dek
    assert mechanism == pkcs11.Mechanism.AES_CBC_PAD
    assert isinstance(mechanism_param, bytes)


def test_pkcs11_app_secret_rejects_tokens_with_only_ecb_encryption() -> None:
    """Tokens without key-wrap or CBC encryption cannot protect the app-secret DEK."""
    service = _service()
    kek = _FakeKek()
    kek.fail_wrap = True
    kek.fail_cbc_encrypt = True

    with pytest.raises(AppSecretConfigurationError, match='standard PKCS#11 AES flows') as exc_info:
        service._generate_protected_dek(session=kek.session, kek=kek)  # noqa: SLF001

    assert 'AES_ECB' not in str(exc_info.value)
    assert all(mechanism is not pkcs11.Mechanism.AES_ECB for _, mechanism, _ in kek.encrypt_calls)


def test_pkcs11_app_secret_recover_dek_uses_key_unwrap_operation() -> None:
    """C_WrapKey DEK envelopes are recovered with C_UnwrapKey."""
    service = _service()
    kek = _FakeKek()

    protected_dek = PKCS11_CWRAP_DEK_PREFIX + b'wrapped:' + (b'b' * 32)

    dek = service._recover_dek(kek=kek, protected_dek=protected_dek)  # noqa: SLF001

    assert dek == b'b' * 32
    assert len(kek.unwrap_calls) == 1
    wrapped_dek, mechanism = kek.unwrap_calls[0]
    assert wrapped_dek == b'wrapped:' + (b'b' * 32)
    assert mechanism == pkcs11.Mechanism.AES_KEY_WRAP
    assert kek.unwrapped_keys[0].destroyed


def test_pkcs11_app_secret_decrypts_encrypted_dek_envelope() -> None:
    """Encrypted DEK envelopes are recovered with PKCS#11 C_Decrypt."""
    service = _service()
    kek = _FakeKek()
    iv = b'i' * 16

    dek = service._recover_dek(  # noqa: SLF001
        kek=kek,
        protected_dek=PKCS11_ENCRYPTED_DEK_CBC_PAD_PREFIX + iv + b'encrypted:' + (b'c' * 32),
    )

    assert dek == b'c' * 32
    assert len(kek.decrypt_calls) == 1
    ciphertext, mechanism, mechanism_param = kek.decrypt_calls[0]
    assert ciphertext == b'encrypted:' + (b'c' * 32)
    assert mechanism == pkcs11.Mechanism.AES_CBC_PAD
    assert mechanism_param == iv


def test_pkcs11_app_secret_rejects_ecb_encrypted_dek_envelope() -> None:
    """AES ECB DEK envelopes are not accepted for app-secret DEK recovery."""
    service = _service()
    kek = _FakeKek()

    with pytest.raises(AppSecretConfigurationError, match='supported protected-DEK envelope format'):
        service._recover_dek(  # noqa: SLF001
            kek=kek,
            protected_dek=b'tpsec:pkcs11:enc-ecb:v1:' + b'encrypted:' + (b'd' * 32),
        )

    assert not kek.decrypt_calls


def test_pkcs11_app_secret_protection_failure_reports_attempts() -> None:
    """Operator-facing protection errors include bounded standard-flow diagnostics."""
    service = _service()
    kek = _FakeKek()
    kek.session.fail_generation = True
    kek.fail_encrypt = True

    def fail_create_object(_attrs: dict[pkcs11.Attribute, object]) -> _FakeDekKey:
        raise pkcs11.PKCS11Error

    kek.session.create_object = fail_create_object  # type: ignore[method-assign]

    with pytest.raises(AppSecretConfigurationError, match='Attempts:') as exc_info:
        service._generate_protected_dek(session=kek.session, kek=kek)  # noqa: SLF001

    assert 'generate/private-readable-session' in str(exc_info.value)
    assert 'import/private-readable-session' in str(exc_info.value)
