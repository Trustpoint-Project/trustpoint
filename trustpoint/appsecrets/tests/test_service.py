# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for application-secret service internals."""

from __future__ import annotations

import base64
from types import SimpleNamespace
from typing import Any

import pkcs11
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from appsecrets.service import (
    CIPHERTEXT_PREFIX,
    DEK_LENGTH_BYTES,
    PKCS11_CWRAP_DEK_PREFIX,
    PKCS11_RSA_OAEP_PARAMS,
    PKCS11_RSA_OAEP_SHA256_DEK_PREFIX,
    RSA_KEK_PREFERRED_BITS,
    AppSecretConfigurationError,
    Pkcs11AppSecretService,
    SoftwareAppSecretService,
)

pytestmark = pytest.mark.django_db


def test_app_secret_rejects_malformed_base64() -> None:
    """Malformed ciphertext encoding is reported as a stable configuration error."""
    service = SoftwareAppSecretService(SimpleNamespace(backend_id=1, raw_dek=b'k' * DEK_LENGTH_BYTES))

    with pytest.raises(AppSecretConfigurationError, match='not valid Base64'):
        service.decrypt_text(CIPHERTEXT_PREFIX + '%%%')


def test_app_secret_rejects_tampered_ciphertext() -> None:
    """Authenticated encryption rejects modified ciphertext."""
    service = SoftwareAppSecretService(SimpleNamespace(backend_id=1, raw_dek=b'k' * DEK_LENGTH_BYTES))
    encrypted = service.encrypt_text('secret')
    payload = bytearray(base64.b64decode(encrypted[len(CIPHERTEXT_PREFIX) :]))
    payload[-1] ^= 1
    tampered = CIPHERTEXT_PREFIX + base64.b64encode(payload).decode('ascii')

    with pytest.raises(AppSecretConfigurationError, match='authentication failed'):
        service.decrypt_text(tampered)


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
        self.generated_rsa_pairs: list[tuple[_FakeRsaPublicKek, _FakeRsaPrivateKek]] = []
        self.token = SimpleNamespace(
            slot=SimpleNamespace(
                get_mechanism_info=lambda _mechanism: SimpleNamespace(
                    min_key_length=1024,
                    max_key_length=4096,
                )
            )
        )

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

    def generate_keypair(
        self,
        key_type: pkcs11.KeyType,
        key_length: int,
        **kwargs: Any,
    ) -> tuple[_FakeRsaPublicKek, _FakeRsaPrivateKek]:
        key_id = kwargs['id']
        label = kwargs['label']
        public_template = kwargs['public_template']
        private_template = kwargs['private_template']
        assert isinstance(key_id, bytes)
        assert isinstance(label, str)
        assert isinstance(public_template, dict)
        assert isinstance(private_template, dict)
        assert key_type is pkcs11.KeyType.RSA
        assert key_length == RSA_KEK_PREFERRED_BITS
        assert kwargs['store'] is True
        assert kwargs['capabilities'] == pkcs11.MechanismFlag.DECRYPT
        assert kwargs['mechanism'] is pkcs11.Mechanism.RSA_PKCS_KEY_PAIR_GEN
        assert public_template[pkcs11.Attribute.PRIVATE] is False
        assert private_template[pkcs11.Attribute.SENSITIVE] is True
        assert private_template[pkcs11.Attribute.EXTRACTABLE] is False
        assert private_template[pkcs11.Attribute.DECRYPT] is True

        software_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_kek = _FakeRsaPublicKek(
            private_key=software_private_key,
            key_id=key_id,
            label=label,
        )
        private_kek = _FakeRsaPrivateKek(
            private_key=software_private_key,
            key_id=key_id,
            label=label,
        )
        self.generated_rsa_pairs.append((public_kek, private_kek))
        return public_kek, private_kek

    def get_key(
        self,
        object_class: pkcs11.ObjectClass | None = None,
        key_type: pkcs11.KeyType | None = None,
        label: str | None = None,
        **kwargs: Any,
    ) -> _FakeRsaPublicKek | _FakeRsaPrivateKek:
        key_id = kwargs.get('id')
        if key_type is not pkcs11.KeyType.RSA:
            raise pkcs11.NoSuchKey
        for public_kek, private_kek in reversed(self.generated_rsa_pairs):
            key = public_kek if object_class is pkcs11.ObjectClass.PUBLIC_KEY else private_kek
            if key.destroyed:
                continue
            if label is not None and key.label != label:
                continue
            if key_id is not None and key.key_id != key_id:
                continue
            return key
        raise pkcs11.NoSuchKey


class _FakeRsaPublicKek:
    """RSA public-key object backed by a cryptography test key."""

    def __init__(self, *, private_key: rsa.RSAPrivateKey, key_id: bytes, label: str) -> None:
        self._public_numbers = private_key.public_key().public_numbers()
        self.key_id = key_id
        self.label = label
        self.destroyed = False

    def __getitem__(self, attribute: pkcs11.Attribute) -> object:
        if attribute is pkcs11.Attribute.MODULUS:
            return self._public_numbers.n
        if attribute is pkcs11.Attribute.PUBLIC_EXPONENT:
            return self._public_numbers.e
        if attribute is pkcs11.Attribute.ID:
            return self.key_id
        raise KeyError(attribute)

    def destroy(self) -> None:
        self.destroyed = True


class _FakeRsaPrivateKek:
    """RSA private-key object that records OAEP parameters used by the service."""

    def __init__(self, *, private_key: rsa.RSAPrivateKey, key_id: bytes, label: str) -> None:
        self._private_key = private_key
        self.key_id = key_id
        self.label = label
        self.destroyed = False
        self.decrypt_calls: list[tuple[pkcs11.Mechanism, object]] = []

    def __getitem__(self, attribute: pkcs11.Attribute) -> object:
        attributes = {
            pkcs11.Attribute.ID: self.key_id,
            pkcs11.Attribute.EXTRACTABLE: False,
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.PRIVATE: True,
            pkcs11.Attribute.DECRYPT: True,
        }
        return attributes[attribute]

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        mechanism: pkcs11.Mechanism,
        mechanism_param: object,
    ) -> bytes:
        self.decrypt_calls.append((mechanism, mechanism_param))
        return self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def destroy(self) -> None:
        self.destroyed = True


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


def test_pkcs11_app_secret_aes_protection_self_test_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    """The PKCS#11 self-test prefers non-persistent AES KEK protection when supported."""
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

    service.verify_dek_protection_support()

    assert len(session.generated_keys) == 1
    assert session.generated_keys[0].destroyed


def test_pkcs11_app_secret_self_test_falls_back_to_disposable_rsa(monkeypatch: pytest.MonkeyPatch) -> None:
    """Signing-focused tokens can pass the app-secret self-test through RSA-OAEP."""
    service = _service()
    session = _FakeSession()
    session.fail_generation = True

    class _SessionContext:
        def __enter__(self) -> _FakeSession:
            return session

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(service, '_open_session', _SessionContext)

    service.verify_dek_protection_support()

    assert len(session.generated_rsa_pairs) == 1
    public_kek, private_kek = session.generated_rsa_pairs[0]
    assert public_kek.destroyed
    assert private_kek.destroyed
    assert private_kek.decrypt_calls == [(pkcs11.Mechanism.RSA_PKCS_OAEP, PKCS11_RSA_OAEP_PARAMS)]


def test_pkcs11_app_secret_rsa_oaep_round_trip_uses_versioned_envelope() -> None:
    """RSA fallback protects the DEK in software and recovers it only through the private HSM key."""
    service = _service()
    session = _FakeSession()
    public_kek, private_kek = service._generate_rsa_kek_pair(  # noqa: SLF001
        session=session,
        label='trustpoint-test-kek',
    )

    dek, protected_dek = service._generate_rsa_protected_dek(public_kek)  # noqa: SLF001
    recovered_dek = service._recover_rsa_protected_dek(  # noqa: SLF001
        private_kek=private_kek,
        protected_dek=protected_dek,
    )

    assert protected_dek.startswith(PKCS11_RSA_OAEP_SHA256_DEK_PREFIX)
    assert recovered_dek == dek
    assert private_kek.decrypt_calls == [(pkcs11.Mechanism.RSA_PKCS_OAEP, PKCS11_RSA_OAEP_PARAMS)]


def test_pkcs11_app_secret_recovers_rsa_envelope_without_public_key() -> None:
    """Restore-time DEK recovery needs only the persistent private RSA KEK."""
    service = _service()
    session = _FakeSession()
    public_kek, private_kek = service._generate_rsa_kek_pair(  # noqa: SLF001
        session=session,
        label='trustpoint-test-kek',
    )
    dek, protected_dek = service._generate_rsa_protected_dek(public_kek)  # noqa: SLF001
    public_kek.destroy()

    recovered_dek = service._recover_configured_dek(  # noqa: SLF001
        session=session,
        protected_dek=protected_dek,
    )

    assert recovered_dek == dek
    assert not private_kek.destroyed


def test_pkcs11_app_secret_kek_creation_requires_key_wrap_profile() -> None:
    """AES KEK creation fails when the token rejects authenticated key wrapping."""
    service = _service()
    session = _FakeSession()
    session.reject_wrap_kek_profile = True

    with pytest.raises(AppSecretConfigurationError, match='persistent KEK'):
        service._create_kek_with_protected_dek(session)  # noqa: SLF001

    assert len(session.generated_keks) == 1
    assert session.generated_keks[0].destroyed


def test_pkcs11_app_secret_rejects_aes_without_key_wrap() -> None:
    """Confidentiality-only AES encryption is not accepted for DEK protection."""
    service = _service()
    kek = _FakeKek()
    kek.fail_wrap = True

    with pytest.raises(AppSecretConfigurationError, match='AES key-wrap flows'):
        service._generate_protected_dek(session=kek.session, kek=kek)  # noqa: SLF001

    assert not kek.encrypt_calls


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


def test_pkcs11_app_secret_rejects_cbc_encrypted_dek_envelope() -> None:
    """Unauthenticated legacy CBC envelopes are not accepted."""
    service = _service()
    kek = _FakeKek()

    with pytest.raises(AppSecretConfigurationError, match='supported protected-DEK envelope format'):
        service._recover_dek(  # noqa: SLF001
            kek=kek,
            protected_dek=b'tpsec:pkcs11:enc-cbc-pad:v1:' + b'encrypted:' + (b'c' * 32),
        )

    assert not kek.decrypt_calls


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
