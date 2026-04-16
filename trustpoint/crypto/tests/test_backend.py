"""Tests for the contained PKCS#11 backend."""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from pkcs11 import Attribute, Mechanism, NoSuchKey, ObjectClass

from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector
from crypto.domain.algorithms import EllipticCurveName, KeyAlgorithm
from crypto.domain.policies import KeyPolicy
from crypto.domain.refs import ManagedKeyRef
from crypto.domain.specs import EcKeySpec, RsaKeySpec, SignRequest


class FakePkcs11Object:
    """Base fake for PKCS#11 objects exposing attribute access."""

    def __init__(self, attributes: dict[Attribute, bytes | str] | None = None) -> None:
        """Store PKCS#11-style attributes."""
        self._attributes = attributes or {}

    def __getitem__(self, item: Attribute) -> bytes | str:
        """Provide PKCS#11 attribute access."""
        return self._attributes[item]


class FakePrivateKey(FakePkcs11Object):
    """Minimal PKCS#11 private key fake."""

    def __init__(
        self,
        signature: bytes = b'signature',
        *,
        attributes: dict[Attribute, bytes | str] | None = None,
    ) -> None:
        """Initialize signature bookkeeping."""
        super().__init__(attributes=attributes)
        self.signature = signature
        self.calls: list[tuple[bytes, Mechanism]] = []

    def sign(self, payload: bytes, *, mechanism: Mechanism) -> bytes:
        """Record the sign call and return the configured signature."""
        self.calls.append((payload, mechanism))
        return self.signature


class FakePublicKey(FakePkcs11Object):
    """Minimal PKCS#11 public key fake for DER encoding helpers."""


@dataclass
class FakeDomainParameters:
    """Domain-parameter fake for EC key generation."""

    generate_keypair_calls: list[dict[str, object]] = field(default_factory=list)

    def generate_keypair(self, **kwargs: object) -> tuple[object, object]:
        """Record a key generation request."""
        self.generate_keypair_calls.append(kwargs)
        return object(), object()


@dataclass(frozen=True)
class FakeMechanismInfo:
    """Minimal mechanism-info fake for capability probing."""

    min_key_length: int = 0
    max_key_length: int = 0
    flags: frozenset[str] = frozenset()


class FakeSession:
    """Minimal PKCS#11 session fake."""

    def __init__(
        self,
        *,
        private_key: FakePrivateKey | None = None,
        public_key: FakePublicKey | None = None,
        duplicate_aliases: set[str] | None = None,
    ) -> None:
        """Initialize the fake session state."""
        self.private_key = private_key or FakePrivateKey()
        self.public_key = public_key
        self.duplicate_aliases = duplicate_aliases or set()
        self.generate_keypair_calls: list[tuple[object, object, dict[str, object]]] = []
        self.domain_parameter_calls: list[tuple[object, dict[Attribute, bytes], bool]] = []
        self.domain_parameters = FakeDomainParameters()

    def get_objects(self, attrs: dict[Attribute, object]) -> list[object]:
        """Return matching fake objects for alias-uniqueness checks."""
        object_class = attrs.get(Attribute.CLASS)
        label = attrs.get(Attribute.LABEL)

        if object_class == ObjectClass.PRIVATE_KEY and isinstance(label, str) and label in self.duplicate_aliases:
            return [self.private_key]
        return []

    def get_key(
        self,
        *,
        object_class: ObjectClass | None = None,
        key_type: object | None = None,
        label: str | None = None,
        id: bytes | None = None,
    ) -> object:
        """Resolve fake keys by id or alias."""
        candidate: object | None = None
        if object_class == ObjectClass.PRIVATE_KEY:
            candidate = self.private_key
        elif object_class == ObjectClass.PUBLIC_KEY and self.public_key is not None:
            candidate = self.public_key

        if candidate is None:
            raise NoSuchKey(f'Key not found for label={label!r} id={id!r} type={key_type!r}')

        actual_id = None
        actual_label = None
        try:
            actual_id = candidate[Attribute.ID]
        except Exception:
            actual_id = None
        try:
            actual_label = candidate[Attribute.LABEL]
        except Exception:
            actual_label = None

        if id is not None:
            if actual_id is not None and bytes(actual_id) == bytes(id):
                return candidate
            raise NoSuchKey(f'Key not found for label={label!r} id={id!r} type={key_type!r}')

        if label is not None:
            if actual_label == label:
                return candidate
            if label in self.duplicate_aliases and object_class == ObjectClass.PRIVATE_KEY:
                return candidate
            raise NoSuchKey(f'Key not found for label={label!r} id={id!r} type={key_type!r}')

        raise NoSuchKey(f'Key not found for label={label!r} id={id!r} type={key_type!r}')

    def generate_keypair(self, key_type: object, key_length: object, **kwargs: object) -> tuple[object, object]:
        """Record RSA key generation."""
        self.generate_keypair_calls.append((key_type, key_length, kwargs))
        return object(), object()

    def create_domain_parameters(
        self,
        key_type: object,
        attrs: dict[Attribute, bytes],
        *,
        local: bool = False,
    ) -> FakeDomainParameters:
        """Record EC parameter creation and return fake parameters."""
        self.domain_parameter_calls.append((key_type, attrs, local))
        return self.domain_parameters

    def close(self) -> None:
        """Satisfy the session-pool interface."""


class FakeToken:
    """Minimal token fake that yields a single session."""

    def __init__(self, session: FakeSession) -> None:
        """Initialize the token fake."""
        self.label = 'Trustpoint-SoftHSM'
        self.serial = 'soft-serial'
        self.model = 'SoftHSM v2'
        self.manufacturer = 'SoftHSM project'
        self.manufacturer_id = 'SoftHSM project'
        self.hardware_version = (2, 6)
        self.firmware_version = (2, 6)
        self._session = session
        self.open_calls = 0

    def open(self, *, user_pin: str, rw: bool) -> FakeSession:
        """Return the configured fake session."""
        assert user_pin == '1234'
        assert rw is True
        self.open_calls += 1
        return self._session


class FakeSlot:
    """Minimal slot fake for backend tests."""

    def __init__(self, token: FakeToken) -> None:
        """Initialize the slot fake."""
        self.slot_id = 5
        self._token = token

    def get_token(self) -> FakeToken:
        """Return the configured token."""
        return self._token

    def get_mechanisms(self) -> set[Mechanism]:
        """Return mechanisms supported by the fake token."""
        return {
            Mechanism.RSA_PKCS_KEY_PAIR_GEN,
            Mechanism.SHA256_RSA_PKCS,
            Mechanism.ECDSA_SHA256,
            Mechanism.EC_KEY_PAIR_GEN,
        }

    def get_mechanism_info(self, mechanism: Mechanism) -> FakeMechanismInfo:
        """Return minimal mechanism info for the requested mechanism."""
        if mechanism not in self.get_mechanisms():
            raise KeyError(mechanism)
        return FakeMechanismInfo()


class FakeLibrary:
    """Library fake that exposes a single slot."""

    def __init__(self, slot: FakeSlot) -> None:
        """Initialize the library fake."""
        self._slot = slot

    def get_slots(self, *, token_present: bool = False) -> list[FakeSlot]:
        """Return the configured slot."""
        assert token_present is True
        return [self._slot]


def _build_backend(session: FakeSession) -> Pkcs11Backend:
    """Build a backend instance wired to fakes."""
    profile = Pkcs11ProviderProfile(
        name='demo',
        module_path='/usr/lib/libpkcs11-proxy.so',
        token=Pkcs11TokenSelector(token_label='Trustpoint-SoftHSM'),
        user_pin='1234',
    )
    token = FakeToken(session)
    slot = FakeSlot(token)
    return Pkcs11Backend(profile=profile, library_loader=lambda _path: FakeLibrary(slot))


def test_generate_managed_rsa_key_uses_pkcs11_keygen() -> None:
    """The backend should drive RSA key generation through the adapter core."""
    session = FakeSession()
    backend = _build_backend(session)

    key_ref = backend.generate_managed_key(
        alias='ca/root',
        key_spec=RsaKeySpec(key_size=2048),
        policy=KeyPolicy.managed_signing_key(),
    )

    assert key_ref.alias == 'ca/root'
    assert key_ref.algorithm is KeyAlgorithm.RSA
    assert session.generate_keypair_calls


def test_generate_managed_ec_key_uses_domain_parameters() -> None:
    """EC generation should go through explicit EC domain parameters."""
    session = FakeSession()
    backend = _build_backend(session)

    backend.generate_managed_key(
        alias='ca/ec-root',
        key_spec=EcKeySpec(curve=EllipticCurveName.SECP256R1),
        policy=KeyPolicy.managed_signing_key(),
    )

    assert session.domain_parameter_calls
    assert session.domain_parameters.generate_keypair_calls


def test_get_public_key_loads_rsa_public_key() -> None:
    """The backend should decode an RSA public key object into a cryptography key."""
    key_id = b'key-id'
    label = 'ca/root'

    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = rsa_private_key.public_key().public_numbers()
    session = FakeSession(
        public_key=FakePublicKey(
            {
                Attribute.ID: key_id,
                Attribute.LABEL: label,
                Attribute.MODULUS: public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big'),
                Attribute.PUBLIC_EXPONENT: public_numbers.e.to_bytes(
                    (public_numbers.e.bit_length() + 7) // 8,
                    'big',
                ),
            },
        ),
    )
    backend = _build_backend(session)
    key_ref = ManagedKeyRef(
        alias=label,
        provider='pkcs11',
        key_id=key_id,
        label=label,
        algorithm=KeyAlgorithm.RSA,
    )

    public_key = backend.get_public_key(key_ref)

    assert isinstance(public_key, rsa.RSAPublicKey)
    assert public_key.key_size == 2048


def test_sign_encodes_ecdsa_signature_as_der() -> None:
    """ECDSA signatures returned by PKCS#11 should be normalized to DER."""
    key_id = b'ec-key'
    label = 'signer/ec'
    raw_signature = (123).to_bytes(32, 'big') + (456).to_bytes(32, 'big')
    session = FakeSession(
        private_key=FakePrivateKey(
            signature=raw_signature,
            attributes={
                Attribute.ID: key_id,
                Attribute.LABEL: label,
            },
        )
    )
    backend = _build_backend(session)
    key_ref = ManagedKeyRef(
        alias=label,
        provider='pkcs11',
        key_id=key_id,
        label=label,
        algorithm=KeyAlgorithm.EC,
    )

    signature = backend.sign(key=key_ref, data=b'payload', request=SignRequest.ecdsa_sha256())

    assert utils.decode_dss_signature(signature) == (123, 456)


def test_sign_uses_rsa_hashing_mechanism() -> None:
    """RSA signing should resolve the correct hash-specific PKCS#11 mechanism."""
    key_id = b'rsa-key'
    label = 'signer/rsa'
    private_key = FakePrivateKey(
        signature=b'rsa-signature',
        attributes={
            Attribute.ID: key_id,
            Attribute.LABEL: label,
        },
    )
    session = FakeSession(private_key=private_key)
    backend = _build_backend(session)
    key_ref = ManagedKeyRef(
        alias=label,
        provider='pkcs11',
        key_id=key_id,
        label=label,
        algorithm=KeyAlgorithm.RSA,
    )

    signature = backend.sign(key=key_ref, data=b'payload', request=SignRequest.rsa_pkcs1v15_sha256())

    assert signature == b'rsa-signature'
    assert private_key.calls == [(b'payload', Mechanism.SHA256_RSA_PKCS)]
