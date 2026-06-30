"""Cryptography-compatible private-key wrappers for managed backend keys."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Never, cast, override

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from crypto.application.service import TrustpointCryptoBackend
from crypto.domain.algorithms import HashAlgorithmName, KeyAlgorithm, SignatureAlgorithm
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from crypto.domain.specs import SignRequest

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.hashes import HashAlgorithm
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        KeySerializationEncryption,
        PrivateFormat,
    )

    from crypto.domain.refs import ManagedKeyRef
    from crypto.domain.specs import KeySpec


def _hash_algorithm_name(algorithm: HashAlgorithm | utils.Prehashed | utils.NoDigestInfo) -> HashAlgorithmName:
    """Map cryptography hash algorithm objects to the backend contract."""
    hash_algorithm = cast('HashAlgorithm', getattr(algorithm, '_algorithm', algorithm))
    name = hash_algorithm.name.lower()
    try:
        return HashAlgorithmName(name)
    except ValueError as exc:
        msg = f'Unsupported managed-key hash algorithm {name!r}.'
        raise ValueError(msg) from exc


class ManagedRSAPrivateKey(rsa.RSAPrivateKey):
    """RSA private-key facade backed by Trustpoint's managed crypto backend."""

    def __init__(
        self,
        *,
        key_ref: ManagedKeyRef,
        crypto_backend: TrustpointCryptoBackend | None = None,
    ) -> None:
        """Initialize the managed RSA key facade."""
        if key_ref.algorithm is not KeyAlgorithm.RSA:
            msg = f'Managed key {key_ref.alias!r} is not an RSA key.'
            raise TypeError(msg)
        self._key_ref = key_ref
        self._crypto_backend = crypto_backend or TrustpointCryptoBackend()
        self._public_key: rsa.RSAPublicKey | None = None

    def sign(
        self,
        data: bytes | bytearray | memoryview,
        padding_algorithm: padding.AsymmetricPadding,
        algorithm: HashAlgorithm | utils.Prehashed | utils.NoDigestInfo,
    ) -> bytes:
        """Sign data through the configured backend."""
        if not isinstance(padding_algorithm, padding.PKCS1v15):
            msg = 'Managed RSA keys currently support PKCS#1 v1.5 signing only.'
            raise NotImplementedError(msg)
        return self._crypto_backend.sign(
            key=self._key_ref,
            data=bytes(data),
            request=SignRequest(
                signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15,
                hash_algorithm=_hash_algorithm_name(algorithm),
                prehashed=isinstance(algorithm, utils.Prehashed),
            ),
        )

    @property
    def managed_key_ref(self) -> ManagedKeyRef:
        """Return the stable application-facing managed key reference."""
        return self._key_ref

    def public_key(self) -> rsa.RSAPublicKey:
        """Return the managed key public key."""
        if self._public_key is None:
            public_key = self._crypto_backend.get_public_key(self._key_ref)
            if not isinstance(public_key, rsa.RSAPublicKey):
                msg = f'Managed key {self._key_ref.alias!r} resolved to a non-RSA public key.'
                raise TypeError(msg)
            self._public_key = public_key
        return self._public_key

    @property
    def key_size(self) -> int:
        """Return the RSA modulus size."""
        return self.public_key().key_size

    def decrypt(self, ciphertext: bytes, padding_algorithm: padding.AsymmetricPadding) -> bytes:
        """Decrypt is intentionally unavailable for managed signing keys."""
        msg = 'Managed Trustpoint RSA keys do not expose decrypt operations.'
        raise NotImplementedError(msg)

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        """Private key material is intentionally non-exportable."""
        msg = 'Managed Trustpoint private key numbers are not accessible.'
        raise NotImplementedError(msg)

    @override
    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes:
        """Private key material is intentionally non-exportable."""
        msg = 'Managed Trustpoint private keys cannot be exported.'
        raise NotImplementedError(msg)

    def __copy__(self) -> ManagedRSAPrivateKey:
        """Return this immutable facade when copied by cryptography callers."""
        return self

    def __deepcopy__(self, memo: dict[Any, Any]) -> ManagedRSAPrivateKey:
        """Return this immutable facade when deep-copied by cryptography callers."""
        return self


class ManagedECPrivateKey(ec.EllipticCurvePrivateKey):
    """EC private-key facade backed by Trustpoint's managed crypto backend."""

    def __init__(
        self,
        *,
        key_ref: ManagedKeyRef,
        crypto_backend: TrustpointCryptoBackend | None = None,
    ) -> None:
        """Initialize the managed EC key facade."""
        if key_ref.algorithm is not KeyAlgorithm.EC:
            msg = f'Managed key {key_ref.alias!r} is not an EC key.'
            raise TypeError(msg)
        self._key_ref = key_ref
        self._crypto_backend = crypto_backend or TrustpointCryptoBackend()
        self._public_key: ec.EllipticCurvePublicKey | None = None

    def sign(
        self,
        data: bytes | bytearray | memoryview,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        """Sign data through the configured backend."""
        if not isinstance(signature_algorithm, ec.ECDSA):
            msg = 'Managed EC keys currently support ECDSA signing only.'
            raise NotImplementedError(msg)
        algorithm = signature_algorithm.algorithm
        return self._crypto_backend.sign(
            key=self._key_ref,
            data=bytes(data),
            request=SignRequest(
                signature_algorithm=SignatureAlgorithm.ECDSA,
                hash_algorithm=_hash_algorithm_name(algorithm),
                prehashed=isinstance(algorithm, utils.Prehashed),
            ),
        )

    @property
    def managed_key_ref(self) -> ManagedKeyRef:
        """Return the stable application-facing managed key reference."""
        return self._key_ref

    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Return the managed key public key."""
        if self._public_key is None:
            public_key = self._crypto_backend.get_public_key(self._key_ref)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                msg = f'Managed key {self._key_ref.alias!r} resolved to a non-EC public key.'
                raise TypeError(msg)
            self._public_key = public_key
        return self._public_key

    @property
    def curve(self) -> ec.EllipticCurve:
        """Return the public key curve."""
        return self.public_key().curve

    @property
    def key_size(self) -> int:
        """Return the EC key size."""
        return self.public_key().key_size

    def exchange(self, algorithm: Any, peer_public_key: Any) -> Never:
        """Key exchange is intentionally unavailable for managed signing keys."""
        msg = 'Managed Trustpoint EC keys do not expose key exchange operations.'
        raise NotImplementedError(msg)

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        """Private key material is intentionally non-exportable."""
        msg = 'Managed Trustpoint private key numbers are not accessible.'
        raise NotImplementedError(msg)

    @override
    def private_bytes(
        self,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: KeySerializationEncryption,
    ) -> bytes:
        """Private key material is intentionally non-exportable."""
        msg = 'Managed Trustpoint private keys cannot be exported.'
        raise NotImplementedError(msg)

    def __copy__(self) -> ManagedECPrivateKey:
        """Return this immutable facade when copied by cryptography callers."""
        return self

    def __deepcopy__(self, memo: dict[Any, Any]) -> ManagedECPrivateKey:
        """Return this immutable facade when deep-copied by cryptography callers."""
        return self


def managed_private_key_for_ref(key_ref: ManagedKeyRef) -> ManagedRSAPrivateKey | ManagedECPrivateKey:
    """Build a cryptography-compatible managed private-key facade."""
    if key_ref.algorithm is KeyAlgorithm.RSA:
        return ManagedRSAPrivateKey(key_ref=key_ref)
    if key_ref.algorithm is KeyAlgorithm.EC:
        return ManagedECPrivateKey(key_ref=key_ref)
    msg = f'Unsupported managed key algorithm {key_ref.algorithm!r}.'
    raise TypeError(msg)


def generate_managed_signing_private_key(
    *,
    alias: str,
    key_spec: KeySpec,
    crypto_backend: TrustpointCryptoBackend | None = None,
) -> ManagedRSAPrivateKey | ManagedECPrivateKey:
    """Generate a non-exportable signing key through the active crypto backend."""
    backend = crypto_backend or TrustpointCryptoBackend()
    key_ref = backend.generate_managed_key(
        alias=alias,
        key_spec=key_spec,
        policy=KeyPolicy.managed_signing_key(
            signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
        ),
    )
    return managed_private_key_for_ref(key_ref)
