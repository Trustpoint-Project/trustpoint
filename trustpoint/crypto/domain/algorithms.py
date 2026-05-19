"""Algorithm primitives for the redesigned crypto layer."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

if TYPE_CHECKING:
    from collections.abc import Callable

type SupportedPublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


class KeyAlgorithm(StrEnum):
    """Top-level key algorithm families supported by the backend."""

    RSA = 'rsa'
    EC = 'ec'


class EllipticCurveName(StrEnum):
    """Named elliptic curves currently supported by the backend."""

    SECP256R1 = 'secp256r1'
    SECP384R1 = 'secp384r1'
    SECP521R1 = 'secp521r1'

    def to_cryptography_curve(self) -> ec.EllipticCurve:
        """Build the matching cryptography curve instance."""
        if self is EllipticCurveName.SECP256R1:
            return ec.SECP256R1()
        if self is EllipticCurveName.SECP384R1:
            return ec.SECP384R1()
        return ec.SECP521R1()


class HashAlgorithmName(StrEnum):
    """Hash algorithms exposed through the backend contract."""

    SHA224 = 'sha224'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    SHA3_224 = 'sha3-224'
    SHA3_256 = 'sha3-256'
    SHA3_384 = 'sha3-384'
    SHA3_512 = 'sha3-512'

    def to_cryptography_hash(self) -> hashes.HashAlgorithm:
        """Build the matching cryptography hash object."""
        return _CRYPTOGRAPHY_HASHES[self]()


class SignatureAlgorithm(StrEnum):
    """Signature algorithms exposed by the backend contract."""

    RSA_PKCS1V15 = 'rsa-pkcs1v15'
    ECDSA = 'ecdsa'


_CRYPTOGRAPHY_HASHES: dict[HashAlgorithmName, Callable[[], hashes.HashAlgorithm]] = {
    HashAlgorithmName.SHA224: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA224),
    HashAlgorithmName.SHA256: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA256),
    HashAlgorithmName.SHA384: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA384),
    HashAlgorithmName.SHA512: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA512),
    HashAlgorithmName.SHA3_224: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA3_224),
    HashAlgorithmName.SHA3_256: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA3_256),
    HashAlgorithmName.SHA3_384: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA3_384),
    HashAlgorithmName.SHA3_512: cast('Callable[[], hashes.HashAlgorithm]', hashes.SHA3_512),
}
