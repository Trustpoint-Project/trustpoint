"""Algorithm primitives for the redesigned crypto layer."""

from __future__ import annotations

from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

type SupportedPublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


class KeyAlgorithm(str, Enum):
    """Top-level key algorithm families supported by the backend."""

    RSA = 'rsa'
    EC = 'ec'


class EllipticCurveName(str, Enum):
    """Named elliptic curves currently supported by the backend."""

    SECP256R1 = 'secp256r1'
    SECP384R1 = 'secp384r1'
    SECP521R1 = 'secp521r1'

    def to_cryptography_curve(self) -> ec.EllipticCurve:
        """Build the matching cryptography curve instance."""
        curve_map = {
            EllipticCurveName.SECP256R1: ec.SECP256R1,
            EllipticCurveName.SECP384R1: ec.SECP384R1,
            EllipticCurveName.SECP521R1: ec.SECP521R1,
        }
        return curve_map[self]()


class HashAlgorithmName(str, Enum):
    """Hash algorithms exposed through the backend contract."""

    SHA224 = 'sha224'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'

    def to_cryptography_hash(self) -> hashes.HashAlgorithm:
        """Build the matching cryptography hash object."""
        hash_map = {
            HashAlgorithmName.SHA224: hashes.SHA224,
            HashAlgorithmName.SHA256: hashes.SHA256,
            HashAlgorithmName.SHA384: hashes.SHA384,
            HashAlgorithmName.SHA512: hashes.SHA512,
        }
        return hash_map[self]()


class SignatureAlgorithm(str, Enum):
    """Signature algorithms exposed by the backend contract."""

    RSA_PKCS1V15 = 'rsa-pkcs1v15'
    ECDSA = 'ecdsa'
