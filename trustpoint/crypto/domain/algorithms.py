"""Algorithm primitives for the redesigned crypto layer."""

from __future__ import annotations

from enum import StrEnum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

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

    def to_cryptography_hash(self) -> hashes.HashAlgorithm:
        """Build the matching cryptography hash object."""
        if self is HashAlgorithmName.SHA224:
            return hashes.SHA224()
        if self is HashAlgorithmName.SHA256:
            return hashes.SHA256()
        if self is HashAlgorithmName.SHA384:
            return hashes.SHA384()
        return hashes.SHA512()


class SignatureAlgorithm(StrEnum):
    """Signature algorithms exposed by the backend contract."""

    RSA_PKCS1V15 = 'rsa-pkcs1v15'
    ECDSA = 'ecdsa'
