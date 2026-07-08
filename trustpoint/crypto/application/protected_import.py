"""Operations for protected imported private keys."""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from appsecrets.service import decrypt_app_secret, encrypt_app_secret
from crypto.adapters.protected_import.bindings import (
    ProtectedImportManagedKeyBinding,
    ProtectedImportManagedKeyVerification,
)
from crypto.domain.algorithms import HashAlgorithmName, KeyAlgorithm, SignatureAlgorithm
from crypto.domain.errors import KeyNotFoundError, MechanismUnsupportedError, ProviderUnavailableError
from crypto.domain.refs import ManagedKeyVerificationStatus

if TYPE_CHECKING:
    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.specs import SignRequest

type SupportedImportedPrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def encrypt_imported_private_key(private_key: SupportedImportedPrivateKey) -> str:
    """Serialize and encrypt imported private-key material with app-secret encryption."""
    der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return encrypt_app_secret(base64.b64encode(der).decode('ascii'))


def imported_key_algorithm(private_key: SupportedImportedPrivateKey) -> KeyAlgorithm:
    """Return the supported key algorithm for an imported private key."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        return KeyAlgorithm.RSA
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return KeyAlgorithm.EC
    msg = f'Unsupported imported private-key type {type(private_key).__name__}.'
    raise ProviderUnavailableError(msg)


def public_key_fingerprint_sha256(public_key: SupportedPublicKey) -> str:
    """Return the SHA-256 fingerprint of a public key SPKI DER encoding."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


class ProtectedImportKeyOperations:
    """Local operations for imported private keys stored through app-secret encryption."""

    def verify_managed_key(self, key: ProtectedImportManagedKeyBinding) -> ProtectedImportManagedKeyVerification:
        """Verify that the encrypted imported key still decrypts and matches its fingerprint."""
        try:
            public_key = self.get_public_key(key)
        except KeyNotFoundError:
            return ProtectedImportManagedKeyVerification(
                status=ManagedKeyVerificationStatus.MISSING,
                resolved_public_key_fingerprint_sha256=None,
            )

        resolved_fingerprint = public_key_fingerprint_sha256(public_key)
        if (
            key.public_key_fingerprint_sha256 is not None
            and key.public_key_fingerprint_sha256 != resolved_fingerprint
        ):
            return ProtectedImportManagedKeyVerification(
                status=ManagedKeyVerificationStatus.MISMATCH,
                resolved_public_key_fingerprint_sha256=resolved_fingerprint,
            )

        return ProtectedImportManagedKeyVerification(
            status=ManagedKeyVerificationStatus.PRESENT,
            resolved_public_key_fingerprint_sha256=resolved_fingerprint,
        )

    def get_public_key(self, key: ProtectedImportManagedKeyBinding) -> SupportedPublicKey:
        """Load the public key for a protected imported key binding."""
        return self._load_private_key(key).public_key()

    def sign(self, *, key: ProtectedImportManagedKeyBinding, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes with a protected imported key."""
        private_key = self._load_private_key(key)
        hash_algorithm = self._hash_algorithm(request.hash_algorithm)

        if key.algorithm is KeyAlgorithm.RSA and isinstance(private_key, rsa.RSAPrivateKey):
            if request.signature_algorithm is not SignatureAlgorithm.RSA_PKCS1V15:
                msg = f'Unsupported RSA signature algorithm {request.signature_algorithm.value!r}.'
                raise MechanismUnsupportedError(msg)
            algorithm = utils.Prehashed(hash_algorithm) if request.prehashed else hash_algorithm
            return bytes(private_key.sign(data, padding.PKCS1v15(), algorithm))

        if key.algorithm is KeyAlgorithm.EC and isinstance(private_key, ec.EllipticCurvePrivateKey):
            if request.signature_algorithm is not SignatureAlgorithm.ECDSA:
                msg = f'Unsupported EC signature algorithm {request.signature_algorithm.value!r}.'
                raise MechanismUnsupportedError(msg)
            algorithm = utils.Prehashed(hash_algorithm) if request.prehashed else hash_algorithm
            return bytes(private_key.sign(data, ec.ECDSA(algorithm)))

        msg = 'Protected imported-key algorithm and private-key type are inconsistent.'
        raise ProviderUnavailableError(msg)

    def _load_private_key(self, key: ProtectedImportManagedKeyBinding) -> SupportedImportedPrivateKey:
        """Decrypt and load an imported private key."""
        try:
            private_key_der = base64.b64decode(
                decrypt_app_secret(key.encrypted_private_key_pkcs8_der_b64).encode('ascii')
            )
            private_key = serialization.load_der_private_key(private_key_der, password=None)
        except (TypeError, ValueError) as exc:
            msg = 'Failed to decrypt protected imported private key material.'
            raise KeyNotFoundError(msg) from exc

        if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            return private_key

        msg = f'Unsupported protected imported private-key type {type(private_key).__name__}.'
        raise ProviderUnavailableError(msg)

    @staticmethod
    def _hash_algorithm(hash_name: HashAlgorithmName) -> hashes.HashAlgorithm:
        """Resolve a domain hash enum value to a cryptography hash algorithm."""
        value = getattr(hash_name, 'value', hash_name)
        normalized = str(value).strip().lower()
        try:
            return HashAlgorithmName(normalized).to_cryptography_hash()
        except ValueError as exc:
            msg = f'Unsupported hash algorithm {value!r} for protected imported keys.'
            raise MechanismUnsupportedError(msg) from exc
