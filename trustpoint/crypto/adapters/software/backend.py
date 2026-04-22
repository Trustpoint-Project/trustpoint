"""Durable software-managed crypto backend."""

from __future__ import annotations

import hashlib
import secrets
from typing import TYPE_CHECKING, Any, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from crypto.adapters.software.bindings import SoftwareManagedKeyBinding, SoftwareManagedKeyVerification
from crypto.adapters.software.capabilities import SoftwareCapabilities
from crypto.domain.algorithms import KeyAlgorithm, SignatureAlgorithm
from crypto.domain.errors import (
    KeyNotFoundError,
    MechanismUnsupportedError,
    ProviderUnavailableError,
    UnsupportedKeySpecError,
)
from crypto.domain.policies import SigningExecutionMode
from crypto.domain.refs import ManagedKeyVerificationStatus
from crypto.domain.specs import EcKeySpec, KeySpec, RsaKeySpec, algorithm_for_key_spec

if TYPE_CHECKING:

    from crypto.adapters.software.config import SoftwareProviderProfile
    from crypto.domain.algorithms import HashAlgorithmName, SupportedPublicKey
    from crypto.domain.policies import KeyPolicy
    from crypto.domain.specs import SignRequest

SupportedPrivateKey = 'RSAPrivateKey | EllipticCurvePrivateKey'


class SoftwareBackend:
    """Software-backed provider adapter for durable managed key operations."""

    provider_name = 'software'

    def __init__(self, *, profile: SoftwareProviderProfile) -> None:
        """Initialize the software backend."""
        self._profile = profile
        self._capabilities: SoftwareCapabilities | None = None

    def verify_provider(self) -> None:
        """Validate that Trustpoint can access the software backend secret material."""
        self.probe_capabilities()

    def refresh_capabilities(self) -> SoftwareCapabilities:
        """Refresh the cached capability snapshot."""
        self._capabilities = None
        return self.probe_capabilities()

    def current_capabilities(self) -> SoftwareCapabilities | None:
        """Return the current cached capability snapshot."""
        return self._capabilities

    def close(self) -> None:
        """Release any runtime state held by the software backend."""
        self._capabilities = None

    def probe_capabilities(self) -> SoftwareCapabilities:
        """Resolve secret material and return the software backend capabilities."""
        self._profile.require_encryption_material()
        if self._capabilities is None:
            self._capabilities = SoftwareCapabilities(
                supported_key_algorithms=('rsa', 'ec'),
                supported_signature_algorithms=('rsa_pkcs1v15', 'ecdsa'),
                supported_signing_execution_modes=(
                    SigningExecutionMode.COMPLETE_BACKEND.value,
                    SigningExecutionMode.ALLOW_APPLICATION_HASH.value,
                ),
            )
        return self._capabilities

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> SoftwareManagedKeyBinding:
        """Generate a durable software-managed key and return its binding."""
        private_key = self._generate_private_key(key_spec)
        public_key = private_key.public_key()
        der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                self._profile.require_encryption_material(),
            ),
        )

        return SoftwareManagedKeyBinding(
            key_handle=secrets.token_hex(16),
            algorithm=algorithm_for_key_spec(key_spec),
            encrypted_private_key_pkcs8_der=der,
            encryption_metadata={'format': 'pkcs8-der', 'encryption': 'best_available'},
            public_key_fingerprint_sha256=self._fingerprint_public_key(public_key),
            signing_execution_mode=policy.signing_execution_mode,
            provider_label=alias,
        )

    def verify_managed_key(self, key: SoftwareManagedKeyBinding) -> SoftwareManagedKeyVerification:
        """Verify that a software-managed binding still decrypts to the expected key."""
        try:
            public_key = self.get_public_key(key)
        except KeyNotFoundError:
            return SoftwareManagedKeyVerification(
                status=ManagedKeyVerificationStatus.MISSING,
                resolved_public_key_fingerprint_sha256=None,
            )

        resolved_fingerprint = self._fingerprint_public_key(public_key)
        if (
            key.public_key_fingerprint_sha256 is not None
            and key.public_key_fingerprint_sha256 != resolved_fingerprint
        ):
            return SoftwareManagedKeyVerification(
                status=ManagedKeyVerificationStatus.MISMATCH,
                resolved_public_key_fingerprint_sha256=resolved_fingerprint,
            )

        return SoftwareManagedKeyVerification(
            status=ManagedKeyVerificationStatus.PRESENT,
            resolved_public_key_fingerprint_sha256=resolved_fingerprint,
        )

    def get_public_key(self, key: SoftwareManagedKeyBinding) -> SupportedPublicKey:
        """Load the public key for a software-managed binding."""
        private_key = self._load_private_key(key)
        public_key = private_key.public_key()
        if isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            return public_key
        msg = f'Unsupported software backend public-key type {type(public_key).__name__}.'
        raise ProviderUnavailableError(msg)

    def sign(self, *, key: SoftwareManagedKeyBinding, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes using a software-managed key binding."""
        private_key = self._load_private_key(key)
        hash_algorithm = self._hash_algorithm(request.hash_algorithm)

        if key.algorithm is KeyAlgorithm.RSA and isinstance(private_key, rsa.RSAPrivateKey):
            algorithm = utils.Prehashed(hash_algorithm) if request.prehashed else hash_algorithm
            if request.signature_algorithm is not SignatureAlgorithm.RSA_PKCS1V15:
                msg = f'Unsupported RSA signature algorithm {request.signature_algorithm.value!r}.'
                raise MechanismUnsupportedError(msg)
            return private_key.sign(
                data,
                padding.PKCS1v15(),
                algorithm,
            )

        if key.algorithm is KeyAlgorithm.EC and isinstance(private_key, ec.EllipticCurvePrivateKey):
            if request.signature_algorithm is not SignatureAlgorithm.ECDSA:
                msg = f'Unsupported EC signature algorithm {request.signature_algorithm.value!r}.'
                raise MechanismUnsupportedError(msg)
            algorithm = utils.Prehashed(hash_algorithm) if request.prehashed else hash_algorithm
            return private_key.sign(data, ec.ECDSA(algorithm))

        msg = 'Software key algorithm and private-key type are inconsistent.'
        raise ProviderUnavailableError(msg)

    def destroy_managed_key(self, key: SoftwareManagedKeyBinding) -> None:
        """Best-effort cleanup for an orphaned software-generated binding."""
        # No persisted provider-side state exists yet. Nothing to destroy.
        return

    def _generate_private_key(self, key_spec: KeySpec) -> SupportedPrivateKey:
        """Generate a supported private key."""
        if isinstance(key_spec, RsaKeySpec):
            return rsa.generate_private_key(public_exponent=65537, key_size=key_spec.key_size)

        if isinstance(key_spec, EcKeySpec):
            curve = self._curve_for_name(key_spec.curve)
            return ec.generate_private_key(curve)

        msg = f'Unsupported key specification: {type(key_spec).__name__}.'
        raise UnsupportedKeySpecError(msg)

    def _load_private_key(self, key: SoftwareManagedKeyBinding) -> SupportedPrivateKey:
        """Load and decrypt a software-managed private key."""
        try:
            private_key = serialization.load_der_private_key(
                key.encrypted_private_key_pkcs8_der,
                password=self._profile.require_encryption_material(),
            )
        except (TypeError, ValueError) as exc:
            msg = 'Failed to decrypt software-managed private key material.'
            raise KeyNotFoundError(msg) from exc

        if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            return cast('SupportedPrivateKey', private_key)

        msg = f'Unsupported software-managed private-key type {type(private_key).__name__}.'
        raise ProviderUnavailableError(msg)

    def _curve_for_name(self, curve_name: Any) -> ec.EllipticCurve:
        """Resolve a domain curve enum value to a cryptography curve."""
        value = getattr(curve_name, 'value', curve_name)
        normalized = str(value).strip().lower()

        if normalized in {'secp256r1', 'prime256v1', 'p-256'}:
            return ec.SECP256R1()
        if normalized in {'secp384r1', 'p-384'}:
            return ec.SECP384R1()
        if normalized in {'secp521r1', 'p-521'}:
            return ec.SECP521R1()

        msg = f'Unsupported elliptic curve {value!r} for the software backend.'
        raise UnsupportedKeySpecError(msg)

    def _hash_algorithm(self, hash_name: HashAlgorithmName) -> hashes.HashAlgorithm:
        """Resolve a domain hash enum value to a cryptography hash algorithm."""
        value = getattr(hash_name, 'value', hash_name)
        normalized = str(value).strip().lower()

        if normalized == 'sha256':
            return hashes.SHA256()
        if normalized == 'sha384':
            return hashes.SHA384()
        if normalized == 'sha512':
            return hashes.SHA512()

        msg = f'Unsupported hash algorithm {value!r} for the software backend.'
        raise MechanismUnsupportedError(msg)

    def _fingerprint_public_key(self, public_key: SupportedPublicKey) -> str:
        """Return the SHA-256 fingerprint of a public key SPKI DER encoding."""
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()
