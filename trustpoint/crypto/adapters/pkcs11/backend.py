"""Contained PKCS#11 backend implementation."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization

import pkcs11
from crypto.adapters.pkcs11.capability_probe import Pkcs11CapabilityProbe
from crypto.adapters.pkcs11.error_map import map_pkcs11_error
from crypto.adapters.pkcs11.locator import Pkcs11ObjectLocator
from crypto.adapters.pkcs11.mechanism_policy import resolve_signing_operation
from crypto.adapters.pkcs11.mechanisms import ec_parameters_for_curve, private_key_template, public_key_template
from crypto.adapters.pkcs11.session_pool import Pkcs11SessionPool
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.errors import (
    CryptoError,
    KeyAlreadyExistsError,
    KeyNotFoundError,
    MechanismUnsupportedError,
    ProviderConfigurationError,
    ProviderUnavailableError,
)
from crypto.domain.refs import (
    ManagedKeyRef,
    ManagedKeyVerification,
    ManagedKeyVerificationStatus,
)
from crypto.domain.specs import EcKeySpec, KeySpec, algorithm_for_key_spec
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass, PKCS11Error
from pkcs11.util.ec import encode_ec_public_key, encode_ecdsa_signature
from pkcs11.util.rsa import encode_rsa_public_key
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
    from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile
    from crypto.domain.algorithms import SupportedPublicKey
    from crypto.domain.policies import KeyPolicy
    from crypto.domain.specs import SignRequest
    from pkcs11 import Session, Slot, Token

type LibraryLoader = Callable[[str], Any]


class Pkcs11Backend(LoggerMixin):
    """PKCS#11-backed implementation of the new crypto backend contract.

    This implementation is intentionally standard-first and avoids any
    vendor-specific behavior. Vendor quirks, if needed later, belong in a
    separate override layer behind the same contract.
    """

    provider_name = 'pkcs11'

    def __init__(
        self,
        *,
        profile: Pkcs11ProviderProfile,
        library_loader: LibraryLoader = pkcs11.lib,
        capability_probe: Pkcs11CapabilityProbe | None = None,
        locator: Pkcs11ObjectLocator | None = None,
    ) -> None:
        """Initialize the PKCS#11 backend."""
        self._profile = profile
        self._library_loader = library_loader
        self._capability_probe = capability_probe or Pkcs11CapabilityProbe()
        self._locator = locator or Pkcs11ObjectLocator()
        self._library: Any | None = None
        self._resolved_slot: Slot | None = None
        self._resolved_token: Token | None = None
        self._session_pool: Pkcs11SessionPool | None = None
        self._capabilities: Pkcs11Capabilities | None = None

    def verify_provider(self) -> None:
        """Validate that the configured provider can be loaded and probed."""
        self.probe_capabilities()

    def refresh_capabilities(self) -> Pkcs11Capabilities:
        """Force a fresh provider resolution and capability probe."""
        self._reset_runtime_state()
        return self.probe_capabilities()

    def current_capabilities(self) -> Pkcs11Capabilities | None:
        """Return the currently cached capability snapshot, if any."""
        return self._capabilities

    def close(self) -> None:
        """Close any pooled PKCS#11 sessions held by this backend."""
        if self._session_pool is not None:
            self._session_pool.close()

    def probe_capabilities(self) -> Pkcs11Capabilities:
        """Probe the configured token and cache the result."""
        self._ensure_token_loaded()
        if self._capabilities is None:
            if self._resolved_slot is None or self._resolved_token is None:
                msg = 'PKCS#11 token resolution failed before capability probing.'
                raise ProviderUnavailableError(msg)
            self._capabilities = self._capability_probe.probe(slot=self._resolved_slot, token=self._resolved_token)
        return self._capabilities

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> ManagedKeyRef:
        """Generate a managed PKCS#11-backed key pair."""
        key_algorithm = algorithm_for_key_spec(key_spec)
        key_id = secrets.token_bytes(16)

        try:
            with self._session_pool_for_token().session() as session:
                self._ensure_alias_is_available(session=session, alias=alias)
                if isinstance(key_spec, EcKeySpec):
                    generated_public_key_object = self._generate_ec_keypair(
                        session=session,
                        alias=alias,
                        key_id=key_id,
                        key_spec=key_spec,
                        policy=policy,
                    )
                else:
                    generated_public_key_object = self._generate_rsa_keypair(
                        session=session,
                        alias=alias,
                        key_id=key_id,
                        key_spec=key_spec,
                        policy=policy,
                    )

                fingerprint = self._fingerprint_generated_public_key(
                    public_key_object=generated_public_key_object,
                    algorithm=key_algorithm,
                )
        except KeyAlreadyExistsError:
            raise
        except CryptoError:
            raise
        except PKCS11Error as exc:
            raise map_pkcs11_error(exc, operation='key generation') from exc

        return ManagedKeyRef(
            alias=alias,
            provider=self.provider_name,
            key_id=key_id,
            label=alias,
            algorithm=key_algorithm,
            public_key_fingerprint_sha256=fingerprint,
        )

    def verify_managed_key(self, key: ManagedKeyRef) -> ManagedKeyVerification:
        """Verify that a managed-key reference still resolves to the expected key."""
        try:
            public_key = self.get_public_key(key)
        except KeyNotFoundError:
            return ManagedKeyVerification(
                key=key,
                status=ManagedKeyVerificationStatus.MISSING,
                resolved_public_key_fingerprint_sha256=None,
            )
        except CryptoError:
            raise

        resolved_fingerprint = self._fingerprint_public_key(public_key)

        if (
            key.public_key_fingerprint_sha256 is not None
            and key.public_key_fingerprint_sha256 != resolved_fingerprint
        ):
            return ManagedKeyVerification(
                key=key,
                status=ManagedKeyVerificationStatus.MISMATCH,
                resolved_public_key_fingerprint_sha256=resolved_fingerprint,
            )

        return ManagedKeyVerification(
            key=key,
            status=ManagedKeyVerificationStatus.PRESENT,
            resolved_public_key_fingerprint_sha256=resolved_fingerprint,
        )

    def get_public_key(self, key: ManagedKeyRef) -> SupportedPublicKey:
        """Load the public key for a managed PKCS#11-managed key."""
        try:
            with self._session_pool_for_token().session() as session:
                public_key_object = self._locator.public_key(
                    session,
                    key,
                    allow_label_fallback=self._profile.allow_legacy_label_lookup,
                )
                der = self._encode_public_key_der(public_key_object, key.algorithm)
        except CryptoError:
            raise
        except PKCS11Error as exc:
            raise map_pkcs11_error(exc, operation='public-key lookup') from exc

        return serialization.load_der_public_key(der)

    def sign(self, *, key: ManagedKeyRef, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes using a managed PKCS#11 key.

        Trustpoint requires the HSM to perform the complete signing operation.
        No software hashing or padding fallback is applied here.
        """
        capabilities = self.probe_capabilities()
        operation = resolve_signing_operation(
            key_algorithm=key.algorithm,
            data=data,
            request=request,
            capabilities=capabilities,
        )

        try:
            with self._session_pool_for_token().session() as session:
                private_key = self._locator.private_key(
                    session,
                    key,
                    allow_label_fallback=self._profile.allow_legacy_label_lookup,
                )
                signature = private_key.sign(operation.payload, mechanism=operation.mechanism)
        except CryptoError:
            raise
        except PKCS11Error as exc:
            raise map_pkcs11_error(exc, operation='signing') from exc

        if key.algorithm is KeyAlgorithm.EC:
            return encode_ecdsa_signature(signature)
        return bytes(signature)

    def _reset_runtime_state(self) -> None:
        """Drop cached runtime provider state so the next operation re-resolves it."""
        if self._session_pool is not None:
            self._session_pool.close()

        self._session_pool = None
        self._resolved_slot = None
        self._resolved_token = None
        self._capabilities = None

    def _ensure_token_loaded(self) -> None:
        """Resolve and cache the library, slot, token, and session pool."""
        if self._resolved_token is not None and self._resolved_slot is not None and self._session_pool is not None:
            return

        if self._library is None:
            try:
                self._library = self._library_loader(self._profile.module_path)
            except OSError as exc:
                msg = f'Failed to load PKCS#11 module at {self._profile.module_path!r}.'
                raise ProviderUnavailableError(msg) from exc

        matches: list[tuple[Slot, Token]] = []

        for slot in self._library.get_slots(token_present=True):
            token = slot.get_token()
            token_serial = getattr(token, 'serial', None) or getattr(token, 'serial_number', None)
            token_label = getattr(token, 'label', None)

            if self._profile.token.matches(
                slot_id=slot.slot_id,
                token_label=token_label,
                token_serial=token_serial,
            ):
                matches.append((slot, token))

        if not matches:
            msg = f'Unable to resolve a PKCS#11 token for profile {self._profile.name!r}.'
            raise ProviderUnavailableError(msg)

        if len(matches) > 1:
            msg = (
                f'PKCS#11 token selector for profile {self._profile.name!r} matched multiple tokens. '
                'Use a more specific selector, preferably token_serial.'
            )
            raise ProviderConfigurationError(msg)

        slot, token = matches[0]
        self._resolved_slot = slot
        self._resolved_token = token
        self._session_pool = Pkcs11SessionPool(
            token=token,
            user_pin=self._profile.require_user_pin(),
            max_size=self._profile.max_sessions,
            borrow_timeout_seconds=self._profile.borrow_timeout_seconds,
            rw=self._profile.rw_sessions,
        )

    def _session_pool_for_token(self) -> Pkcs11SessionPool:
        """Get the lazily initialized session pool."""
        self._ensure_token_loaded()
        if self._session_pool is None:
            msg = 'PKCS#11 session pool was not initialized.'
            raise ProviderUnavailableError(msg)
        return self._session_pool

    def _ensure_alias_is_available(self, *, session: Session, alias: str) -> None:
        """Guard against duplicate application aliases on the token.

        Alias uniqueness is treated as application identity uniqueness, not as
        an algorithm-specific namespace.
        """
        filters = {
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.LABEL: alias,
        }
        existing = session.get_objects(filters)
        if any(True for _ in existing):
            msg = f'A managed key with alias {alias!r} already exists on the PKCS#11 token.'
            raise KeyAlreadyExistsError(msg)

    def _generate_rsa_keypair(
        self,
        *,
        session: Session,
        alias: str,
        key_id: bytes,
        key_spec: KeySpec,
        policy: KeyPolicy,
    ) -> Any | None:
        """Generate an RSA key pair and return the generated public-key object when available."""
        generated = session.generate_keypair(
            KeyType.RSA,
            key_spec.key_size,
            id=key_id,
            label=alias,
            store=not policy.ephemeral,
            public_template=public_key_template(key_id=key_id, label=alias, policy=policy),
            private_template=private_key_template(key_id=key_id, label=alias, policy=policy),
            mechanism=Mechanism.RSA_PKCS_KEY_PAIR_GEN,
        )
        return self._extract_generated_public_key(generated)

    def _generate_ec_keypair(
        self,
        *,
        session: Session,
        alias: str,
        key_id: bytes,
        key_spec: EcKeySpec,
        policy: KeyPolicy,
    ) -> Any | None:
        """Generate an EC key pair using standard EC domain parameters and return the public key when available."""
        parameters = session.create_domain_parameters(
            KeyType.EC,
            {
                Attribute.EC_PARAMS: ec_parameters_for_curve(key_spec.curve),
            },
            local=True,
        )
        generated = parameters.generate_keypair(
            id=key_id,
            label=alias,
            store=not policy.ephemeral,
            public_template=public_key_template(key_id=key_id, label=alias, policy=policy),
            private_template=private_key_template(key_id=key_id, label=alias, policy=policy),
            mechanism=Mechanism.EC_KEY_PAIR_GEN,
        )
        return self._extract_generated_public_key(generated)

    def _fingerprint_public_key(self, public_key: SupportedPublicKey) -> str:
        """Return the SHA-256 fingerprint of a public key's SPKI DER encoding."""
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return self._fingerprint_public_key_der(der)


    def _fingerprint_public_key_der(self, der: bytes) -> str:
        """Return the SHA-256 fingerprint of DER-encoded public-key bytes."""
        return hashlib.sha256(der).hexdigest()

    def _extract_generated_public_key(self, generated: Any) -> Any | None:
        """Extract the generated public-key object from a PKCS#11 generate_keypair result."""
        if isinstance(generated, tuple) and generated:
            return generated[0]
        return None

    def _fingerprint_generated_public_key(
        self,
        *,
        public_key_object: Any | None,
        algorithm: KeyAlgorithm,
    ) -> str | None:
        """Return a stable SPKI fingerprint for a generated public key when available.

        Some unit-test fakes or provider return values may not expose enough PKCS#11
        public-key attributes to encode the key immediately after generation. In that
        case, treat fingerprinting as unavailable instead of failing key generation.
        """
        if public_key_object is None:
            return None

        try:
            der = self._encode_public_key_der(public_key_object, algorithm)
            public_key = serialization.load_der_public_key(der)
        except Exception:
            return None

        return self._fingerprint_public_key(public_key)

    def _encode_public_key_der(self, public_key_object: Any, algorithm: KeyAlgorithm) -> bytes:
        """Encode a PKCS#11 public key into DER for cryptography loading."""
        if algorithm is KeyAlgorithm.RSA:
            return encode_rsa_public_key(public_key_object)
        if algorithm is KeyAlgorithm.EC:
            return encode_ec_public_key(public_key_object)
        msg = f'Unsupported key algorithm for DER encoding: {algorithm!r}'
        raise ProviderUnavailableError(msg)
