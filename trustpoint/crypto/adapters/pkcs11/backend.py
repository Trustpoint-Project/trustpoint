"""Contained PKCS#11 adapter implementation."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crypto.adapters.pkcs11.bindings import Pkcs11ManagedKeyBinding, Pkcs11ManagedKeyVerification
from crypto.adapters.pkcs11.capability_probe import Pkcs11CapabilityProbe
from crypto.adapters.pkcs11.config import _normalize_pkcs11_text
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
    ProviderConfigurationError,
    ProviderUnavailableError,
    UnsupportedKeySpecError,
)
from crypto.domain.refs import ManagedKeyVerificationStatus
from crypto.domain.specs import EcKeySpec, KeySpec, RsaKeySpec, algorithm_for_key_spec
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass, PKCS11Error
from pkcs11 import lib as pkcs11_lib
from pkcs11.exceptions import TokenNotPresent, TokenNotRecognised, UserAlreadyLoggedIn
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
type TokenCandidate = tuple['Slot', 'Token']


class Pkcs11Backend(LoggerMixin):
    """PKCS#11-backed provider adapter for managed key operations."""

    provider_name = 'pkcs11'

    def __init__(
        self,
        *,
        profile: Pkcs11ProviderProfile,
        library_loader: LibraryLoader = pkcs11_lib,
        capability_probe: Pkcs11CapabilityProbe | None = None,
        locator: Pkcs11ObjectLocator | None = None,
    ) -> None:
        """Initialize the PKCS#11 adapter."""
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

    def verify_authentication(self) -> None:
        """Verify that the configured PKCS#11 user PIN can open an authenticated session."""
        self._ensure_token_loaded()
        if self._resolved_token is None:
            msg = 'PKCS#11 token resolution failed before authentication verification.'
            raise ProviderUnavailableError(msg)

        try:
            session = self._resolved_token.open(
                user_pin=self._profile.require_user_pin(),
                rw=self._profile.rw_sessions,
            )
        except UserAlreadyLoggedIn as exc:
            msg = (
                'Trustpoint already has an authenticated PKCS#11 session open and cannot '
                'conclusively re-validate the entered user PIN right now.'
            )
            raise ProviderUnavailableError(msg) from exc
        except CryptoError:
            raise
        except PKCS11Error as exc:
            raise map_pkcs11_error(exc, operation='token authentication') from exc
        else:
            try:
                session.close()
            except PKCS11Error as exc:
                raise map_pkcs11_error(exc, operation='token authentication') from exc

    def close(self) -> None:
        """Close any pooled PKCS#11 sessions held by this adapter."""
        self._reset_runtime_state()

    def probe_capabilities(self) -> Pkcs11Capabilities:
        """Probe the configured token and cache the result."""
        self._ensure_token_loaded()
        if self._capabilities is None:
            if self._resolved_slot is None or self._resolved_token is None:
                msg = 'PKCS#11 token resolution failed before capability probing.'
                raise ProviderUnavailableError(msg)
            self._capabilities = self._capability_probe.probe(slot=self._resolved_slot, token=self._resolved_token)
        return self._capabilities

    def generate_managed_key(self, *, alias: str, key_spec: KeySpec, policy: KeyPolicy) -> Pkcs11ManagedKeyBinding:
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
                elif isinstance(key_spec, RsaKeySpec):
                    generated_public_key_object = self._generate_rsa_keypair(
                        session=session,
                        alias=alias,
                        key_id=key_id,
                        key_spec=key_spec,
                        policy=policy,
                    )
                else:
                    msg = f'Unsupported key specification: {type(key_spec).__name__}.'
                    raise UnsupportedKeySpecError(msg)

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

        return Pkcs11ManagedKeyBinding(
            key_id=key_id,
            algorithm=key_algorithm,
            public_key_fingerprint_sha256=fingerprint,
            signing_execution_mode=policy.signing_execution_mode,
        )

    def verify_managed_key(self, key: Pkcs11ManagedKeyBinding) -> Pkcs11ManagedKeyVerification:
        """Verify that a managed-key binding still resolves to the expected key."""
        try:
            public_key = self.get_public_key(key)
        except KeyNotFoundError:
            return Pkcs11ManagedKeyVerification(
                status=ManagedKeyVerificationStatus.MISSING,
                resolved_public_key_fingerprint_sha256=None,
            )

        resolved_fingerprint = self._fingerprint_public_key(public_key)

        if (
            key.public_key_fingerprint_sha256 is not None
            and key.public_key_fingerprint_sha256 != resolved_fingerprint
        ):
            return Pkcs11ManagedKeyVerification(
                status=ManagedKeyVerificationStatus.MISMATCH,
                resolved_public_key_fingerprint_sha256=resolved_fingerprint,
            )

        return Pkcs11ManagedKeyVerification(
            status=ManagedKeyVerificationStatus.PRESENT,
            resolved_public_key_fingerprint_sha256=resolved_fingerprint,
        )

    def get_public_key(self, key: Pkcs11ManagedKeyBinding) -> SupportedPublicKey:
        """Load the public key for a managed PKCS#11 key binding."""
        try:
            with self._session_pool_for_token().session() as session:
                public_key_object = self._locator.public_key(session, key)
                der = self._encode_public_key_der(public_key_object, key.algorithm)
        except CryptoError:
            raise
        except PKCS11Error as exc:
            raise map_pkcs11_error(exc, operation='public-key lookup') from exc

        public_key = serialization.load_der_public_key(der)
        if isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            return public_key

        msg = f'Unsupported public-key type returned by PKCS#11 provider: {type(public_key).__name__}.'
        raise ProviderUnavailableError(msg)

    def sign(self, *, key: Pkcs11ManagedKeyBinding, data: bytes, request: SignRequest) -> bytes:
        """Sign bytes using a managed PKCS#11 key binding."""
        capabilities = self.probe_capabilities()
        operation = resolve_signing_operation(
            key_algorithm=key.algorithm,
            data=data,
            request=request,
            capabilities=capabilities,
            signing_execution_mode=key.signing_execution_mode,
        )

        try:
            with self._session_pool_for_token().session() as session:
                private_key = self._locator.private_key(session, key)
                signature = cast('Any', private_key).sign(operation.payload, mechanism=operation.mechanism)
        except CryptoError:
            raise
        except PKCS11Error as exc:
            raise map_pkcs11_error(exc, operation='signing') from exc

        if key.algorithm is KeyAlgorithm.EC:
            return encode_ecdsa_signature(signature)
        return bytes(signature)

    def destroy_managed_key(self, key: Pkcs11ManagedKeyBinding) -> None:
        """Best-effort removal of the provider objects for a managed key binding."""
        try:
            with self._session_pool_for_token().session() as session:
                for resolver in (self._locator.private_key, self._locator.public_key):
                    try:
                        obj = resolver(session, key)
                    except KeyNotFoundError:
                        continue
                    cast('Any', obj).destroy()
        except CryptoError:
            raise
        except PKCS11Error as exc:
            raise map_pkcs11_error(exc, operation='key destruction') from exc

    def _reset_runtime_state(self) -> None:
        """Drop cached runtime provider state so the next operation re-resolves it."""
        if self._session_pool is not None:
            self._session_pool.close()

        self._library = None
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
                self._log_runtime_diagnostics()
                self._library = self._library_loader(self._profile.module_path)
            except OSError as exc:
                msg = f'Failed to load PKCS#11 module at {self._profile.module_path!r}.'
                raise ProviderUnavailableError(msg) from exc

        matches = self._resolve_token_candidates()

        if matches is None:
            msg = f'Unable to resolve a PKCS#11 token for profile {self._profile.name!r}.'
            raise ProviderUnavailableError(msg)

        slot, token = matches
        self._resolved_slot = slot
        self._resolved_token = token
        self._session_pool = Pkcs11SessionPool(
            token=token,
            user_pin=self._profile.require_user_pin(),
            max_size=self._profile.max_sessions,
            borrow_timeout_seconds=self._profile.borrow_timeout_seconds,
            rw=self._profile.rw_sessions,
        )

    def _resolve_token_candidates(self) -> TokenCandidate | None:
        """Resolve a token using slot first, then serial/label fallback."""
        candidates = self._discover_present_tokens()

        slot_id = self._profile.token.slot_id
        token_serial = self._profile.token.token_serial
        token_label = self._profile.token.token_label

        if slot_id is not None:
            slot_candidates = [candidate for candidate in candidates if candidate[0].slot_id == slot_id]
            if len(slot_candidates) > 1:
                msg = f'PKCS#11 slot id {slot_id} resolved to multiple tokens for profile {self._profile.name!r}.'
                raise ProviderConfigurationError(msg)
            if slot_candidates:
                slot_candidate = slot_candidates[0]
                if self._candidate_matches_secondary_selector(
                    slot_candidate,
                    token_label=token_label,
                    token_serial=token_serial,
                ):
                    return slot_candidate
                self.logger.warning(
                    'PKCS#11 slot id %s resolved to a token that does not match the configured label/serial; '
                    'falling back to token label/serial lookup.',
                    slot_id,
                )

        if token_serial is not None:
            serial_matches = [
                candidate for candidate in candidates if self._candidate_token_serial(candidate) == token_serial
            ]
            return self._single_candidate_or_error(
                serial_matches,
                selector_description=f'token serial {token_serial!r}',
            )

        if token_label is not None:
            label_matches = [
                candidate for candidate in candidates if self._candidate_token_label(candidate) == token_label
            ]
            return self._single_candidate_or_error(
                label_matches,
                selector_description=f'token label {token_label!r}',
            )

        return None

    def _discover_present_tokens(self) -> list[TokenCandidate]:
        """Return token candidates, tolerating providers that reject token_present scans."""
        if self._library is None:
            msg = 'PKCS#11 library was not loaded before token discovery.'
            raise ProviderUnavailableError(msg)
        try:
            return self._candidates_from_slots(self._library.get_slots(token_present=True))
        except PKCS11Error as token_present_error:
            self._log_runtime_diagnostics(logging.WARNING)
            self.logger.warning(
                'PKCS#11 library failed to enumerate token-present slots; retrying with a full slot scan: %s',
                self._pkcs11_error_summary(token_present_error),
            )
            try:
                return self._candidates_from_slots(self._library.get_slots(token_present=False))
            except PKCS11Error as full_scan_error:
                msg = (
                    'PKCS#11 provider failed while enumerating slots. '
                    f'Initial token-present scan failed with {self._pkcs11_error_summary(token_present_error)}; '
                    f'fallback full scan failed with {self._pkcs11_error_summary(full_scan_error)}.'
                )
                raise ProviderUnavailableError(msg) from full_scan_error

    def _log_runtime_diagnostics(self, level: int = logging.DEBUG) -> None:
        """Log non-secret runtime facts useful for diagnosing PKCS#11 module load failures."""
        if not self.logger.isEnabledFor(level):
            return

        module_path = self._profile.module_path
        module_exists = Path(module_path).is_file()
        module_readable = os.access(module_path, os.R_OK)
        provider_config_envs = self._provider_config_envs()

        self.logger.log(
            level,
            'PKCS#11 runtime diagnostics: module_path=%r module_exists=%s module_readable=%s '
            'provider_config_envs=%s uid=%s gid=%s',
            module_path,
            module_exists,
            module_readable,
            provider_config_envs,
            os.geteuid(),
            os.getegid(),
        )

    @staticmethod
    def _pkcs11_error_summary(error: PKCS11Error) -> str:
        """Return a compact PKCS#11 error summary for diagnostics."""
        detail = str(error).strip()
        if detail:
            return f'{type(error).__name__}: {detail}'
        return type(error).__name__

    @staticmethod
    def _provider_config_envs() -> list[dict[str, object]]:
        """Return non-secret diagnostics for provider config env vars.

        PKCS#11 itself does not define a standard provider-config environment
        variable. During setup, Trustpoint exports the operator-provided env var
        name to the installed config file. For diagnostics we report only env
        vars that point at readable files under Trustpoint's HSM config area.
        """
        hsm_config_dir = os.getenv('TRUSTPOINT_HSM_CONFIG_DIR', '/var/lib/trustpoint/hsm/config')
        try:
            config_root = Path(hsm_config_dir).resolve()
        except OSError:
            return []

        diagnostics: list[dict[str, object]] = []
        for env_name, raw_path in os.environ.items():
            normalized_env_name = env_name.upper()
            if not any(marker in normalized_env_name for marker in ('CONFIG', 'CFG', 'CONF')):
                continue
            config_path = raw_path.strip()
            if not config_path:
                continue
            path = Path(config_path)
            if not path.is_absolute():
                continue
            try:
                resolved_path = path.resolve()
            except OSError:
                continue
            if config_root not in resolved_path.parents:
                continue
            diagnostics.append(
                {
                    'env': env_name,
                    'path': str(resolved_path),
                    'exists': resolved_path.is_file(),
                    'readable': os.access(resolved_path, os.R_OK),
                }
            )
        return sorted(diagnostics, key=lambda item: str(item['env']))

    def _candidates_from_slots(self, slots: list[Slot]) -> list[TokenCandidate]:
        """Return slot/token pairs for slots that currently expose a token."""
        candidates: list[TokenCandidate] = []
        for slot in slots:
            try:
                token = slot.get_token()
            except (TokenNotPresent, TokenNotRecognised):
                continue
            candidates.append((slot, token))
        return candidates

    def _candidate_matches_secondary_selector(
        self,
        candidate: TokenCandidate,
        *,
        token_label: str | None,
        token_serial: str | None,
    ) -> bool:
        """Return whether a slot-selected token satisfies configured label/serial guards."""
        if token_serial is not None and self._candidate_token_serial(candidate) != token_serial:
            return False
        return not (token_label is not None and self._candidate_token_label(candidate) != token_label)

    def _single_candidate_or_error(
        self,
        candidates: list[TokenCandidate],
        *,
        selector_description: str,
    ) -> TokenCandidate | None:
        """Return one matching token candidate or raise on ambiguous selector matches."""
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        msg = (
            f'PKCS#11 selector {selector_description} for profile {self._profile.name!r} matched multiple tokens. '
            'Use a more specific selector, preferably token_serial.'
        )
        raise ProviderConfigurationError(msg)

    @staticmethod
    def _candidate_token_label(candidate: TokenCandidate) -> str | None:
        """Return the normalized label for a token candidate."""
        return _normalize_pkcs11_text(getattr(candidate[1], 'label', None))

    @staticmethod
    def _candidate_token_serial(candidate: TokenCandidate) -> str | None:
        """Return the normalized serial for a token candidate."""
        serial = getattr(candidate[1], 'serial', None) or getattr(candidate[1], 'serial_number', None)
        return _normalize_pkcs11_text(serial)

    def _session_pool_for_token(self) -> Pkcs11SessionPool:
        """Get the lazily initialized session pool."""
        self._ensure_token_loaded()
        if self._session_pool is None:
            msg = 'PKCS#11 session pool was not initialized.'
            raise ProviderUnavailableError(msg)
        return self._session_pool

    def _ensure_alias_is_available(self, *, session: Session, alias: str) -> None:
        """Guard against duplicate application aliases on the token."""
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
        key_spec: RsaKeySpec,
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
        """Return a stable SPKI fingerprint for a generated public key when available."""
        if public_key_object is None:
            return None

        try:
            der = self._encode_public_key_der(public_key_object, algorithm)
            public_key = serialization.load_der_public_key(der)
        except (PKCS11Error, TypeError, ValueError):
            return None

        if isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            return self._fingerprint_public_key(public_key)
        return None

    def _encode_public_key_der(self, public_key_object: Any, algorithm: KeyAlgorithm) -> bytes:
        """Encode a PKCS#11 public key into DER for cryptography loading."""
        if algorithm is KeyAlgorithm.RSA:
            return encode_rsa_public_key(public_key_object)
        if algorithm is KeyAlgorithm.EC:
            return encode_ec_public_key(public_key_object)
        msg = f'Unsupported key algorithm for DER encoding: {algorithm!r}'
        raise ProviderUnavailableError(msg)
