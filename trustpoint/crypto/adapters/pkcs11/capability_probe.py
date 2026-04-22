"""Capability probing for standard PKCS#11 providers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from crypto.adapters.pkcs11.mechanisms import ecdsa_hash_mechanisms, rsa_pkcs1v15_hash_mechanisms
from crypto.domain.errors import ProviderUnavailableError
from pkcs11 import PKCS11Error  # type: ignore[import-untyped]
from pkcs11 import Mechanism  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from pkcs11 import Slot, Token


def _normalize_pkcs11_text(value: bytes | str | None) -> str | None:
    """Normalize fixed-width PKCS#11 text fields from bytes or str."""
    if value is None:
        return None

    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')

    normalized = value.rstrip('\x00 ').strip()
    return normalized or None


def _enum_name(value: Any) -> str:
    """Return a stable enum/member name for PKCS#11 values."""
    if hasattr(value, 'name'):
        return str(value.name)
    return str(value)


def _mechanism_storage_name(value: Any) -> str:
    """Return a normalized persisted name for a PKCS#11 mechanism."""
    name = _enum_name(value).lstrip('_')
    if name.startswith('CKM_'):
        return name
    return f'CKM_{name}'


def _mechanism_storage_code(value: Any) -> int | None:
    """Return the numeric PKCS#11 mechanism code when available."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sorted_flag_names(flags: Any) -> tuple[str, ...]:
    """Convert a PKCS#11 flag set into a stable tuple of names."""
    if flags is None:
        return ()
    try:
        values = sorted(_enum_name(flag) for flag in flags)
    except TypeError:
        values = [_enum_name(flags)]
    return tuple(values)


def _optional_int(value: Any) -> int | None:
    """Convert a value to int when possible."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class LibraryIdentity:
    """Portable identity details for the loaded PKCS#11 library."""

    description: str | None = None
    manufacturer: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class TokenIdentity:
    """Portable identity details for the selected token."""

    slot_id: int | None
    label: str | None
    serial: str | None
    model: str | None
    manufacturer: str | None
    hardware_version: str | None = None
    firmware_version: str | None = None


@dataclass(frozen=True, slots=True)
class MechanismCapability:
    """A single supported PKCS#11 mechanism and its bounds."""

    name: str
    code: int | None
    flags: tuple[str, ...]
    min_key_size: int | None = None
    max_key_size: int | None = None


@dataclass(frozen=True, slots=True)
class Pkcs11Capabilities:
    """Serializable capability snapshot for one PKCS#11 provider/token pair."""

    pkcs11_spec_version: str | None
    library: LibraryIdentity
    token: TokenIdentity
    token_flags: tuple[str, ...]
    mechanisms: dict[str, MechanismCapability]
    derived_features: dict[str, bool] = field(default_factory=dict)

    def supports(self, mechanism: Mechanism) -> bool:
        """Return whether the token supports the given mechanism."""
        return _mechanism_storage_name(mechanism) in self.mechanisms

    def mechanism(self, mechanism: Mechanism) -> MechanismCapability | None:
        """Return a mechanism capability entry if present."""
        return self.mechanisms.get(_mechanism_storage_name(mechanism))

    def to_json_dict(self) -> dict[str, Any]:
        """Convert the snapshot into a JSON-serializable dictionary."""
        return {
            'pkcs11_spec_version': self.pkcs11_spec_version,
            'library': {
                'description': self.library.description,
                'manufacturer': self.library.manufacturer,
                'version': self.library.version,
            },
            'token': {
                'slot_id': self.token.slot_id,
                'label': self.token.label,
                'serial': self.token.serial,
                'model': self.token.model,
                'manufacturer': self.token.manufacturer,
                'hardware_version': self.token.hardware_version,
                'firmware_version': self.token.firmware_version,
            },
            'token_flags': list(self.token_flags),
            'mechanisms': {
                name: {
                    'name': capability.name,
                    'code': capability.code,
                    'flags': list(capability.flags),
                    'min_key_size': capability.min_key_size,
                    'max_key_size': capability.max_key_size,
                }
                for name, capability in sorted(self.mechanisms.items())
            },
            'derived_features': dict(sorted(self.derived_features.items())),
        }

    def fingerprint(self) -> str:
        """Return a stable hash of the snapshot contents."""
        encoded = json.dumps(self.to_json_dict(), sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def from_json_dict(cls, payload: dict[str, Any]) -> Pkcs11Capabilities:
        """Rebuild a capability snapshot from stored JSON."""
        mechanisms = {
            name: MechanismCapability(
                name=entry['name'],
                code=entry.get('code'),
                flags=tuple(entry.get('flags', ())),
                min_key_size=entry.get('min_key_size'),
                max_key_size=entry.get('max_key_size'),
            )
            for name, entry in payload.get('mechanisms', {}).items()
        }
        library_payload = payload.get('library', {})
        token_payload = payload.get('token', {})
        return cls(
            pkcs11_spec_version=payload.get('pkcs11_spec_version'),
            library=LibraryIdentity(
                description=library_payload.get('description'),
                manufacturer=library_payload.get('manufacturer'),
                version=library_payload.get('version'),
            ),
            token=TokenIdentity(
                slot_id=token_payload.get('slot_id'),
                label=token_payload.get('label'),
                serial=token_payload.get('serial'),
                model=token_payload.get('model'),
                manufacturer=token_payload.get('manufacturer'),
                hardware_version=token_payload.get('hardware_version'),
                firmware_version=token_payload.get('firmware_version'),
            ),
            token_flags=tuple(payload.get('token_flags', ())),
            mechanisms=mechanisms,
            derived_features=dict(payload.get('derived_features', {})),
        )


class Pkcs11CapabilityProbe:
    """Probe portable PKCS#11 token and mechanism capabilities."""

    def probe(self, *, slot: Slot, token: Token) -> Pkcs11Capabilities:
        """Probe the selected slot/token and return a serializable snapshot."""
        self._assert_binding_support(slot=slot)

        try:
            mechanisms = self._probe_mechanisms(slot=slot)
            token_flags = self._probe_token_flags(token=token)
            return Pkcs11Capabilities(
                pkcs11_spec_version=self._probe_pkcs11_spec_version(slot=slot, token=token),
                library=self._probe_library_identity(slot=slot, token=token),
                token=self._probe_token_identity(slot=slot, token=token),
                token_flags=token_flags,
                mechanisms=mechanisms,
                derived_features=self._derive_features(mechanisms=mechanisms, token_flags=token_flags),
            )
        except ProviderUnavailableError:
            raise
        except (PKCS11Error, OSError, TypeError, ValueError) as exc:
            msg = 'Failed to probe PKCS#11 provider capabilities.'
            raise ProviderUnavailableError(msg) from exc

    def _assert_binding_support(self, *, slot: Slot) -> None:
        """Fail fast if the active Python PKCS#11 binding lacks required probe APIs."""
        if not callable(getattr(slot, 'get_mechanisms', None)):
            msg = 'The active PKCS#11 binding does not expose Slot.get_mechanisms().'
            raise ProviderUnavailableError(msg)
        if not callable(getattr(slot, 'get_mechanism_info', None)):
            msg = 'The active PKCS#11 binding does not expose Slot.get_mechanism_info().'
            raise ProviderUnavailableError(msg)

    def _probe_library_identity(self, *, slot: Slot, token: Token) -> LibraryIdentity:
        """Probe portable library-level identity where exposed by the binding."""
        info = None
        for candidate in (
            getattr(slot, 'get_library_info', None),
            getattr(token, 'get_library_info', None),
        ):
            if callable(candidate):
                try:
                    info = candidate()
                except (PKCS11Error, OSError, TypeError, ValueError):
                    info = None
                if info is not None:
                    break

        return LibraryIdentity(
            description=_normalize_pkcs11_text(
                getattr(info, 'library_description', None) or getattr(info, 'description', None)
            ),
            manufacturer=_normalize_pkcs11_text(
                getattr(info, 'manufacturer_id', None) or getattr(info, 'manufacturer', None)
            ),
            version=self._format_version(
                getattr(info, 'library_version', None) or getattr(info, 'version', None),
            ),
        )

    def _probe_token_identity(self, *, slot: Slot, token: Token) -> TokenIdentity:
        """Probe token identity in a portable form."""
        return TokenIdentity(
            slot_id=_optional_int(getattr(slot, 'slot_id', None)),
            label=_normalize_pkcs11_text(getattr(token, 'label', None)),
            serial=_normalize_pkcs11_text(getattr(token, 'serial', None) or getattr(token, 'serial_number', None)),
            model=_normalize_pkcs11_text(getattr(token, 'model', None)),
            manufacturer=_normalize_pkcs11_text(
                getattr(token, 'manufacturer_id', None) or getattr(token, 'manufacturer', None)
            ),
            hardware_version=self._format_version(getattr(token, 'hardware_version', None)),
            firmware_version=self._format_version(getattr(token, 'firmware_version', None)),
        )

    def _probe_pkcs11_spec_version(self, *, slot: Slot, token: Token) -> str | None:
        """Probe the PKCS#11 spec version if exposed by the binding."""
        for source in (slot, token):
            value = getattr(source, 'cryptoki_version', None) or getattr(source, 'pkcs11_version', None)
            formatted = self._format_version(value)
            if formatted is not None:
                return formatted
        return None

    def _probe_token_flags(self, *, token: Token) -> tuple[str, ...]:
        """Probe token flags in a portable form."""
        return _sorted_flag_names(getattr(token, 'flags', None))

    def _probe_mechanisms(self, *, slot: Slot) -> dict[str, MechanismCapability]:
        """Probe supported mechanisms and per-mechanism metadata.

        Some PKCS#11 stacks and proxy layers advertise mechanisms via
        get_mechanisms() but then reject get_mechanism_info() for a subset of
        them with CKR_MECHANISM_INVALID. Treat those entries as unusable and
        skip them instead of failing the whole provider probe.
        """
        mechanism_entries: dict[str, MechanismCapability] = {}

        try:
            advertised_mechanisms = tuple(slot.get_mechanisms())
        except (PKCS11Error, OSError, TypeError, ValueError) as exc:
            msg = 'Failed to enumerate PKCS#11 mechanisms.'
            raise ProviderUnavailableError(msg) from exc

        for mechanism in advertised_mechanisms:
            mechanism_name = _mechanism_storage_name(mechanism)

            try:
                info = slot.get_mechanism_info(mechanism)
            except (PKCS11Error, OSError, TypeError, ValueError):
                # Skip mechanisms that cannot be introspected portably.
                continue

            mechanism_entries[mechanism_name] = MechanismCapability(
                name=mechanism_name,
                code=_mechanism_storage_code(mechanism),
                flags=_sorted_flag_names(getattr(info, 'flags', None)),
                min_key_size=_optional_int(getattr(info, 'min_key_size', None) or getattr(info, 'ulMinKeySize', None)),
                max_key_size=_optional_int(getattr(info, 'max_key_size', None) or getattr(info, 'ulMaxKeySize', None)),
            )

        if advertised_mechanisms and not mechanism_entries:
            msg = (
                'PKCS#11 provider advertised mechanisms but none exposed portable '
                'mechanism metadata via Slot.get_mechanism_info().'
            )
            raise ProviderUnavailableError(msg)

        return dict(sorted(mechanism_entries.items()))

    def _derive_features(
        self,
        *,
        mechanisms: dict[str, MechanismCapability],
        token_flags: tuple[str, ...],
    ) -> dict[str, bool]:
        """Derive Trustpoint-facing backend features from raw PKCS#11 facts."""
        mechanism_names = set(mechanisms)
        token_flag_set = set(token_flags)

        def has(mechanism_name: str) -> bool:
            return mechanism_name in mechanism_names

        rsa_exact_support = {
            f'supports_sign_rsa_pkcs1v15_{hash_algorithm.value}': has(_mechanism_storage_name(mechanism))
            for hash_algorithm, mechanism in rsa_pkcs1v15_hash_mechanisms().items()
        }
        ecdsa_exact_support = {
            f'supports_sign_ecdsa_{hash_algorithm.value}': has(_mechanism_storage_name(mechanism))
            for hash_algorithm, mechanism in ecdsa_hash_mechanisms().items()
        }

        derived = {
            'login_required': 'LOGIN_REQUIRED' in token_flag_set or 'CKF_LOGIN_REQUIRED' in token_flag_set,
            'user_pin_initialized': 'USER_PIN_INITIALIZED' in token_flag_set or 'CKF_USER_PIN_INITIALIZED' in token_flag_set,
            'can_generate_rsa': has('CKM_RSA_PKCS_KEY_PAIR_GEN'),
            'can_generate_ec': has('CKM_EC_KEY_PAIR_GEN'),
            'supports_raw_rsa_pkcs1v15': has('CKM_RSA_PKCS'),
            'supports_raw_ecdsa': has('CKM_ECDSA'),
            'can_wrap_keys': has('CKM_AES_KEY_WRAP'),
            'can_unwrap_keys': has('CKM_AES_KEY_WRAP'),
        }
        derived.update(rsa_exact_support)
        derived.update(ecdsa_exact_support)

        derived['can_sign_rsa_pkcs1v15'] = (
            derived['supports_raw_rsa_pkcs1v15'] or any(rsa_exact_support.values())
        )
        derived['can_sign_ecdsa'] = (
            derived['supports_raw_ecdsa'] or any(ecdsa_exact_support.values())
        )
        return derived

    def _format_version(self, value: Any) -> str | None:
        """Convert a PKCS#11 version object into a stable string."""
        if value is None:
            return None
        major = getattr(value, 'major', None)
        minor = getattr(value, 'minor', None)
        if major is not None and minor is not None:
            return f'{major}.{minor}'
        return _normalize_pkcs11_text(str(value))
