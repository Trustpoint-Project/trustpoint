"""Trustpoint-facing crypto backend capability service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec
from pkcs11 import Mechanism  # type: ignore[import-untyped]

from crypto.adapters.pkcs11.capability_probe import Pkcs11Capabilities
from crypto.adapters.rest.capabilities import RestCapabilities
from crypto.adapters.software.capabilities import SoftwareCapabilities
from crypto.application.backend_factory import BackendAdapterFactory, DefaultBackendAdapterFactory
from crypto.domain.algorithms import EllipticCurveName
from crypto.models import BackendKind, CryptoProviderProfileModel
from crypto.repositories import CryptoProviderProfileRepository

if TYPE_CHECKING:
    from crypto.domain.specs import KeySpec
    from crypto.repositories import ProviderCapabilities


SOFTWARE_RSA_KEY_SIZES = (2048, 3072, 4096)
SOFTWARE_EC_CURVES = (
    EllipticCurveName.SECP256R1,
    EllipticCurveName.SECP384R1,
    EllipticCurveName.SECP521R1,
)


@dataclass(frozen=True, slots=True)
class BackendCapabilityReport:
    """Normalized capabilities used by product code above individual adapters."""

    backend_kind: BackendKind | None
    profile_name: str | None
    available: bool
    capabilities_known: bool = True
    diagnostics: tuple[str, ...] = ()
    rsa_key_sizes: tuple[int, ...] = ()
    ec_curves: tuple[EllipticCurveName, ...] = ()

    def supports_rsa_key_size(self, key_size: int) -> bool:
        """Return whether the backend can generate and use an RSA key of this size."""
        return self.available and key_size in self.rsa_key_sizes

    def supports_ec_curve(self, curve: ec.EllipticCurve | EllipticCurveName | str) -> bool:
        """Return whether the backend can generate and use a key on this curve."""
        curve_name = normalize_curve_name(curve)
        return curve_name is not None and self.available and curve_name in self.ec_curves

    def supports_key_spec(self, key_spec: KeySpec) -> bool:
        """Return whether the backend can generate and use the requested key spec."""
        from crypto.domain.specs import EcKeySpec, RsaKeySpec  # noqa: PLC0415

        if isinstance(key_spec, RsaKeySpec):
            return self.supports_rsa_key_size(key_spec.key_size)
        if isinstance(key_spec, EcKeySpec):
            return self.supports_ec_curve(key_spec.curve)
        return False


def normalize_curve_name(curve: ec.EllipticCurve | EllipticCurveName | str) -> EllipticCurveName | None:
    """Normalize supported curve spellings to Trustpoint's domain enum."""
    raw_value = getattr(curve, 'value', None) or getattr(curve, 'name', None) or str(curve)
    normalized = raw_value.strip().lower()
    aliases = {
        'secp256r1': EllipticCurveName.SECP256R1,
        'prime256v1': EllipticCurveName.SECP256R1,
        'p-256': EllipticCurveName.SECP256R1,
        'secp384r1': EllipticCurveName.SECP384R1,
        'p-384': EllipticCurveName.SECP384R1,
        'secp521r1': EllipticCurveName.SECP521R1,
        'p-521': EllipticCurveName.SECP521R1,
    }
    return aliases.get(normalized)


class BackendCapabilityService:
    """Central source for backend capability decisions used by higher layers."""

    def __init__(
        self,
        *,
        profile_repository: CryptoProviderProfileRepository | None = None,
        adapter_factory: BackendAdapterFactory | None = None,
    ) -> None:
        """Initialize the capability service."""
        self._profile_repository = profile_repository or CryptoProviderProfileRepository()
        self._adapter_factory = adapter_factory or DefaultBackendAdapterFactory()

    def active_report(self, *, refresh: bool = False, strict: bool = False) -> BackendCapabilityReport:
        """Return the normalized report for the configured instance backend."""
        try:
            profile = self._profile_repository.get_configured_profile()
        except CryptoProviderProfileModel.DoesNotExist as exc:
            if strict:
                raise
            return BackendCapabilityReport(
                backend_kind=None,
                profile_name=None,
                available=False,
                capabilities_known=False,
                diagnostics=(f'No configured crypto backend profile exists: {exc}',),
            )

        try:
            capabilities = self._load_capabilities(profile=profile, refresh=refresh)
        except Exception as exc:
            if strict:
                raise
            return BackendCapabilityReport(
                backend_kind=BackendKind(profile.backend_kind),
                profile_name=profile.name,
                available=False,
                capabilities_known=False,
                diagnostics=(str(exc),),
            )

        if capabilities is None:
            return BackendCapabilityReport(
                backend_kind=BackendKind(profile.backend_kind),
                profile_name=profile.name,
                available=False,
                capabilities_known=False,
                diagnostics=('No successful backend capability snapshot is available yet.',),
            )
        return self._normalize_capabilities(profile=profile, capabilities=capabilities)

    def refresh_and_record_active_report(self) -> BackendCapabilityReport:
        """Probe the active backend live, persist the snapshot, and return the normalized report."""
        profile = self._profile_repository.get_configured_profile()
        backend = self._adapter_factory.build(profile)
        try:
            capabilities = backend.refresh_capabilities()
            self._profile_repository.record_probe_success(profile=profile, capabilities=capabilities)
        except Exception as exc:
            self._profile_repository.record_probe_failure(profile=profile, error_summary=str(exc))
            raise
        finally:
            backend.close()

        return self._normalize_capabilities(profile=profile, capabilities=capabilities)

    def _load_capabilities(
        self,
        *,
        profile: CryptoProviderProfileModel,
        refresh: bool,
    ) -> ProviderCapabilities | None:
        """Load persisted capabilities, or explicitly refresh them when requested."""
        if refresh:
            backend = self._adapter_factory.build(profile)
            try:
                return backend.refresh_capabilities()
            finally:
                backend.close()

        if profile.backend_kind == BackendKind.SOFTWARE:
            return SoftwareCapabilities(
                supported_key_algorithms=('rsa', 'ec'),
                supported_signature_algorithms=('rsa_pkcs1v15', 'ecdsa'),
                supported_signing_execution_modes=('complete_backend', 'allow_application_hash'),
            )

        return self._profile_repository.load_current_capabilities(profile=profile)

    def _normalize_capabilities(
        self,
        *,
        profile: CryptoProviderProfileModel,
        capabilities: ProviderCapabilities,
    ) -> BackendCapabilityReport:
        """Convert adapter-specific capability snapshots into product-level support."""
        backend_kind = BackendKind(profile.backend_kind)
        if isinstance(capabilities, Pkcs11Capabilities):
            return self._pkcs11_report(profile=profile, capabilities=capabilities)

        if isinstance(capabilities, SoftwareCapabilities):
            return BackendCapabilityReport(
                backend_kind=backend_kind,
                profile_name=profile.name,
                available=True,
                rsa_key_sizes=SOFTWARE_RSA_KEY_SIZES,
                ec_curves=SOFTWARE_EC_CURVES,
            )

        if isinstance(capabilities, RestCapabilities):
            supported_algorithms = set(capabilities.supported_key_algorithms)
            return BackendCapabilityReport(
                backend_kind=backend_kind,
                profile_name=profile.name,
                available=True,
                rsa_key_sizes=SOFTWARE_RSA_KEY_SIZES if 'rsa' in supported_algorithms else (),
                ec_curves=SOFTWARE_EC_CURVES if 'ec' in supported_algorithms else (),
            )

        return BackendCapabilityReport(
            backend_kind=backend_kind,
            profile_name=profile.name,
            available=False,
            diagnostics=(f'Unsupported capability snapshot type {type(capabilities).__name__}.',),
        )

    def _pkcs11_report(
        self,
        *,
        profile: CryptoProviderProfileModel,
        capabilities: Pkcs11Capabilities,
    ) -> BackendCapabilityReport:
        """Normalize a PKCS#11 probe snapshot."""
        rsa_key_sizes: list[int] = []
        ec_curves: list[EllipticCurveName] = []
        derived = capabilities.derived_features

        rsa_generation = capabilities.mechanism(Mechanism.RSA_PKCS_KEY_PAIR_GEN)
        if rsa_generation and derived.get('can_sign_rsa_pkcs1v15', False):
            min_key_size = rsa_generation.min_key_size or 0
            max_key_size = rsa_generation.max_key_size or 100_000
            rsa_key_sizes = [
                key_size for key_size in SOFTWARE_RSA_KEY_SIZES if min_key_size <= key_size <= max_key_size
            ]

        ec_generation = capabilities.mechanism(Mechanism.EC_KEY_PAIR_GEN)
        if ec_generation and derived.get('can_sign_ecdsa', False):
            min_key_size = ec_generation.min_key_size or 0
            max_key_size = ec_generation.max_key_size or 100_000
            ec_curves = [
                curve_name
                for curve_name in SOFTWARE_EC_CURVES
                if min_key_size <= curve_name.to_cryptography_curve().key_size <= max_key_size
            ]

        diagnostics: tuple[str, ...] = ()
        if not rsa_key_sizes and not ec_curves:
            diagnostics = ('The PKCS#11 provider did not report usable CA key-generation/signing support.',)

        return BackendCapabilityReport(
            backend_kind=BackendKind(profile.backend_kind),
            profile_name=profile.name,
            available=bool(rsa_key_sizes or ec_curves),
            diagnostics=diagnostics,
            rsa_key_sizes=tuple(rsa_key_sizes),
            ec_curves=tuple(ec_curves),
        )


def get_active_backend_capability_report(*, refresh: bool = False, strict: bool = False) -> BackendCapabilityReport:
    """Convenience wrapper for callers that do not need to inject dependencies."""
    return BackendCapabilityService().active_report(refresh=refresh, strict=strict)
