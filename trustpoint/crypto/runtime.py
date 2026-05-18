"""Runtime helpers for the configured Trustpoint crypto backend."""

from __future__ import annotations

from trustpoint_core.serializer import PrivateKeyLocation

from crypto.local_development import ensure_local_software_backends
from crypto.models import BackendKind, CryptoProviderProfileModel


def get_configured_profile() -> CryptoProviderProfileModel | None:
    """Return the active configured crypto profile, if any."""
    ensure_local_software_backends()
    return CryptoProviderProfileModel.objects.filter(active=True).first()


def require_configured_profile() -> CryptoProviderProfileModel:
    """Return the active configured crypto profile or raise."""
    profile = get_configured_profile()
    if profile is None:
        msg = 'No configured crypto backend profile is available for this Trustpoint instance.'
        raise RuntimeError(msg)
    return profile


def configured_backend_kind() -> BackendKind | None:
    """Return the active backend kind, if configured."""
    profile = get_configured_profile()
    if profile is None:
        return None
    return BackendKind(profile.backend_kind)


def configured_private_key_location() -> PrivateKeyLocation:
    """Map the configured backend kind for legacy signer import forms."""
    backend_kind = configured_backend_kind()
    if backend_kind == BackendKind.SOFTWARE:
        return PrivateKeyLocation.SOFTWARE
    if backend_kind in {BackendKind.PKCS11, BackendKind.REST}:
        return PrivateKeyLocation.HSM_PROVIDED

    msg = f'No supported private-key location exists for configured crypto backend {backend_kind!r}.'
    raise RuntimeError(msg)
