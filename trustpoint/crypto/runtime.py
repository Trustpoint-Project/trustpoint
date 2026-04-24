"""Runtime helpers for the configured Trustpoint crypto backend."""

from __future__ import annotations

from django.core.exceptions import ObjectDoesNotExist
from trustpoint_core.serializer import PrivateKeyLocation

from crypto.models import BackendKind, CryptoProviderPkcs11ConfigModel, CryptoProviderProfileModel


def get_configured_profile() -> CryptoProviderProfileModel | None:
    """Return the active configured crypto profile, if any."""
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


def is_hsm_backend_configured() -> bool:
    """Return whether the configured instance backend is PKCS#11."""
    return configured_backend_kind() == BackendKind.PKCS11


def configured_private_key_location() -> PrivateKeyLocation:
    """Map the configured backend kind to the application-facing private-key location."""
    if is_hsm_backend_configured():
        return PrivateKeyLocation.HSM_PROVIDED
    return PrivateKeyLocation.SOFTWARE


def require_active_pkcs11_config() -> CryptoProviderPkcs11ConfigModel:
    """Return the configured PKCS#11 backend config or raise."""
    profile = require_configured_profile()
    if profile.backend_kind != BackendKind.PKCS11:
        msg = f'The configured crypto backend is {profile.backend_kind!r}, not PKCS#11.'
        raise RuntimeError(msg)
    try:
        return profile.pkcs11_config
    except ObjectDoesNotExist as exc:
        msg = f'The configured PKCS#11 backend profile {profile.name!r} is missing its PKCS#11 config.'
        raise RuntimeError(msg) from exc
