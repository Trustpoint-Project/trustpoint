# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Local sqlite defaults for Trustpoint's software demo/testing backend.

The setup wizard remains the source of truth for Docker and production-like
runtime handoff. This module fills the local sqlite gap with the same software
backend that the setup wizard can explicitly apply for non-production container
setups.
"""

from __future__ import annotations

from django.conf import settings

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretSoftwareConfigModel,
)
from crypto.models import (
    BackendKind,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    SoftwareKeyEncryptionSource,
)


def local_software_backend_auto_config_enabled() -> bool:
    """Return whether local sqlite may self-seed the software backends."""
    return bool(
        getattr(settings, 'TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND', False)
        and getattr(settings, 'TRUSTPOINT_IS_OPERATIONAL', False)
        and getattr(settings, 'DEVELOPMENT_ENV', False)
        and not getattr(settings, 'DOCKER_CONTAINER', False)
    )


def ensure_local_software_backends() -> None:
    """Create the local dev/test software backends when the environment allows it."""
    if not local_software_backend_auto_config_enabled():
        return

    if _local_software_backends_ready():
        return

    from management.security_change_audit import provider_configuration_changes  # noqa: PLC0415

    with provider_configuration_changes(actor=None):
        if _local_software_backends_ready():
            return
        if _ensure_crypto_software_backend():
            _ensure_app_secret_software_backend()


def _local_software_backends_ready() -> bool:
    """Return whether local software crypto and app-secret backends are already usable."""
    active_profile = CryptoProviderProfileModel.objects.filter(active=True).first()
    if active_profile is None or active_profile.backend_kind != BackendKind.SOFTWARE:
        return False

    software_config = CryptoProviderSoftwareConfigModel.objects.filter(profile=active_profile).first()
    if software_config is None:
        return False
    source_requires_ref = software_config.encryption_source in {
        SoftwareKeyEncryptionSource.ENV,
        SoftwareKeyEncryptionSource.FILE,
    }
    if source_requires_ref and not (software_config.encryption_source_ref or '').strip():
        return False

    backend = AppSecretBackendModel.objects.filter(
        singleton_id=AppSecretBackendModel.SINGLETON_ID,
        backend_kind=AppSecretBackendKind.SOFTWARE,
    ).first()
    if backend is None:
        return False

    return AppSecretSoftwareConfigModel.objects.filter(backend=backend, wrapped_dek__isnull=False).exists()



def _ensure_crypto_software_backend() -> bool:
    """Ensure local development has an active software crypto backend."""
    active_profile = CryptoProviderProfileModel.objects.filter(active=True).first()
    if active_profile is not None:
        if active_profile.backend_kind == BackendKind.SOFTWARE:
            _ensure_software_profile_config(active_profile)
            return True
        return False

    software_profile = (
        CryptoProviderProfileModel.objects.filter(backend_kind=BackendKind.SOFTWARE)
        .order_by('id')
        .first()
    )
    if software_profile is None:
        has_other_backend_kind = CryptoProviderProfileModel.objects.exclude(
            backend_kind=BackendKind.SOFTWARE,
        ).exists()
        if has_other_backend_kind:
            return False

        profile_name = getattr(
            settings,
            'TRUSTPOINT_LOCAL_SOFTWARE_BACKEND_NAME',
            'trustpoint-software-demo-testing-backend',
        )
        software_profile = CryptoProviderProfileModel(
            name=profile_name,
            backend_kind=BackendKind.SOFTWARE,
            active=True,
        )
        software_profile.save()
    else:
        _activate_profile(software_profile)

    _ensure_software_profile_config(software_profile)
    return True


def _activate_profile(profile: CryptoProviderProfileModel) -> None:
    """Make the provided profile the active instance backend."""
    if profile.active:
        return
    CryptoProviderProfileModel.objects.filter(active=True).exclude(pk=profile.pk).update(active=False)
    profile.active = True
    profile.save(update_fields=['active', 'updated_at'])


def _ensure_software_profile_config(profile: CryptoProviderProfileModel) -> None:
    """Ensure the software crypto profile has usable local encryption material."""
    defaults = {
        'encryption_source': SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
        'encryption_source_ref': '',
        'allow_exportable_private_keys': False,
    }
    config, created = CryptoProviderSoftwareConfigModel.objects.get_or_create(
        profile=profile,
        defaults=defaults,
    )

    source_requires_ref = config.encryption_source in {
        SoftwareKeyEncryptionSource.ENV,
        SoftwareKeyEncryptionSource.FILE,
    }
    if created or (source_requires_ref and not (config.encryption_source_ref or '').strip()):
        for field_name, value in defaults.items():
            setattr(config, field_name, value)
        config.full_clean()
        config.save()


def _ensure_app_secret_software_backend() -> None:
    """Ensure local development has a usable app-secret software backend."""
    backend = AppSecretBackendModel.objects.filter(
        singleton_id=AppSecretBackendModel.SINGLETON_ID,
    ).first()
    if backend is None:
        backend = AppSecretBackendModel(
            singleton_id=AppSecretBackendModel.SINGLETON_ID,
            backend_kind=AppSecretBackendKind.SOFTWARE,
        )
        backend.save()
    elif backend.backend_kind != AppSecretBackendKind.SOFTWARE:
        return

    if backend.dek_initialized:
        return
    config, _created = AppSecretSoftwareConfigModel.objects.get_or_create(backend=backend)
    from appsecrets.service import SoftwareAppSecretService  # noqa: PLC0415

    SoftwareAppSecretService(config).ensure_backend_ready()
