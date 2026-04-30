"""Local sqlite defaults for Trustpoint's software demo/testing backend.

The setup wizard remains the source of truth for Docker and production-like
runtime handoff. This module fills the local sqlite gap with the same software
backend that the setup wizard can explicitly apply for non-production container
setups.
"""

from __future__ import annotations

import os
from typing import Final

from django.conf import settings
from django.db import transaction

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

LOCAL_DEVELOPMENT_DEK_LENGTH_BYTES: Final[int] = 32


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

    with transaction.atomic():
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

    raw_dek = (
        AppSecretSoftwareConfigModel.objects.filter(backend=backend)
        .values_list('raw_dek', flat=True)
        .first()
    )
    return len(bytes(raw_dek or b'')) == LOCAL_DEVELOPMENT_DEK_LENGTH_BYTES


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
        'encryption_source_ref': None,
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

    config, _created = AppSecretSoftwareConfigModel.objects.get_or_create(backend=backend)
    raw_dek = bytes(config.raw_dek or b'')
    if len(raw_dek) == LOCAL_DEVELOPMENT_DEK_LENGTH_BYTES:
        return

    config.raw_dek = os.urandom(LOCAL_DEVELOPMENT_DEK_LENGTH_BYTES)
    config.full_clean()
    config.save(update_fields=['raw_dek'])
