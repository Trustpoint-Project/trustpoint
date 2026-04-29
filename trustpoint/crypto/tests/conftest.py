"""Shared pytest fixtures for crypto tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import transaction

from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.domain.errors import (
    AuthenticationError,
    ProviderConfigurationError,
    ProviderUnavailableError,
    SessionUnavailableError,
)
from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    Pkcs11AuthSource,
)


def _read_text_file(path: Path) -> str | None:
    """Read a small text file and return stripped content or None."""
    try:
        value = path.read_text(encoding='utf-8').strip()
    except OSError:
        return None
    return value or None


def _path_exists(path: Path) -> bool:
    """Return whether a local HSM path is readable and exists."""
    try:
        return path.exists()
    except OSError:
        return False


def _ensure_pytest_local_hsm_profile() -> tuple[CryptoProviderProfileModel | None, str | None]:
    """Ensure the pytest DB contains a usable local-dev PKCS#11 provider profile."""
    preferred_names = (
        'local-dev-softhsm',
        'pytest-local-dev-pkcs11',
    )

    for name in preferred_names:
        profile = (
            CryptoProviderProfileModel.objects.select_related('pkcs11_config')
            .filter(name=name, backend_kind=BackendKind.PKCS11)
            .first()
        )
        if profile is not None:
            return profile, None

    existing_active = (
        CryptoProviderProfileModel.objects.select_related('pkcs11_config')
        .filter(active=True, backend_kind=BackendKind.PKCS11)
        .order_by('id')
        .first()
    )
    if existing_active is not None:
        return existing_active, None

    existing_any = (
        CryptoProviderProfileModel.objects.select_related('pkcs11_config')
        .filter(backend_kind=BackendKind.PKCS11)
        .order_by('id')
        .first()
    )
    if existing_any is not None:
        return existing_any, None

    module_path = Path(settings.HSM_DEFAULT_PKCS11_MODULE_PATH)
    if not _path_exists(module_path):
        return None, f'PKCS#11 module path does not exist or is not readable: {module_path}'

    pin_file = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
    if not _path_exists(pin_file):
        return None, f'user PIN file does not exist or is not readable: {pin_file}'

    token_serial = None
    token_serial_file = getattr(settings, 'HSM_DEFAULT_TOKEN_SERIAL_FILE', None)
    if token_serial_file is not None:
        token_serial = _read_text_file(Path(token_serial_file))

    token_label = None
    if token_serial is None:
        token_label = getattr(settings, 'HSM_DEFAULT_TOKEN_LABEL', None)

    if token_serial is None and not token_label:
        return None, (
            'no token selector available: token serial file missing/empty and '
            'HSM_DEFAULT_TOKEN_LABEL is not set'
        )

    with transaction.atomic():
        CryptoProviderProfileModel.objects.filter(active=True).update(active=False)

        profile_model, _ = CryptoProviderProfileModel.objects.update_or_create(
            name='pytest-local-dev-pkcs11',
            defaults={
                'backend_kind': BackendKind.PKCS11,
                'active': True,
            },
        )

        CryptoProviderPkcs11ConfigModel.objects.update_or_create(
            profile=profile_model,
            defaults={
                'module_path': str(module_path),
                'token_serial': token_serial,
                'token_label': token_label,
                'slot_id': None,
                'auth_source': Pkcs11AuthSource.FILE,
                'auth_source_ref': str(pin_file),
                'max_sessions': 4,
                'borrow_timeout_seconds': 2.0,
                'rw_sessions': True,
            },
        )

    return profile_model, None


@pytest.fixture
def live_pkcs11_backend(db):
    """Return a backend connected to a live PKCS#11 token or skip cleanly."""
    profile_model, reason = _ensure_pytest_local_hsm_profile()
    if profile_model is None:
        pytest.skip(
            'Skipping PKCS#11 integration tests: no PKCS#11 provider profile is configured '
            f'and no local-dev PKCS#11 settings could seed one ({reason}).'
        )

    try:
        config = profile_model.pkcs11_config
        profile = config.build_provider_profile()
    except (ObjectDoesNotExist, ValidationError, ProviderConfigurationError) as exc:
        pytest.skip(
            'Skipping PKCS#11 integration tests: provider profile is invalid '
            f'(profile={profile_model.name!r}, backend_kind={profile_model.backend_kind!r}, exc={exc!r}).'
        )

    backend = Pkcs11Backend(profile=profile)

    try:
        backend.refresh_capabilities()
    except (
        ProviderUnavailableError,
        AuthenticationError,
        SessionUnavailableError,
        ProviderConfigurationError,
    ) as exc:
        pytest.skip(
            'Skipping PKCS#11 integration tests: no usable HSM/token is available '
            f'(profile={profile_model.name!r}, '
            f'module_path={config.module_path!r}, '
            f'token_serial={config.token_serial!r}, '
            f'token_label={config.token_label!r}, '
            f'auth_source_ref={config.auth_source_ref!r}, '
            f'exc={exc!r}, cause={exc.__cause__!r}).'
        )

    try:
        yield backend
    finally:
        backend.close()


@pytest.fixture
def live_pkcs11_capabilities(live_pkcs11_backend: Pkcs11Backend):
    """Return the current live PKCS#11 capability snapshot."""
    current = live_pkcs11_backend.current_capabilities()
    if current is not None:
        return current
    return live_pkcs11_backend.refresh_capabilities()
