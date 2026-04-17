"""Shared pytest fixtures for crypto tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from django.conf import settings

from crypto.adapters.pkcs11.backend import Pkcs11Backend
from crypto.domain.errors import (
    AuthenticationError,
    ProviderConfigurationError,
    ProviderUnavailableError,
    SessionUnavailableError,
)
from crypto.models import (
    CryptoProviderProfileModel,
    ProviderAuthSource,
)


def _read_text_file(path: Path) -> str | None:
    """Read a small text file and return stripped content or None."""
    try:
        value = path.read_text(encoding='utf-8').strip()
    except OSError:
        return None
    return value or None


def _ensure_pytest_local_hsm_profile() -> tuple[CryptoProviderProfileModel | None, str | None]:
    """Ensure the pytest DB contains a local-dev PKCS#11 provider profile."""
    profile_model = CryptoProviderProfileModel.objects.filter(active=True).order_by('id').first()
    if profile_model is not None:
        return profile_model, None

    profile_model = CryptoProviderProfileModel.objects.order_by('id').first()
    if profile_model is not None:
        return profile_model, None

    module_path = Path(settings.HSM_DEFAULT_PKCS11_MODULE_PATH)
    if not module_path.exists():
        return None, f'PKCS#11 module path does not exist: {module_path}'

    pin_file = Path(settings.HSM_DEFAULT_USER_PIN_FILE)
    if not pin_file.exists():
        return None, f'user PIN file does not exist: {pin_file}'

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

    profile_model, _ = CryptoProviderProfileModel.objects.update_or_create(
        name='pytest-local-dev-softhsm',
        defaults={
            'module_path': str(module_path),
            'token_serial': token_serial,
            'token_label': token_label,
            'slot_id': None,
            'auth_source': ProviderAuthSource.FILE,
            'auth_source_ref': str(pin_file),
            'max_sessions': 4,
            'borrow_timeout_seconds': 2.0,
            'rw_sessions': True,
            'allow_legacy_label_lookup': False,
            'active': True,
        },
    )
    return profile_model, None


@pytest.fixture
def live_pkcs11_backend(db):
    """Return a backend connected to a live PKCS#11 token or skip cleanly."""
    profile_model, reason = _ensure_pytest_local_hsm_profile()
    if profile_model is None:
        pytest.skip(
            'Skipping PKCS#11 integration tests: no crypto provider profile is configured '
            f'and no local-dev PKCS#11 settings could seed one ({reason}).'
        )

    try:
        profile = profile_model.build_provider_profile()
    except ProviderConfigurationError as exc:
        pytest.skip(f'Skipping PKCS#11 integration tests: provider profile is invalid ({exc}).')

    backend = Pkcs11Backend(profile=profile)

    try:
        backend.refresh_capabilities()
    except (
        ProviderUnavailableError,
        AuthenticationError,
        SessionUnavailableError,
        ProviderConfigurationError,
    ) as exc:
        pytest.skip(f'Skipping PKCS#11 integration tests: no usable HSM/token is available ({exc}).')

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
