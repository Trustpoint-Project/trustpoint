# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Local-only KEK provisioning must never replace an initialized installation's key."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel, AppSecretSoftwareConfigModel
from appsecrets.service import (
    AppSecretConfigurationError,
    SoftwareAppSecretService,
    clear_app_secret_cache,
    load_software_kek,
)
from trustpoint.secret_key import development_software_kek

pytestmark = pytest.mark.django_db


@pytest.fixture
def development_backend(settings, monkeypatch, tmp_path):
    settings.DEBUG = True
    settings.DOCKER_CONTAINER = False
    settings.REPO_ROOT = tmp_path
    monkeypatch.delenv('TRUSTPOINT_SOFTWARE_KEK_FILE', raising=False)
    AppSecretBackendModel.objects.all().delete()
    backend = AppSecretBackendModel.objects.create(backend_kind=AppSecretBackendKind.SOFTWARE)
    config = AppSecretSoftwareConfigModel.objects.create(backend=backend)
    path = tmp_path / 'var/development/software_kek'
    return SoftwareAppSecretService(config), path


def test_fresh_development_backend_creates_private_persistent_kek(development_backend):
    service, path = development_backend
    ciphertext = service.encrypt_text('local field')
    original = path.read_bytes()
    assert len(original) == 64 and len(bytes.fromhex(original.decode())) == 32
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    clear_app_secret_cache()
    restarted = SoftwareAppSecretService(AppSecretSoftwareConfigModel.objects.get())
    assert restarted.decrypt_text(ciphertext) == 'local field'
    assert path.read_bytes() == original


@pytest.mark.parametrize('clear_cache', [False, True])
def test_missing_initialized_development_kek_is_not_replaced(development_backend, clear_cache):
    service, path = development_backend
    service.require_dek()
    original = bytes(AppSecretSoftwareConfigModel.objects.get().wrapped_dek)
    path.unlink()
    if clear_cache:
        clear_app_secret_cache()
    with pytest.raises(AppSecretConfigurationError, match='cannot be read'):
        service.require_dek()
    assert not path.exists()
    assert bytes(AppSecretSoftwareConfigModel.objects.get().wrapped_dek) == original


def test_lost_wrapped_dek_and_kek_are_not_recreated(development_backend):
    service, path = development_backend
    service.require_dek()
    path.unlink()
    AppSecretSoftwareConfigModel.objects.update(wrapped_dek=None)
    with pytest.raises(AppSecretConfigurationError, match='DEK is missing'):
        service.require_dek()
    assert not path.exists()
    assert AppSecretSoftwareConfigModel.objects.get().wrapped_dek is None


def test_wrapped_dek_without_marker_cannot_create_development_kek(development_backend):
    service, path = development_backend
    AppSecretSoftwareConfigModel.objects.update(wrapped_dek=b'inconsistent-envelope')
    with pytest.raises(AppSecretConfigurationError, match='initialization marker'):
        service.require_dek()
    assert not path.exists()


@pytest.mark.parametrize('value', ['', 'malformed', 'ab' * 32 + '\n'])
def test_invalid_existing_development_file_is_preserved(development_backend, value):
    service, path = development_backend
    path.parent.mkdir(parents=True)
    path.write_text(value)
    with pytest.raises(AppSecretConfigurationError, match='64 hexadecimal'):
        service.require_dek()
    assert path.read_text() == value
    assert not AppSecretBackendModel.objects.get().dek_initialized


def test_explicit_kek_file_always_takes_precedence(development_backend, monkeypatch, tmp_path):
    service, default = development_backend
    selected = tmp_path / 'configured-kek'
    monkeypatch.setenv('TRUSTPOINT_SOFTWARE_KEK_FILE', str(selected))
    with pytest.raises(AppSecretConfigurationError, match='cannot be read'):
        service.require_dek()
    assert not default.exists() and not selected.exists()
    selected.write_text('ab' * 32)
    assert len(service.require_dek()) == 32
    assert not default.exists()


@pytest.mark.parametrize('debug,docker', [(False, False), (False, True), (True, True)])
def test_production_and_docker_never_generate_a_kek(development_backend, settings, debug, docker):
    _, path = development_backend
    settings.DEBUG = debug
    settings.DOCKER_CONTAINER = docker
    with (
        patch('appsecrets.service.Path.open', side_effect=FileNotFoundError),
        patch('appsecrets.service.development_software_kek') as helper,
    ):
        with pytest.raises(AppSecretConfigurationError, match='cannot be read'):
            load_software_kek(allow_development_creation=True)
    helper.assert_not_called()
    assert not path.exists()


def test_reading_development_key_does_not_initialize_it(development_backend):
    _, path = development_backend
    with pytest.raises(AppSecretConfigurationError, match='cannot be read'):
        load_software_kek()
    assert not path.parent.exists()


def test_parallel_file_creation_preserves_one_private_key(tmp_path):
    path = tmp_path / 'development/software_kek'
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: development_software_kek(path, allow_creation=True).read_bytes(), range(12)))
    assert all(value == results[0] for value in results)
    assert len(bytes.fromhex(results[0].decode())) == 32
    assert path.stat().st_mode & 0o777 == 0o600
    assert list(path.parent.glob('.development-key-*')) == []


def test_development_symlink_is_rejected(tmp_path):
    source = tmp_path / 'source'
    source.write_text('ab' * 32)
    path = tmp_path / 'software_kek'
    path.symlink_to(source)
    with pytest.raises(ImproperlyConfigured, match='symlinks'):
        development_software_kek(path, allow_creation=True)
    assert source.read_text() == 'ab' * 32


def test_completed_installation_cannot_generate_a_development_kek(development_backend):
    from django.utils import timezone

    from setup_wizard.models import SetupWizardCompletedModel

    service, path = development_backend
    SetupWizardCompletedModel.objects.create(setup_completed_at=timezone.now())
    with pytest.raises(AppSecretConfigurationError, match='DEK is missing'):
        service.require_dek()
    assert not path.exists()
