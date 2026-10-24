# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for backend configuration shared by both setup paths."""

from unittest.mock import patch

import pytest

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel, AppSecretPkcs11ConfigModel
from crypto.models import BackendKind, CryptoProviderPkcs11ConfigModel, CryptoProviderProfileModel
from management.management.commands.apply_bootstrap_config import OperationalBootstrapApplier
from setup_wizard.views import FreshInstallSummaryView


@pytest.mark.parametrize('consumer', [FreshInstallSummaryView, OperationalBootstrapApplier])
@pytest.mark.parametrize('changed_runtime', [False, True])
def test_pkcs11_configuration_preserves_or_resets_wrapped_keys(consumer, changed_runtime):
    """Both setup paths keep existing keys unless the token connection settings change."""
    profile = CryptoProviderProfileModel.objects.create(name='pkcs11', backend_kind=BackendKind.PKCS11, active=True)
    CryptoProviderPkcs11ConfigModel.objects.create(
        profile=profile,
        module_path='/tmp/pkcs11.so',
        token_label='token',
        auth_source='env',
        auth_source_ref='TEST_PKCS11_PIN',
    )
    backend = AppSecretBackendModel.get_singleton()
    backend.backend_kind = AppSecretBackendKind.PKCS11
    backend.save()
    secret_config = AppSecretPkcs11ConfigModel.objects.create(
        backend=backend,
        module_path='/tmp/pkcs11.so',
        token_label='old-token' if changed_runtime else 'token',
        auth_source='env',
        auth_source_ref='TEST_PKCS11_PIN',
        wrapped_dek=b'wrapped',
        backup_encrypted_dek=b'backup',
    )

    with patch('setup_wizard.backend_configuration.get_app_secret_service') as service:
        consumer._configure_pkcs11_app_secret_backend()
        service.return_value.ensure_backend_ready.assert_called_once()

    secret_config.refresh_from_db()
    assert secret_config.token_label == 'token'
    assert secret_config.wrapped_dek == (None if changed_runtime else b'wrapped')
    assert secret_config.backup_encrypted_dek == (None if changed_runtime else b'backup')
