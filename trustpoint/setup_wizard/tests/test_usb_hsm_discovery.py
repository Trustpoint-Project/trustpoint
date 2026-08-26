# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for shared setup-wizard USB HSM discovery."""

from __future__ import annotations

import json
import subprocess
from http import HTTPStatus
from typing import TYPE_CHECKING
from unittest.mock import patch

from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase, override_settings

from crypto.adapters.pkcs11.discovery import DiscoveredPkcs11Token
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.views import (
    USB_HSM_DISCOVERY_SESSION_KEY,
    configure_wizard_usb_hsm,
    discover_usb_hsms_isolated,
    handle_usb_hsm_wizard_action,
    probe_staged_pkcs11_config_isolated,
)

if TYPE_CHECKING:
    from django.http import HttpRequest


def _request_with_session(action: str) -> HttpRequest:
    request = RequestFactory().post('/', {'wizard_action': action})
    SessionMiddleware(lambda _request: None).process_request(request)
    request.session.save()
    request._messages = FallbackStorage(request)  # noqa: SLF001 - Django test request setup.
    return request


class UsbHsmDiscoveryTests(TestCase):
    """Exercise discovery state shared by fresh install, attach, and restore."""

    @override_settings(HSM_OPENSC_PKCS11_MODULE_PATH='/usr/lib/opensc-pkcs11.so')
    def test_configure_wizard_usb_hsm_persists_stable_token_selectors(self) -> None:
        """Selecting a discovered token persists its stable PKCS#11 identity."""
        slot_id = 4
        config_model = SetupWizardConfigModel.get_singleton()
        token = DiscoveredPkcs11Token(slot_id, 'USB HSM', 'serial-1', 'model', 'vendor')

        configure_wizard_usb_hsm(config_model, token=token)

        config_model.refresh_from_db()
        assert config_model.fresh_install_pkcs11_module_path == '/usr/lib/opensc-pkcs11.so'
        assert config_model.fresh_install_pkcs11_token_label == 'USB HSM'  # noqa: S105
        assert config_model.fresh_install_pkcs11_token_serial == 'serial-1'  # noqa: S105
        assert config_model.fresh_install_pkcs11_slot_id == slot_id
        assert config_model.fresh_install_pkcs11_config_path == ''
        assert config_model.fresh_install_pkcs11_config_env_var == ''

    @override_settings(
        ROOT_URLCONF='trustpoint.urls_bootstrap',
        HSM_OPENSC_PKCS11_MODULE_PATH='/usr/lib/opensc-pkcs11.so',
    )
    def test_single_discovered_token_is_selected_for_every_setup_flow(self) -> None:
        """Fresh setup, attachment, and restore share discovery and selection."""
        redirect_names = (
            'setup_wizard:fresh_install_backend_config',
            'setup_wizard:connect_existing_backend_config',
            'setup_wizard:restore_backup_backend_config',
        )
        for redirect_name in redirect_names:
            with self.subTest(redirect_name=redirect_name):
                config_model = SetupWizardConfigModel.get_singleton()
                request = _request_with_session('discover_usb_hsm')
                result = {
                    'status': 'found',
                    'detail': 'Discovered 1 USB HSM token.',
                    'tokens': [DiscoveredPkcs11Token(2, 'USB HSM', 'serial', 'model', 'vendor').to_json_dict()],
                }

                with patch('setup_wizard.views.discover_usb_hsms_isolated', return_value=result):
                    response = handle_usb_hsm_wizard_action(
                        request,
                        config_model=config_model,
                        redirect_name=redirect_name,
                    )

                assert response is not None
                assert response.status_code == HTTPStatus.FOUND
                config_model.refresh_from_db()
                assert config_model.fresh_install_pkcs11_token_serial == 'serial'  # noqa: S105
                assert request.session[USB_HSM_DISCOVERY_SESSION_KEY]['selected_index'] == 0

    @override_settings(HSM_OPENSC_PKCS11_MODULE_PATH='/usr/lib/opensc-pkcs11.so')
    def test_discovery_reports_missing_usb_passthrough_without_starting_pcscd(self) -> None:
        """Missing container USB access yields guidance without starting pcscd."""
        with (
            patch('setup_wizard.views.Path.is_dir', return_value=False),
            patch('setup_wizard.views.execute_shell_script') as execute_script,
        ):
            result = discover_usb_hsms_isolated()

        assert result['status'] == 'unavailable'
        assert '/dev/bus/usb' in result['detail']
        execute_script.assert_not_called()

    @override_settings(HSM_OPENSC_PKCS11_MODULE_PATH='/usr/lib/opensc-pkcs11.so')
    def test_discovery_starts_pcscd_and_parses_isolated_command_output(self) -> None:
        """Discovery starts the service and accepts isolated JSON output."""
        token = DiscoveredPkcs11Token(1, 'USB HSM', 'serial', 'model', 'vendor')
        completed = subprocess.CompletedProcess(
            args=['manage.py'],
            returncode=0,
            stdout=json.dumps({'tokens': [token.to_json_dict()]}) + '\n',
            stderr='',
        )
        with (
            patch('setup_wizard.views.Path.is_dir', return_value=True),
            patch('setup_wizard.views.Path.is_file', return_value=True),
            patch('setup_wizard.views.execute_shell_script') as execute_script,
            patch('setup_wizard.views.subprocess.run', return_value=completed),
        ):
            result = discover_usb_hsms_isolated()

        assert result['status'] == 'found'
        assert result['tokens'][0]['serial'] == 'serial'
        execute_script.assert_called_once()

    @override_settings(HSM_OPENSC_PKCS11_MODULE_PATH='/usr/lib/opensc-pkcs11.so')
    def test_discovery_timeout_is_reported_to_the_wizard(self) -> None:
        """A blocked native provider does not hold the web request indefinitely."""
        with (
            patch('setup_wizard.views.Path.is_dir', return_value=True),
            patch('setup_wizard.views.Path.is_file', return_value=True),
            patch('setup_wizard.views.execute_shell_script'),
            patch('setup_wizard.views.subprocess.run', side_effect=subprocess.TimeoutExpired('probe', 20)),
        ):
            result = discover_usb_hsms_isolated()

        assert result['status'] == 'error'
        assert 'timed out' in result['detail']

    @override_settings(HSM_OPENSC_PKCS11_MODULE_PATH='/usr/lib/opensc-pkcs11.so')
    def test_shared_backend_template_renders_usb_network_and_policy_controls(self) -> None:
        """The shared template keeps fresh, attach, and restore controls aligned."""
        config_model = SetupWizardConfigModel.get_singleton()
        config_model.crypto_storage = SetupWizardConfigModel.CryptoStorageType.HsmStorage
        config_model.save(update_fields=['crypto_storage'])

        from setup_wizard.forms import FreshInstallBackendConfigModelForm  # noqa: PLC0415

        html = render_to_string(
            'setup_wizard/includes/pkcs11_backend_config.html',
            {'form': FreshInstallBackendConfigModelForm(instance=config_model)},
        )

        assert 'Discover USB HSM' in html
        assert 'Network HSM' in html
        assert 'fresh_install_pkcs11_enforce_app_secret_protection' in html

    def test_isolated_probe_prepares_runtime_even_when_test_button_was_skipped(self) -> None:
        """Summary probes work in fresh, attach, and restore flows without an earlier manual test."""
        config_model = SetupWizardConfigModel.get_singleton()
        completed = subprocess.CompletedProcess(
            args=['manage.py'],
            returncode=0,
            stdout='{}\n',
            stderr='',
        )
        with (
            patch('setup_wizard.views.configure_pkcs11_runtime_services') as configure_services,
            patch('setup_wizard.views.subprocess.run', return_value=completed),
            patch('setup_wizard.views.Pkcs11Capabilities.from_json_dict', return_value=object()),
        ):
            capabilities = probe_staged_pkcs11_config_isolated(config_model, profile_name='summary-probe')

        assert capabilities is not None
        configure_services.assert_called_once_with(config_model)
