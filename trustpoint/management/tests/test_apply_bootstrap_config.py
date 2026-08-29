# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Focused tests for bootstrap runtime service selection."""

# ruff: noqa: SLF001

from unittest.mock import MagicMock, call, patch

from management.management.commands.apply_bootstrap_config import OperationalBootstrapApplier


def test_pkcs11_runtime_services_start_pcscd_for_usb_transport() -> None:
    """USB provider choice starts pcscd independently from the module filename."""
    with patch.object(OperationalBootstrapApplier, 'execute_shell_script') as execute:
        OperationalBootstrapApplier._configure_pkcs11_runtime_services(start_pcscd=True)

    assert execute.call_args.args[-1] == 'start'


def test_pkcs11_runtime_services_stop_pcscd_for_network_transport() -> None:
    """Network providers do not keep the container smart-card service active."""
    with patch.object(OperationalBootstrapApplier, 'execute_shell_script') as execute:
        OperationalBootstrapApplier._configure_pkcs11_runtime_services(start_pcscd=False)

    assert execute.call_args.args[-1] == 'stop'


def test_apply_reports_demo_data_completion() -> None:
    """The progress protocol explicitly closes the potentially long-running demo step."""
    applier = OperationalBootstrapApplier({'fresh_install': {'inject_demo_data': True}})

    with (
        patch.object(applier, '_configure_instance_crypto_backend'),
        patch.object(applier, '_probe_and_record_crypto_capabilities'),
        patch.object(applier, '_configure_app_secret_backend'),
        patch.object(applier, '_apply_staged_tls_credential'),
        patch.object(applier, '_create_operational_admin'),
        patch('management.management.commands.apply_bootstrap_config.call_command'),
        patch('management.management.commands.apply_bootstrap_config.report_setup_apply_progress') as report,
    ):
        applier.apply()

    assert call('demo-data', 'Generating demo data and keys.', 65) in report.call_args_list
    assert call('demo-data-complete', 'Demo data and keys generated.', 75) in report.call_args_list


def test_tls_credential_is_staged_without_reloading_nginx() -> None:
    """The runtime switch owns activation so setup cannot reload nginx twice."""
    applier = OperationalBootstrapApplier({'fresh_install': {}})
    credential = MagicMock()
    credential.get_certificate.return_value.fingerprint.return_value = bytes(32)
    active_tls = MagicMock()

    with (
        patch(
            'management.management.commands.apply_bootstrap_config.load_staged_tls_credential',
            return_value=MagicMock(),
        ),
        patch(
            'management.management.commands.apply_bootstrap_config.CredentialModel.save_credential_serializer',
            return_value=credential,
        ),
        patch(
            'management.management.commands.apply_bootstrap_config.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create',
            return_value=(active_tls, True),
        ),
        patch.object(applier, '_write_pem_files') as write_pem_files,
        patch.object(applier, 'execute_shell_script') as execute_shell_script,
        patch('management.management.commands.apply_bootstrap_config.clear_staged_tls_credential'),
    ):
        applier._apply_staged_tls_credential()

    write_pem_files.assert_called_once_with(credential)
    execute_shell_script.assert_not_called()
