# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Focused tests for bootstrap runtime service selection."""

from unittest.mock import patch

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
