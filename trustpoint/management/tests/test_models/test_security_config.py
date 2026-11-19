# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Security mode presets must reset every policy field they advertise."""

from management.models import SecurityConfig


def test_apply_security_settings_disables_custom_device_secrets() -> None:
    """Switching to a stricter preset must not leave custom secrets enabled."""
    config = SecurityConfig(
        security_mode=SecurityConfig.SecurityModeChoices.LAB,
        allow_user_defined_device_secrets=True,
        credential_ttl_seconds=None,
    )

    config.security_mode = SecurityConfig.SecurityModeChoices.HARDENED
    config.apply_security_settings(save=False)

    assert config.allow_user_defined_device_secrets is False
    assert config.credential_ttl_seconds == 600
    config.clean()
