# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the global account security policy."""

from django.test import SimpleTestCase, override_settings

from management.models import AccountSecurityConfig


class AccountSecurityConfigTest(SimpleTestCase):
    """Test account security policy retrieval."""

    @override_settings(TRUSTPOINT_IS_BOOTSTRAP=True)
    def test_get_uses_defaults_without_database_in_bootstrap(self) -> None:
        """Bootstrap mode has no management tables and must use policy defaults."""
        config = AccountSecurityConfig.get()

        assert config.pk == 1
        assert config.password_similarity
        assert config.failed_login_attempts is None
