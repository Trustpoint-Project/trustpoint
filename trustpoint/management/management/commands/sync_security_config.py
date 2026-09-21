# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Synchronize the database security policy from the process environment."""

from django.core.management.base import BaseCommand, CommandError

from management.security_env import SecurityConfigurationError, synchronize_security_config


class Command(BaseCommand):
    """Apply the selected security preset and environment restrictions."""

    help = 'Synchronize Trustpoint security configuration from environment variables.'

    def handle(self, **_options: object) -> None:
        """Validate and persist the effective security policy."""
        try:
            applied = synchronize_security_config()
        except SecurityConfigurationError as exc:
            message = f'Invalid Trustpoint security configuration: {exc}'
            raise CommandError(message) from exc
        if applied:
            self.stdout.write(self.style.SUCCESS('Security configuration synchronized.'))
        else:
            self.stdout.write(
                self.style.WARNING(
                    'Requested security configuration rejected; existing configuration remains active.',
                )
            )
