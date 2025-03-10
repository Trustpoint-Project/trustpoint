"""This module contains a Django management command to execute all task-related notifications sequentially."""

from __future__ import annotations

from typing import Any

from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """A Django management command to run all task-related commands in sequence."""

    help = 'Run all task-related commands sequentially.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command."""
        commands_to_run = [
            'trustpoint_setup_notifications',
            'check_system_health',
            'check_for_security_vulnerabilities',
            'check_certificate_validity',
            'check_issuing_ca_validity',
            'check_domain_issuing_ca',
            'check_non_onboarded_devices',
            'check_for_weak_signature_algorithms',
            'check_for_insufficient_key_length',
            'check_for_weak_ecc_curves',
        ]

        for command in commands_to_run:
            self.stdout.write(self.style.NOTICE(f'Running {command}...'))
            try:
                call_command(command)
                self.stdout.write(self.style.SUCCESS(f'Successfully completed {command}.'))
            except CommandError as e:
                self.stdout.write(self.style.ERROR(f'CommandError while running {command}: {e}'))
            except Exception as e:  # noqa: BLE001
                self.stdout.write(self.style.ERROR(f'Unexpected error while running {command}: {e}'))

        self.stdout.write(self.style.SUCCESS('All tasks completed.'))
