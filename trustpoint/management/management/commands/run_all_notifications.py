"""Django management command to run all notification-related checks sequentially."""

from __future__ import annotations

from typing import Any

from django.core.management import CommandError, call_command
from django.core.management.base import BaseCommand

from management.models import NotificationConfig


class Command(BaseCommand):
    """A Django management command to run all notification-related commands in sequence."""

    help = 'Run all notification-related commands sequentially if notifications are enabled.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        notification_config = NotificationConfig.get()

        if not notification_config.enabled:
            self.stdout.write(
                self.style.WARNING('Notifications are disabled. Enable them in Management > Settings.')
            )
            return

        commands_to_run = [
            'trustpoint_setup_notifications',
            'check_system_health',
            'check_for_security_vulnerabilities',
            'check_certificate_validity',
            'check_issuing_ca_validity',
            'check_crl_validity',
            'check_domain_issuing_ca',
            'check_non_onboarded_devices',
            'check_onboarding_failed_devices',
            'check_revoked_device_certificates',
            'check_for_not_permitted_signature_algorithms',
            'check_for_insufficient_key_length',
            'check_for_not_permitted_ecc_curves',
            'check_gds_push_failures',
            'check_signer_key_validity',
            'check_tls_certificate_validity',
        ]

        failed_commands = []

        for command in commands_to_run:
            self.stdout.write(self.style.NOTICE(f'Running {command}...'))
            try:
                call_command(command)
                self.stdout.write(self.style.SUCCESS(f'Successfully completed {command}.'))
            except CommandError:
                self.stdout.write(self.style.ERROR(f'CommandError while running {command}'))
                failed_commands.append(command)
            except Exception:
                self.stdout.write(self.style.ERROR(f'Unexpected error while running {command}'))
                failed_commands.append(command)

        if failed_commands:
            self.stdout.write(
                self.style.ERROR(f'Failed commands: {", ".join(failed_commands)}')
            )
        else:
            self.stdout.write(self.style.SUCCESS('All notification checks completed successfully.'))
