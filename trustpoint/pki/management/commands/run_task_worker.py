"""Management command to run a background task worker for CRL generation."""

from __future__ import annotations

import time

from django.core.management.base import BaseCommand
from django.utils import timezone
from django.utils.translation import gettext as _


class Command(BaseCommand):
    """Management command to run a continuous background worker for CRL tasks."""

    help = _('Run a background worker that processes pending CRL generation tasks')

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            '--interval',
            type=int,
            default=60,
            help=_('Check interval in seconds (default: 60)'),
        )

    def handle(self, *args, **options):
        """Execute the command."""
        from pki.models import CaModel  # noqa: PLC0415

        interval = options['interval']
        self.stdout.write(
            self.style.SUCCESS(f'Starting CRL task worker (checking every {interval} seconds)...')
        )
        self.stdout.write('Press Ctrl+C to stop')

        try:
            while True:
                try:
                    now = timezone.now()
                    cas_to_process = CaModel.objects.filter(
                        crl_cycle_enabled=True,
                        last_crl_generation_started_at__lte=now
                    ).exclude(last_crl_generation_started_at__isnull=True)

                    if cas_to_process.exists():
                        self.stdout.write(
                            f'[{now.strftime("%Y-%m-%d %H:%M:%S")}] '
                            f'Processing {cas_to_process.count()} pending CRL generation(s)'
                        )

                        for ca in cas_to_process:
                            try:
                                self.stdout.write(f'  Generating CRL for CA: {ca.unique_name}')
                                success = ca.issue_crl(crl_validity_hours=int(ca.crl_validity_hours))
                                if success:
                                    self.stdout.write(self.style.SUCCESS(f'  ✓ {ca.unique_name}'))
                                    # Schedule the next generation
                                    ca.schedule_next_crl_generation()
                                else:
                                    self.stdout.write(
                                        self.style.WARNING(f'  ⚠ Failed: {ca.unique_name}')
                                    )
                            except Exception as exc:
                                self.stdout.write(
                                    self.style.ERROR(f'  ✗ Error for {ca.unique_name}: {exc}')
                                )
                    else:
                        # No pending tasks
                        pass

                    time.sleep(interval)

                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    self.stdout.write(
                        self.style.ERROR(f'Error in worker loop: {exc}')
                    )
                    time.sleep(interval)

        except KeyboardInterrupt:
            self.stdout.write('\n')
            self.stdout.write(self.style.SUCCESS('Task worker stopped'))
