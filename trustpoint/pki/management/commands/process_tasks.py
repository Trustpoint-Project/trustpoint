"""Management command to process pending CRL generation tasks."""

from __future__ import annotations

from django.core.management.base import BaseCommand
from django.utils import timezone
from django.utils.translation import gettext as _


class Command(BaseCommand):
    """Management command to check and execute pending CRL generation tasks."""

    help = _('Check for scheduled CRL generations and execute them if due')

    def handle(self, *args, **options):
        """Execute the command."""
        from pki.models import CaModel  # noqa: PLC0415

        self.stdout.write('Checking for pending CRL generation tasks...')

        now = timezone.now()
        cas_to_process = CaModel.objects.filter(
            crl_cycle_enabled=True,
            last_crl_generation_started_at__lte=now
        ).exclude(last_crl_generation_started_at__isnull=True)

        if not cas_to_process.exists():
            self.stdout.write(self.style.WARNING('No CRL generation tasks are due'))
            return

        self.stdout.write(f'Found {cas_to_process.count()} CA(s) with pending CRL generation')

        for ca in cas_to_process:
            try:
                self.stdout.write(f'Generating CRL for CA: {ca.unique_name}')
                success = ca.issue_crl(crl_validity_hours=int(ca.crl_validity_hours))
                if success:
                    self.stdout.write(self.style.SUCCESS(f'✓ {ca.unique_name}'))
                    # Schedule the next generation
                    ca.schedule_next_crl_generation()
                else:
                    self.stdout.write(self.style.WARNING(f'⚠ CRL generation failed for {ca.unique_name}'))
            except Exception as exc:
                self.stdout.write(
                    self.style.ERROR(f'✗ Error processing {ca.unique_name}: {exc}')
                )

        self.stdout.write(self.style.SUCCESS('Processing completed'))

