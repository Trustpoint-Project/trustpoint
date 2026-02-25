"""Management command to generate CRLs for CAs with enabled cycles."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import gettext as _

from pki.models import CaModel
from pki.tasks import generate_crl_for_ca


class Command(BaseCommand):
    """Management command to trigger CRL generation for CAs with enabled cycles."""

    help = _('Generate CRLs for all CAs with enabled CRL cycle updates')

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            '--ca-id',
            type=int,
            help=_('Generate CRL only for the CA with the specified ID'),
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help=_('Generate CRLs for all CAs with enabled cycles'),
        )

    def handle(self, *args, **options):
        """Execute the command."""
        ca_id = options.get('ca_id')
        all_cas = options.get('all', False)

        if ca_id:
            self._generate_crl_for_ca(ca_id)
        elif all_cas:
            self._generate_crls_for_all_enabled()
        else:
            self.stdout.write(
                self.style.WARNING(
                    _('Please specify --ca-id <id> or --all')
                )
            )

    def _generate_crl_for_ca(self, ca_id: int) -> None:
        """Generate CRL for a specific CA."""
        try:
            ca = CaModel.objects.get(pk=ca_id)
            self.stdout.write(f'Generating CRL for CA: {ca.unique_name}')
            generate_crl_for_ca(ca_id)
            self.stdout.write(
                self.style.SUCCESS(f'CRL generated successfully for CA: {ca.unique_name}')
            )
        except CaModel.DoesNotExist as exc:
            raise CommandError(f'CA with ID {ca_id} does not exist') from exc
        except Exception as exc:
            raise CommandError(f'Failed to generate CRL for CA {ca_id}: {exc}') from exc

    def _generate_crls_for_all_enabled(self) -> None:
        """Generate CRLs for all CAs with enabled cycles."""
        cas = CaModel.objects.filter(crl_cycle_enabled=True)

        if not cas.exists():
            self.stdout.write(
                self.style.WARNING(_('No CAs with enabled CRL cycles found'))
            )
            return

        self.stdout.write(f'Found {cas.count()} CA(s) with enabled CRL cycles')

        for ca in cas:
            try:
                self.stdout.write(f'Generating CRL for CA: {ca.unique_name}')
                generate_crl_for_ca(ca.id)
                self.stdout.write(
                    self.style.SUCCESS(f'✓ {ca.unique_name}')
                )
            except Exception as exc:
                self.stdout.write(
                    self.style.ERROR(f'✗ {ca.unique_name}: {exc}')
                )
