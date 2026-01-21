"""Django management command for issuing CRLs to all issuing CAs."""

from __future__ import annotations

from django.core.management.base import BaseCommand
from pki.models import CaModel

from trustpoint.logger import LoggerMixin


class Command(BaseCommand, LoggerMixin):
    """Issues CRLs to all issuing CAs in the database."""

    help = 'Issues CRLs to all issuing CAs in the database.'

    def log_and_stdout(self, message: str, level: str = 'info') -> None:
        """Log a message and write it to stdout.

        Parameters
        ----------
        message : str
            The message to log and print.
        level : str
            The logging level ('info', 'warning', 'error', etc.).
        """
        # Log the message
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(message)

        # Write to stdout
        if level == 'error':
            self.stdout.write(self.style.ERROR(message))
        elif level == 'warning':
            self.stdout.write(self.style.WARNING(message))
        elif level == 'info':
            self.stdout.write(self.style.SUCCESS(message))
        else:
            self.stdout.write(message)

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Issues CRLs to all issuing CAs."""
        issuing_cas = CaModel.objects.filter(ca_type__isnull=False)
        if not issuing_cas.exists():
            self.log_and_stdout('No issuing CAs found in the database.', level='warning')
            return

        self.log_and_stdout(f'Found {issuing_cas.count()} issuing CA(s). Issuing CRLs...')

        success_count = 0
        for ca in issuing_cas:
            if ca.issue_crl():
                self.log_and_stdout(f'CRL issued successfully for CA: {ca.unique_name}')
                success_count += 1
            else:
                self.log_and_stdout(f'Failed to issue CRL for CA: {ca.unique_name}', level='error')

        self.log_and_stdout(f'CRL issuance completed. {success_count}/{issuing_cas.count()} CAs updated.')
