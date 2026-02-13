"""Management command to print the trustpoint version."""

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """A Django management command to print the trustpoint version."""

    help = 'Prints the current Trustpoint application version.'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.stdout.write(settings.APP_VERSION)
