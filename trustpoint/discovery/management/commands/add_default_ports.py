"""Management command to add default discovery ports."""

from django.core.management.base import BaseCommand

from discovery.models import DiscoveryPort


class Command(BaseCommand):
    """Add default ports (HTTP, HTTPS, OPC UA) to the DiscoveryPort model."""

    help = "Add default discovery ports to the database"

    def handle(self, *args: tuple, **options: dict) -> None:
        """
        Execute the command to add default ports.

        :param args: Positional arguments (unused).
        :param options: Command options (unused).
        """
        defaults = [(80, "HTTP"), (443, "HTTPS"), (4840, "OPC UA")]

        for port, desc in defaults:
            port_obj, created = DiscoveryPort.objects.get_or_create(
                port_number=port, defaults={"description": desc}
            )
            status = "Created" if created else "Already exists"
            self.stdout.write(
                self.style.SUCCESS(
                    f"{status}: Port {port} ({desc})"
                )
            )
