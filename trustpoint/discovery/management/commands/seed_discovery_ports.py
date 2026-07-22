"""Management command to seed the discovery app with default scan ports."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from discovery.models import DiscoveryPort

DEFAULT_PORTS: list[tuple[int, str]] = [
    (80, 'HTTP'),
    (443, 'HTTPS'),
    (4840, 'OPC UA'),
]


class Command(BaseCommand):
    """Seeds the DiscoveryPort table with a default set of well-known scan ports."""

    help = 'Populate the discovery port list with default well-known ports.'

    def handle(self, *_args: tuple[Any, ...], **_kwargs: dict[str, Any]) -> None:
        """Create default discovery ports if they do not already exist."""
        created_count = 0
        for port_number, description in DEFAULT_PORTS:
            _, created = DiscoveryPort.objects.get_or_create(
                port_number=port_number,
                defaults={'description': description},
            )
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'  Created port {port_number} ({description})')
                )
                created_count += 1
            else:
                self.stdout.write(f'  Port {port_number} ({description}) already exists, skipping.')

        if created_count:
            self.stdout.write(self.style.SUCCESS(f'Done. {created_count} port(s) added.'))
        else:
            self.stdout.write(self.style.WARNING('No new ports were added (all already present).'))
