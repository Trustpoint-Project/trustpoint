"""Django management command for creating default organization."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from management.models.organization import OrganizationModel


class Command(BaseCommand):
    """Creates default organization."""

    help = 'Creates default organization.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Creates default organization."""
        name = 'trustpoint'
        _obj, created = OrganizationModel.objects.get_or_create(pk=1, name=name, organization=name)

        if created:
             self.stdout.write(f'Created organization: {name}')
        else:
             self.stdout.write(f'Organization already exists: {name}')
