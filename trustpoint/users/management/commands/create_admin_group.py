"""Management command to create the default Admin role group."""

from django.contrib.auth.models import Group
from django.core.management import BaseCommand

from users.models import GroupProfile, Role


class Command(BaseCommand):
    """Creates the Admin group and its GroupProfile if they do not exist."""

    help = 'Creates the default Admin role group and GroupProfile.'

    def handle(self, *_args: object, **_options: object) -> None:
        """Execute the command."""
        group, created = Group.objects.get_or_create(name=Role.ADMIN.value)
        GroupProfile.objects.get_or_create(
            group=group,
            defaults={'grants_staff': True, 'grants_superuser': True},
        )
        if created:
            self.stdout.write('Admin group created.')
        else:
            self.stdout.write('Admin group already exists.')
