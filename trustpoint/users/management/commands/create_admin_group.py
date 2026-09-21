# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to create the default Admin role group."""

from django.contrib.auth.models import Group
from django.core.management import BaseCommand

from users.models import BuiltinRole, GroupProfile


class Command(BaseCommand):
    """Create built-in role groups and their GroupProfiles if they do not exist."""

    help = 'Creates the built-in Admin and Service Account role groups and GroupProfiles.'

    def handle(self, *_args: object, **_options: object) -> None:
        """Execute the command."""
        group, created = Group.objects.get_or_create(name=BuiltinRole.ADMIN.value)
        GroupProfile.objects.get_or_create(
            group=group,
            defaults={'grants_staff': True, 'grants_superuser': True},
        )
        service_group = BuiltinRole.get_service_group()
        # BuiltinRole.get_service_group() returns a saved instance, so this is always False.
        # Left as is here; changing it would alter what the command prints.
        service_created = service_group._state.adding  # noqa: SLF001
        GroupProfile.objects.get_or_create(
            group=service_group,
            defaults={'grants_staff': False, 'grants_superuser': False},
        )
        if created:
            self.stdout.write('Admin group created.')
        else:
            self.stdout.write('Admin group already exists.')
        if service_created:
            self.stdout.write('Service Account group created.')
        else:
            self.stdout.write('Service Account group already exists.')
