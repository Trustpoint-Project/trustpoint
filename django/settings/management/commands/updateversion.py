"""This module defines a Django management command to delete all existing notifications."""

from typing import Any

from django.conf import settings as django_settings
from django.core.management.base import BaseCommand
from django.db.utils import ProgrammingError
from settings.models import AppVersion

from trustpoint.settings import DOCKER_CONTAINER


class Command(BaseCommand):
    """A Django management command to delete all existing notifications.

    If running inside a Docker container, the command deletes notifications
    without user confirmation. Otherwise, it prompts the user for confirmation.
    """

    help = 'Updates app version'

    def handle(self, **options: Any) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            **options: A variable-length argument.
        """
        self.update_app_version()

    def update_app_version(self) -> None:
            """Update app version if pyproject.toml is different than verison in db."""
            current = django_settings.APP_VERSION

            qs = AppVersion.objects.all()

            try:
                if not qs.exists():
                    AppVersion.objects.create(version=current)
                    msg = f'Version {current} successfully initalized.'
                    self.stdout.write(self.style.SUCCESS(msg))
                else:
                    obj = qs.first()
                    if obj and obj.version != current:
                        old_version= obj.version
                        obj.version = current
                        obj.save()
                        msg = f'Trustpoint Version updated from {old_version} to {current}.'
                        self.stdout.write(self.style.SUCCESS(msg))
            except ProgrammingError:
                self.stdout.write(self.style.ERROR('appversion table not found. DB probably not initalized'))
                return
