from typing import Any

from django.conf import settings as django_settings
from django.core.management.base import BaseCommand
from django.db.models.signals import post_migrate
from django.db.utils import OperationalError, ProgrammingError
from django.utils.translation import gettext as _
from settings.models import AppVersion


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def handle(self, **_options: Any) -> None:
        """Entrypoint for the command."""
        self.update_app_version()

    def update_app_version(self) -> None:
        """Update app version if pyproject.toml is different than version in db."""
        current = django_settings.APP_VERSION
        try:
            app_version = AppVersion.objects.first()

            if not app_version:
                AppVersion.objects.create(version=current)
                msg = _('Version %s successfully initialized.') % current
                self.stdout.write(self.style.SUCCESS(msg))

            elif app_version.version != current:
                old_version = app_version.version
                app_version.version = current
                app_version.save()
                msg = _('Trustpoint version updated from %s to %s') % (old_version, current)
                self.stdout.write(self.style.SUCCESS(msg))

            else:
                msg = _('Version %s is already set; no changes necessary.') % current
                self.stdout.write(self.style.WARNING(msg))

        except (ProgrammingError, OperationalError):
            error_msg = _('Appversion table not found. DB probably not initialized')
            self.stdout.write(self.style.ERROR(error_msg))
            # Connect a receiver that matches Django signal signature
            post_migrate.connect(self.handle_post_migrate, weak=False)

    def handle_post_migrate(self, _sender: Any, **_kwargs: Any) -> None:
        """Signal receiver to run update_app_version after migrations."""
        # Disconnect to avoid repeated calls
        post_migrate.disconnect(self.handle_post_migrate)
        # Retry update
        self.update_app_version()
