from django.core.management.base import BaseCommand


class Command(BaseCommand):
    """A Django management command to check and update the Trustpoint version."""

    help = 'Updates app version'

    def handle(self, **_options: dict[str, str]) -> None:
        """Entrypoint for the command."""
        self.update_version()

    def update_version(self) -> None:
        """Update app version if pyproject.toml is different than version in db."""
        # @TODO(Aircoookie)
