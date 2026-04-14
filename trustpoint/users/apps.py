"""Django apps module which defines the app configuration."""

from django.apps import AppConfig
from django.db.models.signals import post_migrate


def _seed_groups(sender: AppConfig, **kwargs: object) -> None:  # noqa: ARG001
    """Seed built-in role groups and GroupProfiles after migrations run.

    Connected to the ``post_migrate`` signal for the ``users`` app so that
    the three predefined groups (Basic User, Advanced User, Admin) and their
    GroupProfiles always exist after any ``migrate`` call — including after
    ``reset_db`` regenerates migration files.
    """
    apps = kwargs.get('apps')
    if apps is None:
        return
    from users.initial_data import populate_groups  # noqa: PLC0415
    populate_groups(apps, None)  # type: ignore[arg-type]


class UsersConfig(AppConfig):
    """App configuration for the users app."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self) -> None:
        """Connect the post_migrate signal to seed built-in groups."""
        post_migrate.connect(_seed_groups, sender=self)
