"""Management command to reset the database and migrations."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import psycopg
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import BaseCommand, call_command

if TYPE_CHECKING:
    from django.core.management.base import CommandParser


class Command(BaseCommand):
    """Management command to reset the database and migrations."""

    help = (
        'Resets the database by deleting all migrations, dropping '
        'the database, then running makemigrations and migrate. '
        'Creates a superuser unless --no-user is provided.'
    )

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--force', action='store_true', help='Force database reset without prompt.')
        parser.add_argument('--no-user', action='store_true', help='Skip superuser creation.')

    def handle(self, *_args: tuple[str], **options: dict[str, str]) -> None:
        """Executes the command."""
        # Confirm database reset
        if not options.get('force'):
            self.stdout.write('WARNING: This will delete the database and all migration files.')
            answer = input('Are you sure you want to continue? (y/N): ').strip().lower()
            if answer not in ('y', 'yes'):
                self.stdout.write('Aborted.')
                return

        # Remove migration files
        self.stdout.write('Removing migration files...')
        base_path = Path(__file__).resolve().parent.parent.parent.parent
        self._remove_migration_files(base_path)

        # Reset database depending on engine
        engine = settings.DATABASES['default']['ENGINE']
        if engine == 'django.db.backends.sqlite3':
            self._reset_sqlite(base_path)
        elif engine == 'django.db.backends.postgresql':
            self._reset_postgresql()
        else:
            self.stderr.write(f'Database engine {engine} is not supported by this command.')
            return

        # Run migrations
        self.stdout.write('Running makemigrations...')
        call_command('makemigrations')
        self.stdout.write('Running migrate...')
        call_command('migrate')

        # Create superuser if needed
        if not options.get('no_user'):
            self.stdout.write('Creating superuser...')
            call_command('createsuperuser', interactive=False, username='admin', email='')
            user = User.objects.get(username='admin')
            user.set_password('testing321')
            user.save()
            self.stdout.write('Superuser created:')
            self.stdout.write('  Username: admin')
            self.stdout.write('  Password: testing321')

        self.stdout.write('Database reset complete.')

    def _remove_migration_files(self, base_path: Path) -> None:
        """Removes all Django migration files."""
        for root, _dirs, files in os.walk(base_path):
            if 'migrations' in root:
                for file in files:
                    if (file.endswith('.py') and file != '__init__.py') or file.endswith('.pyc'):
                        try:
                            Path(Path(root) / file).unlink()
                        except Exception as e:  # noqa: BLE001
                            self.stderr.write(f'Error removing {file}: {e}')

    def _reset_sqlite(self, base_path: Path) -> None:
        """Deletes the SQLite database file."""
        db_path = base_path / 'db.sqlite3'
        if db_path.exists():
            try:
                Path(db_path).unlink()
                self.stdout.write('SQLite database file deleted.')
            except Exception as e:  # noqa: BLE001
                self.stderr.write(f'Error deleting SQLite database file: {e}')
        else:
            self.stdout.write('No SQLite database file found.')

    def _reset_postgresql(self) -> None:
        """Drops and recreates the PostgreSQL database."""
        db_config = settings.DATABASES['default']
        db_name = db_config['NAME']
        db_user = db_config['USER']
        db_password = db_config['PASSWORD']
        db_host = db_config['HOST']
        db_port = db_config['PORT']

        self.stdout.write(f"Resetting PostgreSQL database '{db_name}'...")

        try:
            # Connect to the default 'postgres' database to issue drop/create commands
            conn = psycopg.connect(
                dbname='postgres',
                user=db_user,
                password=db_password,
                host=db_host,
                port=db_port,
                autocommit=True,
            )
            cur = conn.cursor()

            # Terminate existing connections to the target database
            self.stdout.write('Terminating existing connections...')
            cur.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s
                AND pid <> pg_backend_pid();
                """,
                (db_name,),
            )

            # Drop the database if it exists
            self.stdout.write('Dropping database...')
            cur.execute(f'DROP DATABASE IF EXISTS {db_name};')

            # Recreate the database owned by the specified user
            self.stdout.write('Creating database...')
            cur.execute(f'CREATE DATABASE {db_name} OWNER {db_user};')

            cur.close()
            conn.close()
            self.stdout.write('PostgreSQL database reset successfully.')

        except Exception as e:  # noqa: BLE001
            self.stderr.write(f'Error resetting PostgreSQL database: {e}')
