"""Management command to reset the database and migrations."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import psycopg
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import BaseCommand, call_command

from management.models import AppVersion, KeyStorageConfig

if TYPE_CHECKING:
    from django.core.management.base import CommandParser

ENGINE_SQLITE = 'django.db.backends.sqlite3'
ENGINE_POSTGRESQL = 'django.db.backends.postgresql'

class Command(BaseCommand):
    """Management command to reset the database and migrations."""

    help = (
        'Resets the database by deleting current version migrations, dropping '
        'the database, then running makemigrations and migrate. '
        'Creates a superuser unless --no-user is provided.'
    )

    def add_arguments(self, parser: CommandParser) -> None:
        """Adds command arguments/options."""
        parser.add_argument('--add', action='store_true', help='Add demo domains and devices after reset.')
        parser.add_argument('--force', action='store_true', help='Force database reset without prompt.')
        parser.add_argument('--no-user', action='store_true', help='Skip superuser creation.')
        parser.add_argument(
            '--keep-all-migrations', action='store_true',
            help='Use in CI environments, does not regenerate migrations.')
        parser.add_argument(
            '--initial-migrations', action='store_true',
            help='DO NOT USE! Breaks the DB of existing installations! Remove all migrations and create initial.')

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
        keep_established = not options.get('initial_migrations', False)
        do_makemigrations = not options.get('keep_all_migrations', False)
        base_path = Path(__file__).resolve().parent.parent.parent.parent
        if do_makemigrations:
            self._remove_migration_files(base_path, keep_established=keep_established)

        # Reset database depending on engine
        engine = settings.DATABASES['default']['ENGINE']
        if engine == ENGINE_SQLITE:
            self._reset_sqlite(base_path)
        elif engine == ENGINE_POSTGRESQL:
            self._reset_postgresql()
        else:
            self.stderr.write(f'Database engine {engine} is not supported by this command.')
            return

        # Run migrations
        if do_makemigrations:
            migration_name = 'tp_v' + settings.APP_VERSION.replace('.', '_')
            if options.get('initial_migrations'):
                migration_name = 'initial'
            self.stdout.write('Running makemigrations...')
            call_command('makemigrations', name=migration_name)
        self.stdout.write('Running migrate...')
        call_command('migrate')

        # Add default models for development server
        if engine == ENGINE_SQLITE:
            self.stdout.write('Adding default models for development server...')
            AppVersion.objects.get_or_create(version=settings.APP_VERSION)
            # Ensure crypto storage config exists for encrypted fields
            KeyStorageConfig.get_or_create_default()

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

        # Add demo domains and devices
        if options.get('add'):
            call_command('add_domains_and_devices')

    def _remove_migration_files(self, base_path: Path, *_args: tuple, keep_established: bool) -> None:
        """Removes all Django migration files."""
        current_version_py_id = settings.APP_VERSION.replace('.', '_')
        for root, _dirs, files in os.walk(base_path):
            if 'migrations' in root:
                for file in files:
                    if (file.endswith('.py') and file != '__init__.py') or file.endswith('.pyc'):
                        if (keep_established and
                            (('_tp_v' in file and current_version_py_id not in file) or '0001_initial' in file)
                        ):
                            continue
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
            except Exception as e:
                self.stderr.write(f'Error deleting SQLite database file: {e}')
                self.stderr.write('Is it still open in another program?')
                raise
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
