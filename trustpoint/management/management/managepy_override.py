"""Override the default makemigrations to get Trustpoint naming and additional checks."""

import os
import sys
from pathlib import Path

from django.conf import settings
from django.core.management import execute_from_command_line


def _check_migration_name_duplicates(migration_name: str, base_path: Path, *_args: tuple[object, ...]) -> None:
    """Check for multiple migration files and warn if found."""
    for root, _dirs, files in os.walk(base_path):
        if 'migrations' in root:
            mig_name_counts: dict[str, int] = {}
            for file in files:
                if file.endswith(migration_name + '.py'):
                    mig_name_counts[migration_name] = mig_name_counts.get(migration_name, 0) + 1
            for name, count in mig_name_counts.items():
                dir_name = Path(root).parent.name
                if count > 1:
                    sys.stderr.write(
                        f'Warning: {count} migrations with name {name} exist in {dir_name}.\n'
                        'Please combine them before finishing your PR using the "reset_db" command.\n'
                    )


def override_makemigrations(cmd_args: list[str]) -> None:
    """Override the default makemigrations command to use Trustpoint naming."""
    sys.stdout.write(f'makemigrations called with args: {cmd_args}\n')
    migration_name = 'tp_v' + settings.APP_VERSION.replace('.', '_')
    # override default migration name
    if '--name' not in cmd_args and '-n' not in cmd_args:
        cmd_args.extend(['--name', migration_name])
    execute_from_command_line(cmd_args)
    base_path = Path(__file__).resolve().parent.parent.parent.parent
    _check_migration_name_duplicates(migration_name, base_path)
