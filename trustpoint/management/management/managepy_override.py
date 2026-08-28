# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Override the default makemigrations to get Trustpoint naming and additional checks."""

import os
import sys
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.core.management import execute_from_command_line

COPYRIGHT_HEADER = '# Copyright (c) {year} The Trustpoint Project Authors\n# SPDX-License-Identifier: MIT\n\n'


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


def _add_copyright_headers(migration_name: str, base_path: Path) -> None:
    """Prepend a copyright header to newly generated migration files missing one."""
    header = COPYRIGHT_HEADER.format(year=datetime.now().astimezone().year)
    for root, _dirs, files in os.walk(base_path):
        if 'migrations' not in root:
            continue
        for file in files:
            if not file.endswith(migration_name + '.py'):
                continue
            file_path = Path(root) / file
            content = file_path.read_text(encoding='utf-8')
            if 'Copyright (c)' not in content:
                file_path.write_text(header + content, encoding='utf-8')


def override_makemigrations(cmd_args: list[str]) -> None:
    """Override the default makemigrations command to use Trustpoint naming."""
    sys.stdout.write(f'makemigrations called with args: {cmd_args}\n')
    migration_name = 'tp_v' + settings.APP_VERSION.replace('.', '_')
    # override default migration name
    if '--name' not in cmd_args and '-n' not in cmd_args:
        cmd_args.extend(['--name', migration_name])
    # remove migration header to reduce merge conflicts
    if '--no-header' not in cmd_args:
        cmd_args.append('--no-header')
    execute_from_command_line(cmd_args)
    base_path = Path(__file__).resolve().parent.parent.parent.parent
    _check_migration_name_duplicates(migration_name, base_path)
    _add_copyright_headers(migration_name, base_path)

