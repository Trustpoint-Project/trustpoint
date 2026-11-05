# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to build the Sphinx documentation."""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.management.base import BaseCommand

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from pathlib import Path


class Command(BaseCommand):
    """Builds the Sphinx documentation, optionally syncing the docs dependencies first."""

    help = 'Builds Sphinx documentation locally, integrating with the uv workflow.'

    def add_arguments(self, parser: ArgumentParser) -> None:
        """Adds the command arguments."""
        parser.add_argument('--sync-deps', action='store_true', help='Run uv sync --group docs (Requires Internet)')
        parser.add_argument('--clean', action='store_true', help='Clean build directory before building')
        parser.add_argument('--force-env', action='store_true', help='Force use of sphinx.cmd.build directly')

    def handle(self, *_args: object, **options: Any) -> None:
        """Entrypoint for the command."""
        repo_root = settings.BASE_DIR.parent
        docs_dir = repo_root / 'docs'

        if not docs_dir.exists():
            self.stderr.write(self.style.ERROR(f'Documentation directory not found at {docs_dir}'))
            return


        if options['sync_deps']:
            self.stdout.write('Syncing documentation dependencies...')
            try:
                subprocess.run(['uv', 'sync', '--group', 'docs'], cwd=repo_root, check=True)  # noqa: S607
                self.stdout.write(self.style.SUCCESS('Dependencies synced successfully.'))
            except subprocess.CalledProcessError as e:
                self.stderr.write(self.style.ERROR(f'Failed to sync dependencies: {e}'))
                return


        if options['clean']:
            self.stdout.write('Cleaning previous build...')
            try:

                subprocess.run(['make', 'clean'], cwd=docs_dir, check=True)  # noqa: S607
            except subprocess.CalledProcessError:
                self.stdout.write(self.style.WARNING('Standard make clean failed. Proceeding anyway...'))


        self.stdout.write('Building documentation...')
        build_success = False

        if options['force_env']:
            build_success = self._build_sphinx_direct(docs_dir)
        else:
            try:
                subprocess.run(['make', 'html'], cwd=docs_dir, check=True)  # noqa: S607
                build_success = True
            except subprocess.CalledProcessError as e:
                self.stdout.write(
                    self.style.WARNING(f"'make html' failed ({e}). Falling back to direct sphinx.cmd.build...")
                )
                build_success = self._build_sphinx_direct(docs_dir)


        if build_success:
            docs_build_path = docs_dir / 'build' / 'html'
            self.stdout.write(self.style.SUCCESS(f'Successfully built docs at: {docs_build_path}'))
        else:
            self.stderr.write(self.style.ERROR('Documentation build failed entirely.'))

    def _build_sphinx_direct(self, docs_dir: Path) -> bool:
        """Fallback method utilizing the direct Sphinx module build."""
        try:
            subprocess.run(
                [sys.executable, '-m', 'sphinx.cmd.build', '-M', 'html', 'source', 'build'],
                cwd=docs_dir, check=True
            )
        except subprocess.CalledProcessError as e:
            self.stderr.write(self.style.ERROR(f'Direct Sphinx build also failed: {e}'))
            return False
        return True
