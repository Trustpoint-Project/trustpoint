# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Merge Dashboard V2 endpoints into the existing home/views.py, safely and idempotently.

Run from the repository root AFTER copying the package trustpoint/ overlay.
Will back up views.py and validate syntax before deleting old modules.
"""

from __future__ import annotations

import argparse
import ast
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

MARKER = '# === Dashboard V2 unified views (managed integration) ==='
END = '# === End Dashboard V2 unified views ==='


def clean_source(path: Path, *, analytics: bool) -> str:
    """Strip imports that must not be duplicated in the merged module."""
    text = path.read_text(encoding='utf-8')
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    skip: set[int] = set()
    for node in tree.body:
        # Keep imports except future directives and the analytics dependency on views.
        if isinstance(node, ast.ImportFrom) and (
            node.module == '__future__' or (analytics and node.module == 'home.views')
        ):
            skip.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    cleaned = ''.join(line for i, line in enumerate(lines, 1) if i not in skip)
    return cleaned.strip() + '\n'


def main() -> None:
    """Parse arguments and run the requested migration step."""
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, default=Path.cwd())
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    root = args.project_root.resolve()
    home = root / 'trustpoint/home'
    current = home / 'views.py'
    staging = Path(__file__).resolve().parent / 'migration_sources'
    first = staging / 'dashboard_v2_views.py'
    second = staging / 'dashboard_v2_analytics.py'
    if not current.exists() or not first.exists() or not second.exists():
        parser.error('Missing existing views.py or migration_sources (keep package intact)')
    old = current.read_text(encoding='utf-8')
    if MARKER in old or 'class DashboardV2View(' in old:
        parser.error('V2 already appears merged into views.py; refusing a duplicate merge')
    new = (
        old.rstrip()
        + '\n\n'
        + MARKER
        + '\n'
        + clean_source(first, analytics=False)
        + '\n'
        + clean_source(second, analytics=True)
        + END
        + '\n'
    )
    try:
        compile(new, str(current), 'exec')
    except SyntaxError as exc:
        parser.error(f'Merged views.py failed syntax check: {exc}')
    logger.info('Ready to merge V2 endpoint implementations into %s', current)
    logger.info('Current lines: %s Merged lines: %s', len(old.splitlines()), len(new.splitlines()))
    if not args.apply:
        logger.info('Dry-run only. Re-run with --apply to back up and write views.py')
        return
    backup = current.with_suffix('.py.pre_v2_merge.bak')
    if backup.exists():
        parser.error(f'Backup already exists: {backup}; preserve it before retrying')
    shutil.copy2(current, backup)
    tmp = current.with_suffix('.py.merged.tmp')
    tmp.write_text(new, encoding='utf-8')
    tmp.replace(current)
    for legacy in ('dashboard_v2_views.py', 'dashboard_v2_analytics.py'):
        p = home / legacy
        if p.exists():
            p.unlink()
    logger.info('Merged OK. Backup: %s', backup)
    logger.info('Remove old milestone assets with cleanup_obsolete_dashboard_v2.py after running Django tests.')


if __name__ == '__main__':
    main()
