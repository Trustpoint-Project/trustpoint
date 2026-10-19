# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Remove superseded Dashboard V2 milestone assets safely.

Dry run by default. Run from any working directory: script locates Trustpoint root
from --project-root; never deletes legacy dashboard files or unknown project files.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

OBSOLETE = (
    'trustpoint/static/js/dashboard/dashboard_v2_m6.js',
    'trustpoint/static/js/dashboard/dashboard_v2_m8.js',
    'trustpoint/static/js/dashboard/dashboard_v2_analytics.js',
    'trustpoint/static/js/dashboard/dashboard_v2_analytics_m6.js',
    'trustpoint/static/js/dashboard/dashboard_v2_analytics_m8.js',
)


def main() -> None:
    """Parse arguments and run the requested migration step."""
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, default=Path.cwd())
    parser.add_argument('--apply', action='store_true', help='Delete allowlisted obsolete files')
    args = parser.parse_args()
    root = args.project_root.resolve()
    if not (root / 'trustpoint/home/urls.py').is_file():
        parser.error('Not a Trustpoint checkout (missing trustpoint/home/urls.py)')
    for name in OBSOLETE:
        target = root / name
        if not target.is_file():
            logger.info('ABSENT %s', name)
            continue
        if args.apply:
            target.unlink()
            logger.info('REMOVED %s', name)
        else:
            logger.info('WOULD REMOVE %s', name)
    logger.info('Legacy dashboard.py / dashboard.js / dashboard.css and all original templates are preserved.')


if __name__ == '__main__':
    main()
