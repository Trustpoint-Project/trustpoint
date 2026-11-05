# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Keep unfinished setup material beside the persistent bootstrap database."""

import os
from pathlib import Path

from django.conf import settings

_default_database = (
    Path('/var/lib/trustpoint/bootstrap/bootstrap.sqlite3')
    if settings.DOCKER_CONTAINER
    else settings.REPO_ROOT / 'var' / 'bootstrap' / 'bootstrap.sqlite3'
)
WIZARD_STAGING_ROOT = Path(os.getenv('TRUSTPOINT_BOOTSTRAP_DB_PATH', str(_default_database))).parent / 'staging'
