"""Django settings entrypoint for the isolated Trustpoint bootstrap phase."""

from __future__ import annotations

import os

os.environ['TRUSTPOINT_PHASE'] = 'bootstrap'

from .settings import *  # noqa: F403
