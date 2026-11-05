# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Development server commands that run the Django-Q2 qcluster alongside the server."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING, Any

from django.core.management.commands.runserver import Command as RunServerCommand

if TYPE_CHECKING:
    from django.core.management.base import CommandParser

QCLUSTER_STOP_TIMEOUT = 5


class QClusterMixin:
    """Starts ``qcluster`` next to a runserver-style command and stops it on exit."""

    def add_arguments(self, parser: CommandParser) -> None:
        """Add the qcluster opt-out flag."""
        super().add_arguments(parser)  # type: ignore[misc]
        parser.add_argument('--no-qcluster', action='store_true', help='Do not start the Django-Q2 qcluster.')

    def handle(self, *args: Any, **options: Any) -> None:
        """Run the server with a qcluster subprocess."""
        qcluster: subprocess.Popen[bytes] | None = None
        # The autoreloader re-runs handle() in a child with RUN_MAIN set; only the parent owns the qcluster.
        if not options.get('no_qcluster') and os.environ.get('RUN_MAIN') != 'true':
            qcluster = subprocess.Popen([sys.executable, '-m', 'django', 'qcluster'])
        try:
            super().handle(*args, **options)  # type: ignore[misc]
        finally:
            if qcluster is not None and qcluster.poll() is None:
                qcluster.terminate()
                try:
                    qcluster.wait(timeout=QCLUSTER_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    qcluster.kill()
                    qcluster.wait()


class Command(QClusterMixin, RunServerCommand):
    """Plain ``runserver`` together with the Django-Q2 qcluster."""
