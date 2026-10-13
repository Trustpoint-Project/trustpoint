# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Development server whose port is also the advertised TP_HTTP_PORT."""

from __future__ import annotations

import os
from typing import Any

from django.conf import settings
from django.contrib.staticfiles.management.commands.runserver import Command as StaticFilesRunServerCommand

PRIVILEGED_PORT_LIMIT = 1024


class Command(StaticFilesRunServerCommand):
    """``runserver`` that defaults to ``TP_HTTP_PORT`` if set, and publishes the port it listens on as that setting."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Use the TP_HTTP_PORT environment variable as default port if present."""
        super().__init__(*args, **kwargs)
        http_port = os.environ.get('TP_HTTP_PORT', '').strip()
        if http_port.isdigit():
            self.default_port = http_port
            if int(http_port) < PRIVILEGED_PORT_LIMIT:
                self.default_addr = '0.0.0.0'  # noqa: S104

    def run(self, **options: Any) -> None:
        """Make the port given as ``[addr:]port`` the TP_HTTP_PORT used for generated URLs."""
        settings.TP_HTTP_PORT = str(self.port)
        super().run(**options)
