# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Publish auto-setup readiness after the operational runtime is serving requests."""

from pathlib import Path

from django.core.management.base import BaseCommand

from setup_wizard.operational_handoff import operational_ready_file_path, write_operational_ready_file


class Command(BaseCommand):
    """Complete the auto-setup handoff as the application account."""

    def handle(self, **_options: object) -> None:
        """Persist readiness before removing the retry marker."""
        write_operational_ready_file(operational_ready_file_path())
        Path('/var/lib/trustpoint/bootstrap/auto-setup.marker').unlink(missing_ok=True)
