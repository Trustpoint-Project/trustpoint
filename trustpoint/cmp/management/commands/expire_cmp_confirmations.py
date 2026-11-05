# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Allow explicit CMP confirmation cleanup from cron or an operator shell."""

from typing import Any

from django.core.management.base import BaseCommand

from cmp.confirmation import expire_due_confirmations


class Command(BaseCommand):
    """Apply the persisted rejection policy to overdue CMP confirmations."""

    help = 'Reject expired explicit CMP confirmations and release their bootstrap credentials.'

    def handle(self, *_args: Any, **_options: Any) -> None:
        """Run one expiry sweep."""
        self.stdout.write(f'Expired {expire_due_confirmations()} CMP confirmation(s).')
