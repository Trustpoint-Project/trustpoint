# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Create an audit checkpoint when policy requires it, or on demand."""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from management.services.audit_signing import create_checkpoint, maybe_sign_checkpoint


class Command(BaseCommand):
    """Sign the current unsigned audit range for cron or Django-Q2 scheduling."""

    help = 'Create an audit checkpoint according to policy, or immediately with --force.'

    def add_arguments(self, parser: Any) -> None:
        """Allow operators to force a checkpoint during incident response or tests."""
        parser.add_argument('--force', action='store_true', help='Sign the current unsigned range immediately.')

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Create at most one checkpoint."""
        try:
            checkpoint = create_checkpoint() if options['force'] else maybe_sign_checkpoint()
        except ValidationError as error:
            raise CommandError(str(error)) from error
        if checkpoint is None:
            self.stdout.write('No audit checkpoint was required.')
            return
        self.stdout.write(
            self.style.SUCCESS(
                f'Created checkpoint {checkpoint.checkpoint_number} covering '
                f'sequences {checkpoint.first_sequence}-{checkpoint.last_sequence}.'
            )
        )
