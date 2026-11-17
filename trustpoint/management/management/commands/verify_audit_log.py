# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify the audit event hash chain and signed checkpoints."""

from __future__ import annotations

import json
import sys
from typing import Any

from django.core.management.base import BaseCommand

from management.services.audit_integrity import verify_audit_chain


class Command(BaseCommand):
    """Exit non-zero when the chain or a checkpoint signature is invalid."""

    help = 'Verify the complete audit hash chain and all checkpoint signatures.'

    def add_arguments(self, parser: Any) -> None:
        """Add machine-readable output for monitoring."""
        parser.add_argument('--json', action='store_true', help='Emit the verification report as JSON.')

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Run verification and report fatal findings."""
        report = verify_audit_chain()
        if options['json']:
            payload = {
                'ok': report.ok,
                'entries_checked': report.entries_checked,
                'checkpoints_checked': report.checkpoints_checked,
                'unsigned_entries': report.unsigned_entries,
                'findings': [
                    {'code': str(finding.code), 'sequence': finding.sequence, 'detail': finding.detail}
                    for finding in report.findings
                ],
            }
            self.stdout.write(json.dumps(payload, indent=2))
        else:
            style = self.style.SUCCESS if report.ok else self.style.ERROR
            self.stdout.write(
                style(
                    f'Verified {report.entries_checked} events and '
                    f'{report.checkpoints_checked} checkpoints; '
                    f'{report.unsigned_entries} event(s) after the latest checkpoint.'
                )
            )
            for finding in report.findings:
                sequence = f' sequence {finding.sequence}' if finding.sequence is not None else ''
                self.stdout.write(f'{finding.code}{sequence}: {finding.detail}')
        if not report.ok:
            sys.exit(1)
