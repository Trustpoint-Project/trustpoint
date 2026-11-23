# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Recalculate renewal dates after upgrading to expiry-based scheduling."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from agents.models import AgentAssignedProfile
from management.models import AuditLog


class Command(BaseCommand):
    """Move existing renewal dates earlier when the old interval is past the safe threshold."""

    help = (
        'Recomputes agent renewal dates from the currently issued certificate expiry. '
        'Use --dry-run to list assignments that would change.'
    )

    def add_arguments(self, parser: Any) -> None:
        """Add the dry-run flag."""
        parser.add_argument('--dry-run', action='store_true', help='Only report assignments that would change.')

    def handle(self, *_args: tuple[str], **options: Any) -> None:
        """Recalculate every assignment that has an issued certificate."""
        dry_run = bool(options.get('dry_run'))
        now = timezone.now()
        changed = 0
        assignments = AgentAssignedProfile.objects.select_related(
            'agent__device__domain',
            'workflow_definition',
        ).defer('workflow_definition__secrets')
        for assignment in assignments:
            computed = assignment.next_update_from_certificate(now)
            if computed is None:
                continue
            current = assignment.next_certificate_update_scheduled
            if current is not None and current <= computed:
                continue

            changed += 1
            self.stdout.write(
                f'{"Would update" if dry_run else "Updating"}: '
                f'{assignment.agent.name} / {assignment.workflow_definition.name} '
                f'({current} -> {computed})'
            )
            if dry_run:
                continue

            with transaction.atomic():
                assignment.next_certificate_update_scheduled = computed
                assignment.save(update_fields=['next_certificate_update_scheduled', 'updated_at'])
                AuditLog.create_entry(
                    operation_type=AuditLog.OperationType.MODEL_UPDATED,
                    target=assignment,
                    target_display=(
                        f'Agent Assignment: {assignment.agent.name} / {assignment.workflow_definition.name}'
                    ),
                    actor=None,
                    details={'action': 'recalculate_renewal_schedule'},
                )

        suffix = ' (dry run)' if dry_run else ''
        self.stdout.write(self.style.SUCCESS(f'Updated {changed} assignment(s){suffix}.'))
