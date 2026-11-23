# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Move literal password step values into the encrypted profile secret store."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from agents.models import AgentProfileDefinition, is_literal_password_step
from management.models import AuditLog


class Command(BaseCommand):
    """Encrypt literal password values that were saved before the secret store existed."""

    help = (
        'Moves literal password values from agent profile steps into the encrypted Secret Values field. '
        'Use --dry-run to list affected profiles without writing.'
    )

    def add_arguments(self, parser: Any) -> None:
        """Add the dry-run flag."""
        parser.add_argument('--dry-run', action='store_true', help='Only report profiles that would change.')

    def handle(self, *_args: tuple[str], **options: Any) -> None:
        """Migrate every profile that still contains a literal password."""
        dry_run = bool(options.get('dry_run'))
        migrated = 0
        for profile in AgentProfileDefinition.objects.all():
            raw_profile = profile.profile
            if not isinstance(raw_profile, dict):
                continue
            steps = raw_profile.get('steps')
            if not isinstance(steps, list):
                continue

            secrets = dict(profile.secrets or {})
            changed = False
            for index, step in enumerate(steps):
                if not isinstance(step, dict) or not is_literal_password_step(step):
                    continue
                value = step.get('value')
                if not isinstance(value, str):
                    continue
                key = f'step_{index}_value'
                while key in secrets:
                    key += '_'
                secrets[key] = value
                step['value'] = f'{{{{ secret:{key} }}}}'
                changed = True

            if not changed:
                continue

            migrated += 1
            self.stdout.write(f'{"Would update" if dry_run else "Updating"}: {profile.name}')
            if dry_run:
                continue

            profile.secrets = secrets
            profile.profile = raw_profile
            profile.save(update_fields=['profile', 'secrets', 'updated_at'])
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.AGENT_PROFILE_UPDATED,
                target=profile,
                target_display=f'Agent Profile Definition: {profile.name}',
                actor=None,
                details={'action': 'encrypt_literal_password_values'},
            )

        suffix = ' (dry run)' if dry_run else ''
        self.stdout.write(self.style.SUCCESS(f'Processed {migrated} profile(s){suffix}.'))
