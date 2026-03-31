"""Django management command to create default agent workflow definitions."""

from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand

from agents.models import AgentWorkflowDefinition

_DEFAULTS_DIR = Path(__file__).resolve().parent.parent.parent / 'default'


class Command(BaseCommand):
    """Creates default agent workflow definitions."""

    help = 'Creates default agent workflow definitions if they do not already exist.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Load each *.json file from the default/ directory and create workflow definitions."""
        for json_file in sorted(_DEFAULTS_DIR.glob('*.json')):
            wf_data: dict = json.loads(json_file.read_text(encoding='utf-8'))
            _, created = AgentWorkflowDefinition.objects.get_or_create(
                name=wf_data['name'],
                defaults={
                    'profile': wf_data['profile'],
                    'is_active': wf_data.get('is_active', True),
                },
            )
            status = 'Created' if created else 'Already exists'
            self.stdout.write(f'{status}: {wf_data["name"]}')
