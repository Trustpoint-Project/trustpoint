"""Django management command to create default agent workflow definitions."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from agents.models import AgentWorkflowDefinition

_DEFAULT_WORKFLOWS: list[dict] = [
    {
        'name': 'WBM Generic',
        'profile': {
            'vendor': 'Generic',
            'device_family': 'WBM Device',
            'firmware_hint': '1.0',
            'version': '1.0',
            'description': 'Generic Web-Based Management (WBM) workflow for certificate push.',
            'steps': [
                {
                    'type': 'goto',
                    'url': 'https://device.example.com',
                },
                {
                    'type': 'fill',
                    'selector': '#username',
                    'value': 'admin',
                },
                {
                    'type': 'fill',
                    'selector': '#password',
                    'value': 'password',
                },
                {
                    'type': 'click',
                    'selector': '#login-button',
                },
                {
                    'type': 'waitFor',
                    'selector': '.dashboard',
                    'timeout_ms': 5000,
                },
                {
                    'type': 'screenshot',
                },
            ],
        },
        'is_active': True,
    },
]


class Command(BaseCommand):
    """Creates default agent workflow definitions."""

    help = 'Creates default agent workflow definitions if they do not already exist.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Create each default workflow definition using get_or_create."""
        for wf_data in _DEFAULT_WORKFLOWS:
            _, created = AgentWorkflowDefinition.objects.get_or_create(
                name=wf_data['name'],
                defaults={
                    'profile': wf_data['profile'],
                    'is_active': wf_data['is_active'],
                },
            )
            status = 'Created' if created else 'Already exists'
            self.stdout.write(f'{status}: {wf_data["name"]}')
