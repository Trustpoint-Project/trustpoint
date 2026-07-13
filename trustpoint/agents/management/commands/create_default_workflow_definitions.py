"""Django management command to create default agent workflow definitions."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from django.core.management.base import BaseCommand

from agents.models import AgentWorkflowDefinition
from management.models import AuditLog

_DEFAULTS_DIR = Path(__file__).resolve().parent.parent.parent / 'default'

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Creates default agent workflow definitions."""

    help = 'Creates default agent workflow definitions if they do not already exist.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Load each *.json file from the default/ directory and create workflow definitions."""
        logger.info('Starting creation of default agent workflow definitions from %s', _DEFAULTS_DIR)
        
        json_files = sorted(_DEFAULTS_DIR.glob('*.json'))
        if not json_files:
            logger.warning('No JSON files found in %s', _DEFAULTS_DIR)
            self.stdout.write(self.style.WARNING(f'No JSON files found in {_DEFAULTS_DIR}'))
            return
        
        created_count = 0
        existing_count = 0
        
        for json_file in json_files:
            try:
                wf_data: dict = json.loads(json_file.read_text(encoding='utf-8'))
                workflow_name = wf_data.get('name')
                
                if not workflow_name:
                    logger.error('Workflow definition in %s is missing required "name" field', json_file)
                    self.stdout.write(self.style.ERROR(f'ERROR: {json_file.name} is missing "name" field'))
                    continue
                
                workflow, created = AgentWorkflowDefinition.objects.get_or_create(
                    name=workflow_name,
                    defaults={
                        'profile': wf_data['profile'],
                        'is_active': wf_data.get('is_active', True),
                    },
                )
                
                if created:
                    created_count += 1
                    logger.info('Created workflow definition: %s (from %s)', workflow_name, json_file.name)
                    self.stdout.write(self.style.SUCCESS(f'Created: {workflow_name}'))
                    
                    # Create audit log entry
                    AuditLog.create_entry(
                        operation_type=AuditLog.OperationType.MODEL_CREATED,
                        target=workflow,
                        target_display=f'Workflow Definition: {workflow_name}',
                        actor=None,  # System action
                        details={
                            'source': 'create_default_workflow_definitions',
                            'source_file': json_file.name,
                            'is_active': wf_data.get('is_active', True),
                        },
                    )
                else:
                    existing_count += 1
                    logger.debug('Workflow definition already exists: %s', workflow_name)
                    self.stdout.write(f'Already exists: {workflow_name}')
                    
            except json.JSONDecodeError as e:
                logger.error('Invalid JSON in %s: %s', json_file, e)
                self.stdout.write(self.style.ERROR(f'ERROR: Invalid JSON in {json_file.name}: {e}'))
            except KeyError as e:
                logger.error('Missing required field in %s: %s', json_file, e)
                self.stdout.write(self.style.ERROR(f'ERROR: Missing required field in {json_file.name}: {e}'))
            except Exception as e:
                logger.exception('Unexpected error processing %s', json_file)
                self.stdout.write(self.style.ERROR(f'ERROR: Failed to process {json_file.name}: {e}'))
        
        logger.info(
            'Finished creating default workflow definitions. Created: %d, Already existed: %d, Total processed: %d',
            created_count,
            existing_count,
            len(json_files),
        )
        self.stdout.write(
            self.style.SUCCESS(
                f'\nSummary: Created {created_count}, Already existed {existing_count}, Total {len(json_files)}'
            )
        )
