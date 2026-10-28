# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Load YAML examples from the explicit demo-data initialization path."""

from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from django.db import transaction

from workflows2.compiler.errors import CompileError
from workflows2.models import Workflow2Definition
from workflows2.services.definitions import WorkflowDefinitionService

DEMO_WORKFLOWS_PATH = Path(__file__).resolve().parent.parent / 'demo_workflows'


@transaction.atomic
def install_demo_workflows() -> int:
    """Import missing YAML files, using filenames as stable example identities."""
    service = WorkflowDefinitionService()
    created_count = 0
    for path in sorted(DEMO_WORKFLOWS_PATH.glob('*.yaml')):
        # Keep identity stable even when users rename or edit a workflow.
        definition_id = uuid5(NAMESPACE_URL, f'https://trustpoint.org/demo-workflows/{path.stem}')
        if Workflow2Definition.objects.filter(pk=definition_id).exists():
            continue

        yaml_text = path.read_text(encoding='utf-8')
        result = service.compile_yaml(yaml_text)
        if not result.ok or result.ir is None:
            msg = f'Invalid demo workflow {path.name}: {result.error}'
            raise CompileError(msg)
        ir = result.ir
        _, created = Workflow2Definition.objects.get_or_create(
            pk=definition_id,
            defaults={
                'name': ir['name'],
                'enabled': ir['enabled'],
                'trigger_on': ir['trigger']['on'],
                'yaml_text': yaml_text,
                'ir_json': ir,
                'ir_hash': ir['meta']['ir_hash'],
            },
        )
        created_count += created
    return created_count
