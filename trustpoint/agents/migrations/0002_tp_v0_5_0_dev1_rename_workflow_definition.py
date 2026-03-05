"""Rename WbmWorkflowDefinition → AgentWorkflowDefinition."""

from __future__ import annotations

from typing import ClassVar

from django.db import migrations


class Migration(migrations.Migration):
    """Rename WbmWorkflowDefinition to AgentWorkflowDefinition."""

    dependencies: ClassVar = [
        ('agents', '0001_tp_v0_5_0_dev1'),
    ]

    operations: ClassVar = [
        migrations.RenameModel(
            old_name='WbmWorkflowDefinition',
            new_name='AgentWorkflowDefinition',
        ),
    ]
