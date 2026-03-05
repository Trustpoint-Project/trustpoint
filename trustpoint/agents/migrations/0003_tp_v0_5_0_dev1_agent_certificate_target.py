"""Rename WbmCertificateTarget → AgentCertificateTarget; drop slot/purpose/base_url fields."""

from __future__ import annotations

from typing import ClassVar

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    """Rename WbmCertificateTarget to AgentCertificateTarget and simplify its fields."""

    dependencies: ClassVar = [
        ('agents', '0002_tp_v0_5_0_dev1_rename_workflow_definition'),
        ('devices', '0005_tp_v0_5_0_dev1_agent_managed_device'),
        ('pki', '0003_tp_v0_5_0_dev1'),
    ]

    operations: ClassVar = [
        # 1. Rename the model (renames the DB table)
        migrations.RenameModel(
            old_name='WbmCertificateTarget',
            new_name='AgentCertificateTarget',
        ),
        # 2. Drop fields that are no longer needed
        migrations.RemoveField(
            model_name='agentcertificatetarget',
            name='purpose',
        ),
        migrations.RemoveField(
            model_name='agentcertificatetarget',
            name='slot',
        ),
        migrations.RemoveField(
            model_name='agentcertificatetarget',
            name='base_url',
        ),
        # 3. Replace the old unique_together with the new one
        migrations.AlterUniqueTogether(
            name='agentcertificatetarget',
            unique_together={('device', 'agent', 'certificate_profile')},
        ),
        # 4. Update related_name on device FK
        migrations.AlterField(
            model_name='agentcertificatetarget',
            name='device',
            field=models.ForeignKey(
                help_text=(
                    'The managed device that owns this certificate target. '
                    'For 1-to-n agents this must be an Agent Managed Device, not the agent device itself. '
                    "For 1-to-1 agents this must be the agent's own device."
                ),
                on_delete=django.db.models.deletion.CASCADE,
                related_name='agent_targets',
                to='devices.devicemodel',
                verbose_name='Device',
            ),
        ),
        # 5. Update related_name on agent FK
        migrations.AlterField(
            model_name='agentcertificatetarget',
            name='agent',
            field=models.ForeignKey(
                help_text='The agent deployed in the production cell that can reach this device.',
                on_delete=django.db.models.deletion.PROTECT,
                related_name='agent_targets',
                to='agents.trustpointagent',
                verbose_name='Agent',
            ),
        ),
        # 6. Update related_name on certificate_profile FK
        migrations.AlterField(
            model_name='agentcertificatetarget',
            name='certificate_profile',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name='agent_targets',
                to='pki.certificateprofilemodel',
                verbose_name='Certificate Profile',
            ),
        ),
        # 7. Update WbmJob.target FK to point at the renamed model
        migrations.AlterField(
            model_name='wbmjob',
            name='target',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='jobs',
                to='agents.agentcertificatetarget',
                verbose_name='Certificate Target',
            ),
        ),
    ]
