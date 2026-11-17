# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from typing import Any

import django.db.models.deletion
from django.db import migrations, models


def create_chain_lock(apps: Any, schema_editor: Any) -> None:
    """Create the singleton lock row used to serialize audit appends."""
    del schema_editor
    apps.get_model('management', 'AuditLogChainLock').objects.get_or_create(pk=1)


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('management', '0015_audit_checkpoint_event'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLogChainLock',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            options={
                'verbose_name': 'Audit Log Chain Lock',
                'verbose_name_plural': 'Audit Log Chain Lock',
            },
        ),
        migrations.RunPython(create_chain_lock, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='auditlog',
            name='target_content_type',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='contenttypes.contenttype', verbose_name='Target Content Type'),
        ),
    ]
