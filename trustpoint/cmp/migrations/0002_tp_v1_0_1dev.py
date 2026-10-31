# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cmp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='confirmation_deadline',
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='cmptransactionmodel',
            name='confirmation_timeout_policy',
            field=models.CharField(choices=[('revoke', 'Revoke'), ('log', 'Log rejection')], default='revoke', max_length=16),
        ),
    ]
