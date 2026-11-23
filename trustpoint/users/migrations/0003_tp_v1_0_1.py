# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('users', '0002_tp_v1_0_1'),
    ]

    operations = [
        migrations.AddField(
            model_name='trustpointuser',
            name='failed_login_locked_until',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]
