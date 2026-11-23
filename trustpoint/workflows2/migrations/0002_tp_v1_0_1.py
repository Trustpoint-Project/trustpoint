# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('workflows2', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='workflow2job',
            name='max_attempts',
            field=models.PositiveIntegerField(default=3),
        ),
    ]
