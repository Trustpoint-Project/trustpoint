# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0002_tp_v1_0_1'),
    ]

    operations = [
        migrations.AlterField(
            model_name='discoveryport',
            name='port_number',
            field=models.PositiveIntegerField(unique=True, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(65535)]),
        ),
    ]
