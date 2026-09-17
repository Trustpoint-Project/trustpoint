# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0004_tp_v1_0_dev0'),
    ]

    operations = [
        migrations.DeleteModel(
            name='InternationalizationConfig',
        ),
    ]
