# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0003_tp_v0_6_0'),
    ]

    operations = [
        migrations.AlterField(
            model_name='devicemodel',
            name='device_type',
            field=models.IntegerField(choices=[(0, 'Generic Device'), (2, 'OPC UA GDS Push'), (3, 'Agent (1-to-1)')], default=0, verbose_name='Device Type'),
        ),
    ]
