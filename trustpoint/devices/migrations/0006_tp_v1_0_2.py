# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0005_tp_v1_0_2'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_server_url',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Optional full endpoint URL (opc.tcp://host:port/path). Overrides the IP address and port.',
                max_length=255,
                verbose_name='OPC Server URL',
            ),
        ),
    ]
