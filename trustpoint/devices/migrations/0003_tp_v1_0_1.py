# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0002_tp_v1_0_1'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_regenerate_server_key',
            field=models.BooleanField(
                default=False,
                help_text=(
                    'Generate a new private key on the server for each certificate renewal. '
                    'Disabled by default so secure elements and non-exportable keys are reused.'
                ),
                verbose_name='Generate New Server Key on Renewal',
            ),
        ),
    ]
