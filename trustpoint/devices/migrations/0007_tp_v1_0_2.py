# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0006_tp_v1_0_2'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_renewal_threshold_days',
            field=models.PositiveIntegerField(
                default=30,
                help_text='Only replace the server certificate in the periodic task when it expires within this many days. The trust list is still refreshed each cycle.',
                verbose_name='Certificate Renewal Threshold (days)',
            ),
        ),
    ]
