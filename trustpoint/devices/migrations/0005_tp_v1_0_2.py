# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0004_tp_v1_0_2'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_require_crls',
            field=models.BooleanField(
                default=True,
                help_text='Reject a trust-list update when a CA in the chain has no CRL.',
                verbose_name='Require CRLs in Pushed Trust Lists',
            ),
        ),
    ]
