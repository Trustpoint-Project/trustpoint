# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('devices', '0003_tp_v1_0_2'),
    ]

    operations = [
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_max_trustlist_element_size',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Maximum size of one DER-encoded certificate or CRL in a pushed trust list. 0 means no limit.',
                verbose_name='Maximum Trust-List Element Size (bytes)',
            ),
        ),
        migrations.AddField(
            model_name='opcuagdspushconfig',
            name='opc_gds_push_max_trustlist_entries',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Maximum number of unique certificates and CRLs in a pushed trust list. 0 means no limit. Set this for devices with fixed trust-list capacity.',
                verbose_name='Maximum Trust-List Entries',
            ),
        ),
    ]
